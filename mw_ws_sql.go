package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	wsModeTerminal   = "terminal"
	wsModeSQLConsole = "sql_console"
	wsSQLQueryTool   = "ws_sql_query"
)

// MWSQLDefaults are connection fields shared by every datasource in a SQL 控制台
// middleware. Only spaceCode and dbType are middleware-level defaults; envId
// and envType live on each datasource row. A row may override spaceCode/dbType
// (advanced). Legacy env_id / env_type keys in old stored defaults are captured
// during decode so they can be copied onto rows, then dropped on save.
type MWSQLDefaults struct {
	SpaceCode string `json:"space_code,omitempty"`
	DBType    string `json:"db_type,omitempty"`

	legacyEnvID   any
	legacyEnvType string
}

// MWDatasource is one AI-visible database alias. The user fills in a name, the
// datasource id, envId, envType, and an optional description shown to the AI.
// (dsId, envId, envType) together uniquely identify a database. Identifiers
// themselves never appear in MCP schemas, approval previews, or audit text.
type MWDatasource struct {
	Alias       string         `json:"alias"`
	DSID        any            `json:"ds_id,omitempty"`
	Description string         `json:"description,omitempty"`
	Enabled     *bool          `json:"enabled,omitempty"`
	MaxRows     int            `json:"max_rows,omitempty"`
	SpaceCode   string         `json:"space_code,omitempty"` // advanced override
	EnvID       any            `json:"env_id,omitempty"`
	EnvType     string         `json:"env_type,omitempty"`
	DBType      string         `json:"db_type,omitempty"` // advanced override
	Fields      map[string]any `json:"fields,omitempty"`
}

func (d *MWSQLDefaults) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		*d = MWSQLDefaults{}
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var raw map[string]any
	if err := dec.Decode(&raw); err != nil {
		return err
	}
	out := MWSQLDefaults{}
	if v, ok := raw["space_code"]; ok && !isEmptyJSONValue(v) {
		out.SpaceCode = strings.TrimSpace(fmt.Sprint(v))
	}
	if v, ok := raw["db_type"]; ok && !isEmptyJSONValue(v) {
		out.DBType = strings.TrimSpace(fmt.Sprint(v))
	}
	if v, ok := raw["env_id"]; ok && !isEmptyJSONValue(v) {
		out.legacyEnvID = v
	}
	if v, ok := raw["env_type"]; ok && !isEmptyJSONValue(v) {
		out.legacyEnvType = strings.TrimSpace(fmt.Sprint(v))
	}
	*d = out
	return nil
}

func envTypeOrPROD(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "PROD"
	}
	return s
}

func jsonScalarKey(v any) string {
	if isEmptyJSONValue(v) {
		return ""
	}
	switch x := v.(type) {
	case json.Number:
		return strings.TrimSpace(x.String())
	case float64:
		if x == float64(int64(x)) && x >= -1e15 && x <= 1e15 {
			return strconv.FormatInt(int64(x), 10)
		}
		return strconv.FormatFloat(x, 'f', -1, 64)
	case float32:
		return jsonScalarKey(float64(x))
	case int:
		return strconv.Itoa(x)
	case int32:
		return strconv.FormatInt(int64(x), 10)
	case int64:
		return strconv.FormatInt(x, 10)
	case uint64:
		return strconv.FormatUint(x, 10)
	case string:
		return strings.TrimSpace(x)
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func datasourceTripleKey(d MWDatasource) string {
	return jsonScalarKey(d.DSID) + "\x00" + jsonScalarKey(d.EnvID) + "\x00" + strings.ToLower(envTypeOrPROD(d.EnvType))
}

// applySQLConsoleEnvPromotion copies env_id / env_type from leftover
// middleware-level defaults onto any row that is missing them, then drops the
// old default keys. Empty envType becomes PROD. Idempotent.
func applySQLConsoleEnvPromotion(c *MWConfig) {
	if c == nil {
		return
	}
	legacyID := c.SQLDefaults.legacyEnvID
	legacyType := strings.TrimSpace(c.SQLDefaults.legacyEnvType)
	for i := range c.Datasources {
		if isEmptyJSONValue(c.Datasources[i].EnvID) && !isEmptyJSONValue(legacyID) {
			c.Datasources[i].EnvID = legacyID
		}
		if strings.TrimSpace(c.Datasources[i].EnvType) == "" && legacyType != "" {
			c.Datasources[i].EnvType = legacyType
		}
		if strings.TrimSpace(c.Datasources[i].Alias) == "" && isEmptyJSONValue(c.Datasources[i].DSID) {
			continue
		}
		if strings.TrimSpace(c.Datasources[i].EnvType) == "" {
			c.Datasources[i].EnvType = "PROD"
		}
	}
	c.SQLDefaults.legacyEnvID = nil
	c.SQLDefaults.legacyEnvType = ""
}

func sqlConsoleEnvNeedsPromote(c MWConfig) bool {
	if !c.isSQLConsole() {
		return false
	}
	if !isEmptyJSONValue(c.SQLDefaults.legacyEnvID) || strings.TrimSpace(c.SQLDefaults.legacyEnvType) != "" {
		return true
	}
	for _, d := range c.Datasources {
		if strings.TrimSpace(d.Alias) == "" && isEmptyJSONValue(d.DSID) {
			continue
		}
		if isEmptyJSONValue(d.EnvID) || strings.TrimSpace(d.EnvType) == "" {
			return true
		}
	}
	return false
}

func (c *MWConfig) wsMode() string {
	switch strings.TrimSpace(c.WSMode) {
	case "", wsModeTerminal:
		return wsModeTerminal
	default:
		return strings.TrimSpace(c.WSMode)
	}
}

func (c *MWConfig) isSQLConsole() bool { return c.wsMode() == wsModeSQLConsole }

func (c *MWConfig) sqlPath() string {
	if p := strings.TrimSpace(c.SQLPath); p != "" {
		return p
	}
	return "data.sql"
}

func defaultDSFieldPaths() map[string]string {
	return map[string]string{
		"space_code": "data.spaceCode",
		"ds_id":      "data.dsId",
		"env_id":     "data.envId",
		"env_type":   "data.envType",
		"db_type":    "data.dbType",
	}
}

func (c *MWConfig) dsFieldPaths() map[string]string {
	out := defaultDSFieldPaths()
	for k, v := range c.DSFieldPaths {
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k != "" && v != "" {
			out[k] = v
		}
	}
	return out
}

func (d MWDatasource) enabled() bool { return d.Enabled == nil || *d.Enabled }

func (d MWDatasource) maxRows(c *MWConfig) int {
	n := sqlGuardMaxRowsDefault
	if c != nil && c.MaxRows > 0 {
		n = c.MaxRows
	}
	if d.MaxRows > 0 {
		n = d.MaxRows
	}
	if n > sqlGuardMaxRowsCap {
		n = sqlGuardMaxRowsCap
	}
	if n < 1 {
		n = 1
	}
	return n
}

func (d MWDatasource) fieldValues(c *MWConfig) map[string]any {
	out := map[string]any{}
	put := func(k string, v any) {
		if !isEmptyJSONValue(v) {
			out[k] = v
		}
	}
	if c != nil {
		put("space_code", c.SQLDefaults.SpaceCode)
		put("db_type", c.SQLDefaults.DBType)
	}
	put("space_code", d.SpaceCode)
	put("db_type", d.DBType)
	put("ds_id", d.DSID)
	put("env_id", d.EnvID)
	put("env_type", envTypeOrPROD(d.EnvType))
	for k, v := range d.Fields {
		k = strings.TrimSpace(k)
		if k == "" || isEmptyJSONValue(v) {
			continue
		}
		out[k] = v
	}
	return out
}

func isEmptyJSONValue(v any) bool {
	if v == nil {
		return true
	}
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x) == ""
	case json.Number:
		return strings.TrimSpace(x.String()) == ""
	case []byte:
		return len(x) == 0
	}
	return false
}

// configHideValues lists datasource identifiers that must stay out of MCP
// schemas, approval previews, audit text and error messages, but must not be
// substring-scrubbed out of successful result rows. They are configuration,
// not credentials.
func (d MWDatasource) configHideValues(c *MWConfig) []string {
	var out []string
	seen := map[string]bool{}
	add := func(v any) {
		if isEmptyJSONValue(v) {
			return
		}
		s := strings.TrimSpace(fmt.Sprint(v))
		if s == "" || s == "<nil>" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, v := range d.fieldValues(c) {
		add(v)
	}
	return out
}

func (d MWDatasource) labelForAI() string {
	desc := strings.TrimSpace(d.Description)
	if desc == "" {
		return d.Alias
	}
	return d.Alias + "：" + desc
}

func (m *Middleware) datasourceListForAI() string {
	parts := []string{}
	for _, d := range m.enabledDatasources() {
		parts = append(parts, d.labelForAI())
	}
	return strings.Join(parts, "、")
}

func (m *Middleware) enabledDatasources() []MWDatasource {
	out := []MWDatasource{}
	for _, d := range m.Config.Datasources {
		if strings.TrimSpace(d.Alias) == "" || !d.enabled() {
			continue
		}
		out = append(out, d)
	}
	return out
}

func (m *Middleware) datasourceAliases() []string {
	out := []string{}
	for _, d := range m.enabledDatasources() {
		out = append(out, d.Alias)
	}
	return out
}

func (m *Middleware) lookupDatasource(alias string) (MWDatasource, error) {
	alias = strings.TrimSpace(alias)
	allowed := m.datasourceAliases()
	if alias == "" {
		if len(allowed) == 1 {
			return m.enabledDatasources()[0], nil
		}
		return MWDatasource{}, fmt.Errorf("请提供 database（数据源别名）。可用：%s", strings.Join(allowed, "、"))
	}
	var insensitive []MWDatasource
	for _, d := range m.enabledDatasources() {
		if d.Alias == alias {
			return d, nil
		}
		if strings.EqualFold(d.Alias, alias) {
			insensitive = append(insensitive, d)
		}
	}
	if len(insensitive) == 1 {
		return insensitive[0], nil
	}
	if len(allowed) == 0 {
		return MWDatasource{}, errors.New("这个中间件还没有启用的数据源")
	}
	return MWDatasource{}, fmt.Errorf("数据源「%s」不存在。可用：%s", alias, strings.Join(allowed, "、"))
}

func decodeMWConfig(raw string) (MWConfig, error) {
	var c MWConfig
	if strings.TrimSpace(raw) == "" {
		return c, nil
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil {
		return MWConfig{}, err
	}
	return c, nil
}

// normalizeCookieHeaderBinding canonicalizes a Cookie header so
// {{header.cookie}} (any case) and leftover literals become a jar binding.
// Other valid bindings ({{cookie.NAME}}, {{secret.*}}, {{cfg.*}}) are kept.
func normalizeCookieHeaderBinding(headers map[string]string) {
	if headers == nil {
		return
	}
	var keys []string
	var first string
	seen := false
	for k, v := range headers {
		if !strings.EqualFold(k, "Cookie") {
			continue
		}
		keys = append(keys, k)
		if !seen {
			first = v
			seen = true
		}
	}
	if !seen {
		return
	}
	for _, k := range keys {
		delete(headers, k)
	}
	headers["Cookie"] = canonicalCookieBinding(first)
}

func canonicalCookieBinding(v string) string {
	s := strings.TrimSpace(v)
	if bindingPlaceholder(s) {
		ref := strings.TrimSpace(s[2 : len(s)-2])
		if isCookieJarRef(ref) {
			return "{{header.cookie}}"
		}
		return s
	}
	return "{{header.cookie}}"
}

func normalizeSQLConsole(m *Middleware) error {
	c := &m.Config
	c.WSMode = wsModeSQLConsole
	c.URL = strings.TrimSpace(c.URL)
	if c.WSHeaders == nil {
		c.WSHeaders = map[string]string{}
	}
	normalizeCookieHeaderBinding(c.WSHeaders)
	if c.URL == "" {
		return errors.New("请填写 WebSocket 地址")
	}
	if !strings.HasPrefix(c.URL, "ws://") && !strings.HasPrefix(c.URL, "wss://") {
		return errors.New("WebSocket 地址必须以 ws:// 或 wss:// 开头")
	}
	applySQLConsoleEnvPromotion(c)
	c.SQLPath = c.sqlPath()
	c.WSMessages = cleanLines(c.WSMessages)
	if len(c.WSMessages) == 0 {
		c.WSMessages = []string{`execute {"data":{"sql":"{{sql}}"}}`}
	}
	if !strings.Contains(strings.Join(c.WSMessages, "\n"), "{{sql}}") {
		return errors.New("发送的文本帧里要有 {{sql}}，调用时会替换成要执行的 SQL")
	}
	if err := validateToolConfig("WS", ToolConfig{Messages: c.WSMessages, SQLGuard: &SQLGuardConfig{Enabled: true, Path: c.sqlPath(), MaxRows: c.MaxRows}, Collect: c.WSCollect, Auth: c.WSAuth}, true); err != nil {
		return err
	}
	if err := validateWSCredentialBindings(&Tool{Method: "WS", URL: c.URL, Headers: c.WSHeaders, Config: ToolConfig{Messages: c.WSMessages}}); err != nil {
		return err
	}
	if c.MaxRows <= 0 {
		c.MaxRows = sqlGuardMaxRowsDefault
	}
	if c.MaxRows > sqlGuardMaxRowsCap {
		c.MaxRows = sqlGuardMaxRowsCap
	}
	if c.TimeoutSec <= 0 {
		c.TimeoutSec = 30
	}
	seen := map[string]bool{}
	clean := []MWDatasource{}
	for _, d := range c.Datasources {
		d.Alias = strings.TrimSpace(d.Alias)
		if d.Alias == "" {
			continue
		}
		if !mwNameRe.MatchString(d.Alias) {
			return fmt.Errorf("数据源别名「%s」只能包含中文、字母、数字、下划线、短横线和点（最长 40 个字）", d.Alias)
		}
		key := strings.ToLower(d.Alias)
		if seen[key] {
			return fmt.Errorf("数据源别名「%s」重复", d.Alias)
		}
		seen[key] = true
		if isEmptyJSONValue(d.DSID) {
			return fmt.Errorf("数据源「%s」请填写数据源 ID", d.Alias)
		}
		if isEmptyJSONValue(d.EnvID) {
			return fmt.Errorf("数据源「%s」请填写 envId", d.Alias)
		}
		d.EnvType = envTypeOrPROD(d.EnvType)
		d.Description = strings.TrimSpace(d.Description)
		if d.MaxRows < 0 || d.MaxRows > sqlGuardMaxRowsCap {
			return fmt.Errorf("数据源「%s」的最多行数必须在 1–%d 之间", d.Alias, sqlGuardMaxRowsCap)
		}
		clean = append(clean, d)
	}
	triples := map[string]string{}
	for _, d := range clean {
		key := datasourceTripleKey(d)
		if prev, ok := triples[key]; ok {
			return fmt.Errorf("数据源「%s」与「%s」的数据源 ID、envId、envType 完全相同；这三个值必须一起唯一确定一个库", d.Alias, prev)
		}
		triples[key] = d.Alias
	}
	if len(clean) == 0 {
		return errors.New("请至少添加一个数据源：填写名称、数据源 ID、envId，以及给 AI 看的说明")
	}
	c.Datasources = clean
	return nil
}

func applyDatasourceToMessages(messages []string, ds MWDatasource, c *MWConfig) ([]string, error) {
	vals := ds.fieldValues(c)
	paths := map[string]string{}
	if c != nil {
		paths = c.dsFieldPaths()
	} else {
		paths = defaultDSFieldPaths()
	}
	out := make([]string, 0, len(messages))
	for _, tmpl := range messages {
		msg, err := injectDatasourceFields(tmpl, vals, paths)
		if err != nil {
			return nil, err
		}
		out = append(out, msg)
	}
	return out, nil
}

func injectDatasourceFields(tmpl string, vals map[string]any, paths map[string]string) (string, error) {
	prefix, tail, ok := splitCommandJSON(tmpl)
	if !ok {
		return replaceDSPlaceholders(tmpl, vals), nil
	}
	dec := json.NewDecoder(strings.NewReader(tail))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", fmt.Errorf("消息不是合法 JSON：%w", err)
	}
	for name, val := range vals {
		path := paths[name]
		if path == "" {
			if strings.Contains(name, ".") {
				path = name
			} else {
				path = "data." + name
			}
		}
		if !setJSONPathCreate(&v, path, val) {
			return "", fmt.Errorf("无法写入数据源字段 %s", path)
		}
	}
	return strings.TrimRight(prefix, " ") + " " + string(compactJSON(v)), nil
}

func replaceDSPlaceholders(s string, vals map[string]any) string {
	return placeholderRe.ReplaceAllStringFunc(s, func(m string) string {
		name := placeholderRe.FindStringSubmatch(m)[1]
		if !strings.HasPrefix(name, "ds.") {
			return m
		}
		key := strings.TrimPrefix(name, "ds.")
		if v, ok := vals[key]; ok && !isEmptyJSONValue(v) {
			return fmt.Sprint(v)
		}
		return m
	})
}

// setJSONPathCreate is setJSONPath but creates missing object keys.
func setJSONPathCreate(root *any, p string, val any) bool {
	if p == "" {
		return false
	}
	if *root == nil {
		*root = map[string]any{}
	}
	segs := strings.Split(p, ".")
	cur := root
	for i, s := range segs {
		last := i == len(segs)-1
		m, ok := (*cur).(map[string]any)
		if !ok {
			return false
		}
		if last {
			m[s] = val
			return true
		}
		next, ok := m[s]
		if !ok || next == nil {
			next = map[string]any{}
			m[s] = next
		}
		if _, ok := next.(map[string]any); !ok {
			return false
		}
		m[s] = next
		v := m[s]
		cur = &v
		defer func(m map[string]any, k string, p *any) { m[k] = *p }(m, s, cur)
	}
	return false
}

func (m *Middleware) sqlConsoleFingerprint() string {
	b, _ := json.Marshal(struct {
		URL, Mode, Path string
		Messages        []string
		Headers         map[string]string
		Datasources     []MWDatasource
		Paths           map[string]string
		MaxRows         int
		Timeout         int
		Collect         *WSCollectConfig
		Auth            *WSAuthConfig
		Updated         string
	}{m.Config.URL, m.Config.wsMode(), m.Config.sqlPath(), m.Config.WSMessages, m.Config.WSHeaders, m.Config.Datasources, m.Config.DSFieldPaths, m.Config.MaxRows, m.Config.TimeoutSec, m.Config.WSCollect, m.Config.WSAuth, m.UpdatedAt})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (m *Middleware) sqlConsoleCollect() *WSCollectConfig {
	c := &WSCollectConfig{}
	if m.Config.WSCollect != nil {
		*c = *m.Config.WSCollect
	}
	if c.TimeoutMS == 0 && m.Config.TimeoutSec > 0 {
		c.TimeoutMS = m.Config.TimeoutSec * 1000
		if c.TimeoutMS < wsTimeoutMinMS {
			c.TimeoutMS = wsTimeoutMinMS
		}
		if c.TimeoutMS > wsTimeoutMaxMS {
			c.TimeoutMS = wsTimeoutMaxMS
		}
	}
	if c.MaxBytes == 0 && m.Config.MaxResultKB > 0 {
		c.MaxBytes = m.Config.MaxResultKB * 1024
		if c.MaxBytes < wsMaxBytesMin {
			c.MaxBytes = wsMaxBytesMin
		}
		if c.MaxBytes > wsMaxBytesMax {
			c.MaxBytes = wsMaxBytesMax
		}
	}
	return c
}

func (m *Middleware) sqlConsoleAuth() *WSAuthConfig {
	if m.Config.WSAuth != nil {
		return m.Config.WSAuth
	}
	return &WSAuthConfig{RetryRelogin: true, FailMessageMatch: defaultAuthKeywords}
}

func (m *Middleware) sqlConsoleTool(ds MWDatasource) (*Tool, error) {
	msgs, err := applyDatasourceToMessages(m.Config.WSMessages, ds, &m.Config)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{}
	for k, v := range m.Config.WSHeaders {
		headers[k] = v
	}
	collect := m.sqlConsoleCollect()
	return &Tool{
		Name:        wsSQLQueryTool,
		Title:       fmt.Sprintf("WebSocket SQL 查询（%s / %s）", m.Name, ds.Alias),
		Description: "在 WebSocket SQL 控制台执行一条只读查询。必须是单条 SELECT，必须写 LIMIT，必须走索引。",
		Method:      "WS",
		URL:         m.Config.URL,
		Headers:     headers,
		Approval:    "always",
		Rev:         1,
		Params: []Param{
			{Name: "database", Type: "string", Required: true, Description: "数据源别名"},
			{Name: "sql", Type: "string", Required: true, Description: "一条只读 SELECT，必须带 LIMIT，且不超过允许的行数"},
		},
		Config: ToolConfig{
			Messages: msgs,
			SQLGuard: &SQLGuardConfig{Enabled: true, Param: "sql", Path: m.Config.sqlPath(), MaxRows: ds.maxRows(&m.Config)},
			Collect:  collect,
			Auth:     m.sqlConsoleAuth(),
		},
		mwID:          m.ID,
		mwFingerprint: m.sqlConsoleFingerprint(),
		mwName:        m.Name,
		mwAlias:       ds.Alias,
	}, nil
}

func redactSQLConsolePreview(p *PreparedCall, m *Middleware, alias string, configValues []string) {
	if p == nil {
		return
	}
	p.configValues = append(p.configValues, configValues...)
	p.Preview.URL = fmt.Sprintf("WebSocket SQL 控制台「%s」 / %s", m.Name, alias)
	p.Preview.Method = "WS"
	if p.wsSQL != "" {
		p.Preview.Body = p.wsSQL
	}
	for k, v := range p.Preview.Headers {
		if strings.Contains(v, "{{") {
			continue
		}
		p.Preview.Headers[k] = secretMask
	}
	p.Preview = scrubPreviewSecrets(p.Preview, p.secretValues)
	p.Preview = scrubPreviewConfigTokens(p.Preview, p.configValues)
}

func scrubPreviewSecrets(prev RequestPreview, secrets []string) RequestPreview {
	return mapPreviewText(prev, func(s string) string { return scrubSecretText(s, nil, secrets) })
}

func scrubPreviewConfigTokens(prev RequestPreview, values []string) RequestPreview {
	return mapPreviewText(prev, func(s string) string { return scrubConfigTokens(s, values) })
}

func mapPreviewText(prev RequestPreview, mask func(string) string) RequestPreview {
	h := map[string]string{}
	for k, v := range prev.Headers {
		h[k] = mask(v)
	}
	return RequestPreview{Method: prev.Method, URL: mask(prev.URL), Headers: h, Body: mask(prev.Body)}
}

func (a *App) scrubSQLConsoleText(text string, secrets, config []string, isErr bool) string {
	text = a.scrubApprovalText(text, secrets)
	if isErr {
		text = scrubConfigTokens(text, config)
	}
	return text
}

func (m *Middleware) allConfigHideValues() []string {
	if m == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, d := range m.Config.Datasources {
		for _, v := range d.configHideValues(&m.Config) {
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func (a *App) refreshSQLConsoleTool(t *Tool, args map[string]any) (*Tool, *Middleware, MWDatasource, error) {
	if t == nil || t.mwID == 0 {
		return t, nil, MWDatasource{}, nil
	}
	m, err := a.store.GetMiddleware(t.mwID)
	if err != nil {
		return nil, nil, MWDatasource{}, errors.New("中间件不存在或已删除")
	}
	if !m.Config.isSQLConsole() {
		return nil, nil, MWDatasource{}, errors.New("该中间件不是 SQL 控制台")
	}
	alias := strings.TrimSpace(argStr(args, "database"))
	if alias == "" {
		alias = t.mwAlias
	}
	ds, err := m.lookupDatasource(alias)
	if err != nil {
		return nil, m, MWDatasource{}, err
	}
	tool, err := m.sqlConsoleTool(ds)
	if err != nil {
		return nil, m, ds, err
	}
	return tool, m, ds, nil
}

func (a *App) callWSSQL(ctx context.Context, c *mwCall, args map[string]any) (string, bool) {
	if !c.m.Config.isSQLConsole() {
		return c.blocked("该中间件不是 SQL 控制台，不能用 ws_sql_query 调用"), true
	}
	if msg, ok := c.need("select"); !ok {
		return msg, true
	}
	sqlText := strings.TrimSpace(argStr(args, "sql"))
	alias := strings.TrimSpace(argStr(args, "database"))
	c.action = alias + ": " + sqlText
	if sqlText == "" {
		return c.blocked("请提供 sql"), true
	}
	cfgAll := c.m.allConfigHideValues()
	ds, err := c.m.lookupDatasource(alias)
	if err != nil {
		return c.blocked(a.scrubSQLConsoleText(err.Error(), nil, cfgAll, true)), true
	}
	cfgVals := ds.configHideValues(&c.m.Config)
	if err := checkGuardedSQL(sqlText, ds.maxRows(&c.m.Config)); err != nil {
		return c.blocked(a.scrubSQLConsoleText(err.Error(), nil, cfgVals, true)), true
	}
	if err := a.ensureSQLConsoleCredentials(c.m, nil); err != nil {
		return c.blocked(a.scrubSQLConsoleText(err.Error(), nil, cfgVals, true)), true
	}
	tool, err := c.m.sqlConsoleTool(ds)
	if err != nil {
		return c.blocked(a.scrubSQLConsoleText(err.Error(), nil, cfgVals, true)), true
	}
	callArgs := map[string]any{"sql": sqlText, "database": ds.Alias}
	prepared, err := a.Prepare(tool, callArgs)
	if err != nil {
		return c.blocked(a.scrubSQLConsoleText(err.Error(), nil, cfgVals, true)), true
	}
	redactSQLConsolePreview(prepared, c.m, ds.Alias, cfgVals)
	pending, err := a.waitApproval(ctx, tool, callArgs, prepared, c.client)
	if err != nil {
		return c.blocked(a.scrubSQLConsoleText(err.Error(), prepared.secretValues, prepared.configValues, true)), true
	}
	if !a.approvalCommitValid(pending) {
		a.approvalResult(pending.record.ID, "未执行：中间件在审批期间被修改或已移出已开启的流程包")
		return c.blocked("中间件或请求内容在审批期间变化，未执行，请重新调用"), true
	}
	prepared = pending.prepared
	prefix := a.approvalEditPrefix(pending)
	res, err := a.Send(prepared)
	text, isErr := formatWSSQLResult(res, err)
	text = prefix + text
	text = a.scrubSQLConsoleText(text, prepared.secretValues, prepared.configValues, isErr)
	if pending != nil {
		a.approvalResult(pending.record.ID, text)
	}
	out, failed := c.done(text, nil)
	if isErr {
		return out, true
	}
	return out, failed
}

func formatWSSQLResult(res *CallResult, err error) (string, bool) {
	if err != nil {
		return "执行失败：" + err.Error(), true
	}
	if res == nil {
		return "执行失败：没有返回结果", true
	}
	if res.Outcome != "" && res.Outcome != outcomeSuccess {
		return firstNonEmpty(res.Error, res.Body, res.Outcome), true
	}
	if res.Error != "" && res.Outcome != outcomeSuccess {
		return "执行失败：" + res.Error, true
	}
	text := res.Body
	if res.Relogged {
		text = "（登录已过期，已自动重新登录并重试）\n" + text
	}
	return text, false
}

func (a *App) testWSSQLConsole(ctx context.Context, m *Middleware) (string, error) {
	if err := normalizeSQLConsole(m); err != nil {
		return "", err
	}
	var secrets []string
	if err := a.ensureSQLConsoleCredentials(m, &secrets); err != nil {
		return "", err
	}
	if strings.Contains(m.Config.URL, "{{") && hasUserURLPlaceholders(m.Config.URL) {
		return "地址格式正确。调用时再填入数据源并执行 SQL；测试连接未发起真实会话", nil
	}
	headers := http.Header{}
	for k, v := range m.Config.WSHeaders {
		if bindingPlaceholder(v) {
			ref := strings.TrimSpace(v[2 : len(v)-2])
			val, err := a.resolveWSRef(ref, m.Config.URL, &secrets)
			if err != nil {
				return "", err
			}
			headers.Set(k, val)
		} else if v != "" {
			headers.Set(k, v)
		}
	}
	cookies, _ := a.CookiesFor(m.Config.URL)
	if ch, matched := CookieHeader(cookies, m.Config.URL); ch != "" {
		headers.Set("Cookie", ch)
		rememberSecret(&secrets, ch)
		for _, c := range matched {
			rememberCookieValue(&secrets, c.Value)
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	conn, resp, err := a.dialWS(cctx, m.Config.URL, headers)
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return "", fmt.Errorf("未登录，请先在「登录中心」登录这个网站（HTTP %d）", resp.StatusCode)
		}
		return "", err
	}
	conn.Close()
	return "连接成功，已完成握手（未执行 SQL）", nil
}

func walkSQLConsolePlaceholders(m *Middleware, fn func(ref string)) {
	if m == nil {
		return
	}
	add := func(s string) {
		for _, g := range placeholderRe.FindAllStringSubmatch(s, -1) {
			fn(g[1])
		}
	}
	add(m.Config.URL)
	for _, v := range m.Config.WSHeaders {
		add(v)
	}
	for _, msg := range m.Config.WSMessages {
		add(msg)
	}
}

// collectHeaderRefs lists harvested custom request-header names referenced by
// the middleware. header.cookie is excluded: it comes from the login-center
// cookie jar, not site_headers.
func collectHeaderRefs(m *Middleware) []string {
	seen := map[string]bool{}
	var out []string
	walkSQLConsolePlaceholders(m, func(ref string) {
		if isCookieJarRef(ref) {
			return
		}
		name, ok := headerBindingName(ref)
		if !ok {
			return
		}
		key := headerNameKey(name)
		if key == "" || key == "cookie" {
			return
		}
		if !seen[key] {
			seen[key] = true
			out = append(out, key)
		}
	})
	return out
}

func sqlConsoleNeedsCookieJar(m *Middleware) bool {
	need := false
	walkSQLConsolePlaceholders(m, func(ref string) {
		if isCookieJarRef(ref) {
			need = true
		}
	})
	return need
}

func (a *App) ensureSQLConsoleCredentials(m *Middleware, secrets *[]string) error {
	for _, name := range collectHeaderRefs(m) {
		if _, err := a.GetSiteHeader(m.Config.URL, name); err != nil {
			return err
		}
	}
	if sqlConsoleNeedsCookieJar(m) {
		if _, err := a.resolveCookieJar(m.Config.URL, secrets); err != nil {
			return err
		}
	}
	return nil
}

func hasUserURLPlaceholders(raw string) bool {
	for _, g := range placeholderRe.FindAllStringSubmatch(raw, -1) {
		n := g[1]
		if n == "sql" || n == "command" || strings.HasPrefix(n, "header.") || strings.HasPrefix(n, "cookie.") || strings.HasPrefix(n, "ds.") || strings.HasPrefix(n, "secret.") || strings.HasPrefix(n, "cfg.") {
			continue
		}
		return true
	}
	return false
}

func isWSInternalPlaceholder(name string) bool {
	switch name {
	case "command", "sql", "database", "middleware", "file", "lines", "timeout":
		return true
	}
	return strings.HasPrefix(name, "header.") || strings.HasPrefix(name, "cookie.") || strings.HasPrefix(name, "ds.") || strings.HasPrefix(name, "secret.") || strings.HasPrefix(name, "cfg.")
}

func sqlConsoleAliases(ms []*Middleware) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range ms {
		for _, a := range m.datasourceAliases() {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}
