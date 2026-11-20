package mwconfig

import (
	"action2mcp/internal/credential"
	"action2mcp/internal/domain"
	"action2mcp/internal/execution"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

func defaultWSMessages() []string {
	return []string{
		`{"type":"TERMINAL_COMMAND","text":"{{command}}"}`,
		`{"type":"TERMINAL_COMMAND","text":"\r"}`,
	}
}

const (
	WSModeTerminal   = "terminal"
	WSModeSQLConsole = "sql_console"
	WSSQLQueryTool   = "ws_sql_query"
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

func envTypeOrPROD(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "PROD"
	}
	return s
}

func jsonScalarKey(v any) string {
	if IsEmptyJSONValue(v) {
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
func ApplySQLConsoleEnvPromotion(c *MWConfig) {
	if c == nil {
		return
	}
	legacyID := c.SQLDefaults.legacyEnvID
	legacyType := strings.TrimSpace(c.SQLDefaults.legacyEnvType)
	for i := range c.Datasources {
		if IsEmptyJSONValue(c.Datasources[i].EnvID) && !IsEmptyJSONValue(legacyID) {
			c.Datasources[i].EnvID = legacyID
		}
		if strings.TrimSpace(c.Datasources[i].EnvType) == "" && legacyType != "" {
			c.Datasources[i].EnvType = legacyType
		}
		if strings.TrimSpace(c.Datasources[i].Alias) == "" && IsEmptyJSONValue(c.Datasources[i].DSID) {
			continue
		}
		if strings.TrimSpace(c.Datasources[i].EnvType) == "" {
			c.Datasources[i].EnvType = "PROD"
		}
	}
	c.SQLDefaults.legacyEnvID = nil
	c.SQLDefaults.legacyEnvType = ""
}

func SQLConsoleEnvNeedsPromote(c MWConfig) bool {
	if !c.IsSQLConsole() {
		return false
	}
	if !IsEmptyJSONValue(c.SQLDefaults.legacyEnvID) || strings.TrimSpace(c.SQLDefaults.legacyEnvType) != "" {
		return true
	}
	for _, d := range c.Datasources {
		if strings.TrimSpace(d.Alias) == "" && IsEmptyJSONValue(d.DSID) {
			continue
		}
		if IsEmptyJSONValue(d.EnvID) || strings.TrimSpace(d.EnvType) == "" {
			return true
		}
	}
	return false
}

func normalizeSQLConsoleApproval(c *MWConfig) {
	if c == nil {
		return
	}
	switch strings.ToLower(strings.TrimSpace(c.Approval)) {
	case "off":
		c.Approval = "off"
	default:
		c.Approval = "always"
	}
}

func DefaultDSFieldPaths() map[string]string {
	return map[string]string{
		"space_code": "data.spaceCode",
		"ds_id":      "data.dsId",
		"env_id":     "data.envId",
		"env_type":   "data.envType",
		"db_type":    "data.dbType",
	}
}

func IsEmptyJSONValue(v any) bool {
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

func DecodeMWConfig(raw string) (MWConfig, error) {
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
func NormalizeCookieHeaderBinding(headers map[string]string) {
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
	if execution.BindingPlaceholder(s) {
		ref := strings.TrimSpace(s[2 : len(s)-2])
		if credential.IsCookieJarRef(ref) {
			return "{{header.cookie}}"
		}
		return s
	}
	return "{{header.cookie}}"
}

func NormalizeSQLConsole(m *Middleware) error {
	c := &m.Config
	c.WSMode = WSModeSQLConsole
	normalizeSQLConsoleApproval(c)
	c.URL = strings.TrimSpace(c.URL)
	if c.WSHeaders == nil {
		c.WSHeaders = map[string]string{}
	}
	NormalizeCookieHeaderBinding(c.WSHeaders)
	if c.URL == "" {
		return errors.New("请填写 WebSocket 地址")
	}
	if !strings.HasPrefix(c.URL, "ws://") && !strings.HasPrefix(c.URL, "wss://") {
		return errors.New("WebSocket 地址必须以 ws:// 或 wss:// 开头")
	}
	ApplySQLConsoleEnvPromotion(c)
	c.SQLPath = c.sqlPath()
	c.WSMessages = cleanLines(c.WSMessages)
	if len(c.WSMessages) == 0 {
		c.WSMessages = []string{`execute {"data":{"sql":"{{sql}}"}}`}
	}
	if !strings.Contains(strings.Join(c.WSMessages, "\n"), "{{sql}}") {
		return errors.New("发送的文本帧里要有 {{sql}}，调用时会替换成要执行的 SQL")
	}
	if err := execution.ValidateToolConfig("WS", execution.ToolConfig{Messages: c.WSMessages, SQLGuard: &execution.SQLGuardConfig{Enabled: true, Path: c.sqlPath(), MaxRows: c.MaxRows}, Collect: c.WSCollect, Auth: c.WSAuth}, true); err != nil {
		return err
	}
	if err := execution.ValidateWSCredentialBindings(&execution.Tool{Method: "WS", URL: c.URL, Headers: c.WSHeaders, Config: execution.ToolConfig{Messages: c.WSMessages}}); err != nil {
		return err
	}
	if c.MaxRows <= 0 {
		c.MaxRows = execution.SQLGuardMaxRowsDefault
	}
	if c.MaxRows > execution.SQLGuardMaxRowsCap {
		c.MaxRows = execution.SQLGuardMaxRowsCap
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
		if IsEmptyJSONValue(d.DSID) {
			return fmt.Errorf("数据源「%s」请填写数据源 ID", d.Alias)
		}
		if IsEmptyJSONValue(d.EnvID) {
			return fmt.Errorf("数据源「%s」请填写 envId", d.Alias)
		}
		d.EnvType = envTypeOrPROD(d.EnvType)
		d.Description = strings.TrimSpace(d.Description)
		if d.MaxRows < 0 || d.MaxRows > execution.SQLGuardMaxRowsCap {
			return fmt.Errorf("数据源「%s」的最多行数必须在 1–%d 之间", d.Alias, execution.SQLGuardMaxRowsCap)
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
	vals := ds.FieldValues(c)
	paths := map[string]string{}
	if c != nil {
		paths = c.dsFieldPaths()
	} else {
		paths = DefaultDSFieldPaths()
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
	prefix, tail, ok := execution.SplitCommandJSON(tmpl)
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
		if !SetJSONPathCreate(&v, path, val) {
			return "", fmt.Errorf("无法写入数据源字段 %s", path)
		}
	}
	return strings.TrimRight(prefix, " ") + " " + string(execution.CompactJSON(v)), nil
}

func replaceDSPlaceholders(s string, vals map[string]any) string {
	return execution.PlaceholderPattern().ReplaceAllStringFunc(s, func(m string) string {
		name := execution.PlaceholderPattern().FindStringSubmatch(m)[1]
		if !strings.HasPrefix(name, "ds.") {
			return m
		}
		key := strings.TrimPrefix(name, "ds.")
		if v, ok := vals[key]; ok && !IsEmptyJSONValue(v) {
			return fmt.Sprint(v)
		}
		return m
	})
}

// setJSONPathCreate is setJSONPath but creates missing object keys.
func SetJSONPathCreate(root *any, p string, val any) bool {
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
	if v, ok := raw["space_code"]; ok && !IsEmptyJSONValue(v) {
		out.SpaceCode = strings.TrimSpace(fmt.Sprint(v))
	}
	if v, ok := raw["db_type"]; ok && !IsEmptyJSONValue(v) {
		out.DBType = strings.TrimSpace(fmt.Sprint(v))
	}
	if v, ok := raw["env_id"]; ok && !IsEmptyJSONValue(v) {
		out.legacyEnvID = v
	}
	if v, ok := raw["env_type"]; ok && !IsEmptyJSONValue(v) {
		out.legacyEnvType = strings.TrimSpace(fmt.Sprint(v))
	}
	*d = out
	return nil
}

func (c *MWConfig) EffectiveWSMode() string {
	switch strings.TrimSpace(c.WSMode) {
	case "", WSModeTerminal:
		return WSModeTerminal
	default:
		return strings.TrimSpace(c.WSMode)
	}
}

func (c *MWConfig) IsSQLConsole() bool { return c.EffectiveWSMode() == WSModeSQLConsole }

// sqlConsoleApproval returns the per-middleware approval mode. Unknown or
// empty values fail closed to "always". Only "off" skips the console card.
func (c *MWConfig) SQLConsoleApproval() string {
	if c != nil && strings.TrimSpace(c.Approval) == "off" {
		return "off"
	}
	return "always"
}

func (c *MWConfig) sqlPath() string {
	if p := strings.TrimSpace(c.SQLPath); p != "" {
		return p
	}
	return "data.sql"
}

func (c *MWConfig) dsFieldPaths() map[string]string {
	out := DefaultDSFieldPaths()
	for k, v := range c.DSFieldPaths {
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		if k != "" && v != "" {
			out[k] = v
		}
	}
	return out
}

func (d MWDatasource) enabled() bool { return d.Enabled == nil || *d.Enabled }

func (d MWDatasource) EffectiveMaxRows(c *MWConfig) int {
	n := execution.SQLGuardMaxRowsDefault
	if c != nil && c.MaxRows > 0 {
		n = c.MaxRows
	}
	if d.MaxRows > 0 {
		n = d.MaxRows
	}
	if n > execution.SQLGuardMaxRowsCap {
		n = execution.SQLGuardMaxRowsCap
	}
	if n < 1 {
		n = 1
	}
	return n
}

func (d MWDatasource) FieldValues(c *MWConfig) map[string]any {
	out := map[string]any{}
	put := func(k string, v any) {
		if !IsEmptyJSONValue(v) {
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
		if k == "" || IsEmptyJSONValue(v) {
			continue
		}
		out[k] = v
	}
	return out
}

// configHideValues lists datasource identifiers that must stay out of MCP
// schemas, approval previews, audit text and error messages, but must not be
// substring-scrubbed out of successful result rows. They are configuration,
// not credentials.
func (d MWDatasource) ConfigHideValues(c *MWConfig) []string {
	var out []string
	seen := map[string]bool{}
	add := func(v any) {
		if IsEmptyJSONValue(v) {
			return
		}
		s := strings.TrimSpace(fmt.Sprint(v))
		if s == "" || s == "<nil>" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, v := range d.FieldValues(c) {
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

func (m *Middleware) DatasourceListForAI() string {
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

func (m *Middleware) DatasourceAliases() []string {
	out := []string{}
	for _, d := range m.enabledDatasources() {
		out = append(out, d.Alias)
	}
	return out
}

func (m *Middleware) LookupDatasource(alias string) (MWDatasource, error) {
	alias = strings.TrimSpace(alias)
	allowed := m.DatasourceAliases()
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

func (m *Middleware) SQLConsoleFingerprint() string {
	b, _ := json.Marshal(struct {
		URL, Mode, Path string
		Messages        []string
		Headers         map[string]string
		Datasources     []MWDatasource
		Paths           map[string]string
		MaxRows         int
		Timeout         int
		Collect         *execution.WSCollectConfig
		Auth            *execution.WSAuthConfig
		Approval        string
		AllowDescribe   bool
		Updated         string
	}{m.Config.URL, m.Config.EffectiveWSMode(), m.Config.sqlPath(), m.Config.WSMessages, m.Config.WSHeaders, m.Config.Datasources, m.Config.DSFieldPaths, m.Config.MaxRows, m.Config.TimeoutSec, m.Config.WSCollect, m.Config.WSAuth, m.Config.SQLConsoleApproval(), m.Config.Perms["describe"], m.UpdatedAt})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (m *Middleware) sqlConsoleCollect() *execution.WSCollectConfig {
	c := &execution.WSCollectConfig{}
	if m.Config.WSCollect != nil {
		*c = *m.Config.WSCollect
	}
	if c.TimeoutMS == 0 && m.Config.TimeoutSec > 0 {
		c.TimeoutMS = m.Config.TimeoutSec * 1000
		if c.TimeoutMS < execution.WSTimeoutMinMS {
			c.TimeoutMS = execution.WSTimeoutMinMS
		}
		if c.TimeoutMS > execution.WSTimeoutMaxMS {
			c.TimeoutMS = execution.WSTimeoutMaxMS
		}
	}
	if c.MaxBytes == 0 && m.Config.MaxResultKB > 0 {
		c.MaxBytes = m.Config.MaxResultKB * 1024
		if c.MaxBytes < execution.WSMaxBytesMin {
			c.MaxBytes = execution.WSMaxBytesMin
		}
		if c.MaxBytes > execution.WSMaxBytesMax {
			c.MaxBytes = execution.WSMaxBytesMax
		}
	}
	return c
}

func (m *Middleware) sqlConsoleAuth() *execution.WSAuthConfig {
	if m.Config.WSAuth != nil {
		return m.Config.WSAuth
	}
	return &execution.WSAuthConfig{RetryRelogin: true, FailMessageMatch: execution.DefaultAuthKeywords()}
}

func (m *Middleware) SQLConsoleTool(ds MWDatasource) (*execution.Tool, error) {
	msgs, err := applyDatasourceToMessages(m.Config.WSMessages, ds, &m.Config)
	if err != nil {
		return nil, err
	}
	headers := map[string]string{}
	for k, v := range m.Config.WSHeaders {
		headers[k] = v
	}
	collect := m.sqlConsoleCollect()
	allowDescribe := m.Config.Perms["describe"]
	desc := "在 WebSocket SQL 控制台执行一条只读查询。必须是单条 SELECT，必须写 LIMIT，必须走索引。"
	sqlParamDesc := "一条只读 SELECT，必须带 LIMIT，且不超过允许的行数"
	if allowDescribe {
		desc = "在 WebSocket SQL 控制台执行一条只读查询（SELECT 必须带 LIMIT 且走索引）或表结构查看（DESCRIBE / SHOW COLUMNS / SHOW INDEX / SHOW CREATE TABLE）。"
		sqlParamDesc = "一条只读 SELECT（必须带 LIMIT）或表结构查看语句（DESCRIBE / SHOW COLUMNS / SHOW INDEX / SHOW CREATE TABLE）"
	}
	tool := &execution.Tool{
		Name:        WSSQLQueryTool,
		Title:       fmt.Sprintf("WebSocket SQL 查询（%s / %s）", m.Name, ds.Alias),
		Description: desc,
		Method:      "WS",
		URL:         m.Config.URL,
		Headers:     headers,
		Approval:    m.Config.SQLConsoleApproval(),
		Rev:         1,
		Params: []domain.Param{
			{Name: "database", Type: "string", Required: true, Description: "数据源别名"},
			{Name: "sql", Type: "string", Required: true, Description: sqlParamDesc},
		},
		Config: execution.ToolConfig{
			Messages: msgs,
			SQLGuard: &execution.SQLGuardConfig{Enabled: true, Param: "sql", Path: m.Config.sqlPath(), MaxRows: ds.EffectiveMaxRows(&m.Config), AllowDescribe: allowDescribe},
			Collect:  collect,
			Auth:     m.sqlConsoleAuth(),
		},
	}
	tool.BindConsole(execution.ConsoleBinding{ID: m.ID, Fingerprint: m.SQLConsoleFingerprint(), Name: m.Name, Alias: ds.Alias})
	return tool, nil
}

func (m *Middleware) AllConfigHideValues() []string {
	if m == nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, d := range m.Config.Datasources {
		for _, v := range d.ConfigHideValues(&m.Config) {
			if v == "" || seen[v] {
				continue
			}
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}
