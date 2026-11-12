package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ---------- model ----------

type MWConfig struct {
	Host          string            `json:"host"`
	Port          int               `json:"port"`
	User          string            `json:"user"`
	PasswordRef   string            `json:"password_ref"` // name of a secret in 配置管理 (never the value)
	Database      string            `json:"database"`     // MySQL default db / Redis db index / RabbitMQ vhost
	Addrs         string            `json:"addrs"`        // Kafka brokers / RocketMQ namesrv / Redis cluster nodes / sentinels (comma separated)
	MQKind        string            `json:"mq_kind"`      // rocketmq | kafka | rabbitmq
	RedisMode     string            `json:"redis_mode"`   // standalone | cluster | sentinel
	MasterName    string            `json:"master_name"`
	TLS           bool              `json:"tls"`
	TLSSkipVerify bool              `json:"tls_skip_verify"`
	SASL          string            `json:"sasl"`        // Kafka: PLAIN | SCRAM-SHA-256 | SCRAM-SHA-512
	BrokerAddr    string            `json:"broker_addr"` // RocketMQ broker used for creating topics
	Perms         map[string]bool   `json:"perms"`
	AllowedDBs    []string          `json:"allowed_dbs"`
	AllowedTables []string          `json:"allowed_tables"`
	KeyPrefixes   []string          `json:"key_prefixes"`
	Topics        []string          `json:"topics"`
	URL           string            `json:"url,omitempty"`         // WebSocket address template, wss://…
	WSMessages    []string          `json:"ws_messages,omitempty"` // text frames; {{command}} or {{sql}}
	CommandAllow  []string          `json:"command_allow"`         // pod_exec allowlist, applied to each pipeline stage; empty = unrestricted. No omitempty: [] must survive a save.
	MaxRows       int               `json:"max_rows"`
	MaxResultKB   int               `json:"max_result_kb"`
	TimeoutSec    int               `json:"timeout_sec"`
	RequireWhere  *bool             `json:"require_where,omitempty"`
	Description   string            `json:"description"`
	WSMode        string            `json:"ws_mode,omitempty"`  // terminal (default) | sql_console
	Approval      string            `json:"approval,omitempty"` // sql_console only: off | always (default always)
	SQLPath       string            `json:"sql_path,omitempty"`
	WSHeaders     map[string]string `json:"ws_headers,omitempty"`
	Datasources   []MWDatasource    `json:"datasources,omitempty"`
	DSFieldPaths  map[string]string `json:"ds_field_paths,omitempty"`
	SQLDefaults   MWSQLDefaults     `json:"sql_defaults"`
	WSCollect     *WSCollectConfig  `json:"ws_collect,omitempty"`
	WSAuth        *WSAuthConfig     `json:"ws_auth,omitempty"`
}

type Middleware struct {
	ID        int64    `json:"id"`
	Name      string   `json:"name"`
	Type      string   `json:"type"` // mysql | redis | mq
	Config    MWConfig `json:"config"`
	CreatedAt string   `json:"created_at,omitempty"`
	UpdatedAt string   `json:"updated_at,omitempty"`

	pwOverride *string // console "测试连接" with a typed, not yet saved password
}

type permDef struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Default bool   `json:"default"`
	Hint    string `json:"hint"`
}

var mwPermDefs = map[string][]permDef{
	"mysql": {
		{"select", "查", true, "SELECT / SHOW / DESCRIBE / EXPLAIN"},
		{"insert", "增", false, "INSERT / REPLACE"},
		{"update", "改", false, "UPDATE、SELECT … FOR UPDATE、REPLACE 和 ON DUPLICATE KEY UPDATE"},
		{"delete", "删", false, "DELETE / TRUNCATE"},
		{"ddl", "DDL", false, "CREATE / ALTER / DROP 表、索引、视图、库"},
	},
	"redis": {
		{"read", "读", true, "GET / HGETALL / LRANGE / SCAN 等"},
		{"write", "写", false, "SET / HSET / LPUSH / EXPIRE 等"},
		{"delete", "删", false, "DEL / HDEL / LPOP / SREM 等"},
		{"script", "脚本", false, "EVAL / EVALSHA（脚本可以访问任意 key，谨慎开启）"},
	},
	"mq": {
		{"consume", "查看消息", true, "列出 Topic、查看最近的消息（不提交消费位点）"},
		{"send", "发送", false, "向 Topic / 队列发送消息"},
		{"admin", "管理", false, "创建 Topic / 队列"},
	},
	"websocket": {
		{"log", "查日志", true, "pod_read_log：只执行 tail 查看文件末尾"},
		{"exec", "执行命令", false, "pod_exec：在远端 shell 执行命令。开启后还受「允许的命令」约束，管道的每一段也要在列表里；留空则不限制"},
	},
}

var mwSQLConsolePerms = []permDef{
	{"select", "查", true, "只读 SELECT：必须带 LIMIT、必须走索引、最多 200 行"},
}

func mwPermsOf(m *Middleware) []permDef {
	if m != nil && m.Type == "websocket" && m.Config.isSQLConsole() {
		return mwSQLConsolePerms
	}
	if m != nil {
		return mwPermDefs[m.Type]
	}
	return nil
}

var mwTypeLabel = map[string]string{"mysql": "MySQL / OceanBase", "redis": "Redis", "mq": "消息队列", "websocket": "WebSocket"}
var mqKindLabel = map[string]string{"rocketmq": "RocketMQ", "kafka": "Kafka", "rabbitmq": "RabbitMQ"}

func permLabel(typ, key string) string {
	for _, d := range mwPermDefs[typ] {
		if d.Key == key {
			return d.Label
		}
	}
	for _, d := range mwSQLConsolePerms {
		if d.Key == key {
			return d.Label
		}
	}
	return key
}

func (c *MWConfig) maxRows() int {
	if c.MaxRows <= 0 {
		return 200
	}
	if c.MaxRows > 10000 {
		return 10000
	}
	return c.MaxRows
}
func (c *MWConfig) maxResultBytes() int {
	if c.MaxResultKB <= 0 {
		return 256 * 1024
	}
	if c.MaxResultKB > 8192 {
		return 8192 * 1024
	}
	return c.MaxResultKB * 1024
}
func (c *MWConfig) timeoutSec() int {
	if c.TimeoutSec <= 0 {
		return 15
	}
	if c.TimeoutSec > 300 {
		return 300
	}
	return c.TimeoutSec
}
func (c *MWConfig) requireWhere() bool { return c.RequireWhere == nil || *c.RequireWhere }

func (m *Middleware) kindLabel() string {
	if m.Type == "websocket" && m.Config.isSQLConsole() {
		return "WebSocket · SQL 控制台"
	}
	if m.Type == "mq" {
		return mqKindLabel[m.Config.MQKind]
	}
	return mwTypeLabel[m.Type]
}

func (m *Middleware) cacheKey(pw string) string {
	b, _ := json.Marshal(m.Config)
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s|%s", m.ID, m.Type, b, pw)))
	return hex.EncodeToString(h[:])
}

var mwNameRe = regexp.MustCompile(`^[\p{L}\p{N}_\-\.]{1,40}$`)

func cleanList(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '，' || r == ' ' }) {
			p = strings.TrimSpace(p)
			if p != "" && !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// normalize validates and fills defaults.
func (m *Middleware) normalize() error {
	m.Name = strings.TrimSpace(m.Name)
	if !mwNameRe.MatchString(m.Name) {
		return errors.New("中间件名称只能包含中文、字母、数字、下划线、短横线和点（最长 40 个字），例如「订单库」")
	}
	if _, ok := mwPermDefs[m.Type]; !ok {
		return errors.New("中间件类型必须是 mysql、redis、mq 或 websocket")
	}
	if m.Type == "websocket" {
		mode := strings.TrimSpace(m.Config.WSMode)
		if mode != "" && mode != wsModeTerminal && mode != wsModeSQLConsole {
			return errors.New("WebSocket 模式只能是 terminal（终端）或 sql_console（SQL 控制台）")
		}
	}
	if m.Type != "websocket" || !m.Config.isSQLConsole() {
		m.Config.Approval = ""
	}
	c := &m.Config
	c.Host = strings.TrimSpace(c.Host)
	c.User = strings.TrimSpace(c.User)
	c.Database = strings.TrimSpace(c.Database)
	c.Addrs = strings.Join(cleanList([]string{c.Addrs}), ",")
	c.AllowedDBs = cleanList(c.AllowedDBs)
	c.AllowedTables = cleanList(c.AllowedTables)
	c.KeyPrefixes = cleanList(c.KeyPrefixes)
	c.Topics = cleanList(c.Topics)
	if c.PasswordRef != "" && !vaultNameRe.MatchString(c.PasswordRef) {
		return errors.New("密码引用的配置名无效")
	}
	if c.Perms == nil {
		c.Perms = map[string]bool{}
	}
	clean := map[string]bool{}
	for _, d := range mwPermsOf(m) {
		v, ok := c.Perms[d.Key]
		if !ok {
			v = d.Default
		}
		clean[d.Key] = v
	}
	c.Perms = clean
	switch m.Type {
	case "mysql":
		if c.Host == "" {
			return errors.New("请填写数据库地址")
		}
		if c.Port == 0 {
			c.Port = 3306
		}
	case "redis":
		if c.RedisMode == "" {
			c.RedisMode = "standalone"
		}
		if c.RedisMode != "standalone" && c.RedisMode != "cluster" && c.RedisMode != "sentinel" {
			return errors.New("Redis 模式只能是 standalone / cluster / sentinel")
		}
		if c.RedisMode == "standalone" && c.Host == "" {
			return errors.New("请填写 Redis 地址")
		}
		if c.RedisMode != "standalone" && c.Addrs == "" {
			return errors.New("集群 / 哨兵模式请填写节点地址列表")
		}
		if c.RedisMode == "sentinel" && c.MasterName == "" {
			return errors.New("哨兵模式请填写 master 名称")
		}
		if c.Port == 0 {
			c.Port = 6379
		}
		if c.Database != "" {
			var n int
			if _, err := fmt.Sscanf(c.Database, "%d", &n); err != nil || n < 0 || n > 255 {
				return errors.New("Redis 库编号必须是 0-255 的数字")
			}
		}
	case "mq":
		if _, ok := mqKindLabel[c.MQKind]; !ok {
			return errors.New("请选择消息队列类型：RocketMQ / Kafka / RabbitMQ")
		}
		switch c.MQKind {
		case "rabbitmq":
			if c.Host == "" {
				return errors.New("请填写 RabbitMQ 地址")
			}
			if c.Port == 0 {
				c.Port = 5672
				if c.TLS {
					c.Port = 5671
				}
			}
		default:
			if c.Addrs == "" && c.Host != "" {
				p := c.Port
				if p == 0 {
					p = map[string]int{"rocketmq": 9876, "kafka": 9092}[c.MQKind]
				}
				c.Addrs = joinHostPort(c.Host, p)
			}
			if c.Addrs == "" {
				return errors.New(map[string]string{"rocketmq": "请填写 NameServer 地址", "kafka": "请填写 Broker 地址"}[c.MQKind])
			}
		}
	case "websocket":
		if c.isSQLConsole() {
			return normalizeSQLConsole(m)
		}
		c.URL = strings.TrimSpace(c.URL)
		if c.URL == "" {
			return errors.New("请填写 WebSocket 地址")
		}
		if !strings.HasPrefix(c.URL, "ws://") && !strings.HasPrefix(c.URL, "wss://") {
			return errors.New("WebSocket 地址必须以 ws:// 或 wss:// 开头")
		}
		c.WSMessages = cleanLines(c.WSMessages)
		if len(c.WSMessages) == 0 {
			c.WSMessages = defaultWSMessages()
		}
		if !strings.Contains(strings.Join(c.WSMessages, "\n"), "{{command}}") {
			return errors.New("发送的文本帧里要有 {{command}}，调用时会替换成要执行的命令")
		}
		if c.CommandAllow == nil {
			c.CommandAllow = []string{"tail", "head", "ls", "cat", "grep", "pwd"}
		} else {
			c.CommandAllow = cleanList(c.CommandAllow)
		}
		if c.TimeoutSec <= 0 {
			c.TimeoutSec = 30
		}
	}
	return nil
}

// cleanLines keeps non-empty lines. Unlike cleanList it does not split on commas or spaces,
// so a JSON frame stays intact.
func cleanLines(in []string) []string {
	out := []string{}
	for _, s := range in {
		for _, line := range strings.Split(s, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				out = append(out, line)
			}
		}
	}
	return out
}

// ---------- store ----------

func (s *Store) ListMiddleware() ([]*Middleware, error) {
	rows, err := s.db.Query(`SELECT id,name,type,config,created_at,updated_at FROM middleware ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Middleware{}
	for rows.Next() {
		var m Middleware
		var cfg string
		rows.Scan(&m.ID, &m.Name, &m.Type, &cfg, &m.CreatedAt, &m.UpdatedAt)
		if decoded, err := decodeMWConfig(cfg); err == nil {
			m.Config = decoded
		} else {
			json.Unmarshal([]byte(cfg), &m.Config)
		}
		m.normalize()
		out = append(out, &m)
	}
	return out, nil
}

func (s *Store) GetMiddleware(id int64) (*Middleware, error) {
	all, err := s.ListMiddleware()
	if err != nil {
		return nil, err
	}
	for _, m := range all {
		if m.ID == id {
			return m, nil
		}
	}
	return nil, errors.New("中间件不存在")
}

func (s *Store) GetMiddlewareByName(name string) (*Middleware, error) {
	all, _ := s.ListMiddleware()
	for _, m := range all {
		if m.Name == name {
			return m, nil
		}
	}
	return nil, errors.New("中间件不存在")
}

func (s *Store) SaveMiddleware(m *Middleware) error {
	if err := m.normalize(); err != nil {
		return err
	}
	b, _ := json.Marshal(m.Config)
	ts := now()
	if m.ID == 0 {
		r, err := s.db.Exec(`INSERT INTO middleware(name,type,config,created_at,updated_at) VALUES(?,?,?,?,?)`, m.Name, m.Type, string(b), ts, ts)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("已经有名为「%s」的中间件了", m.Name)
			}
			return err
		}
		m.ID, _ = r.LastInsertId()
		return nil
	}
	_, err := s.db.Exec(`UPDATE middleware SET name=?,type=?,config=?,updated_at=? WHERE id=?`, m.Name, m.Type, string(b), ts, m.ID)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return fmt.Errorf("已经有名为「%s」的中间件了", m.Name)
	}
	return err
}

func (s *Store) DeleteMiddleware(id int64) error {
	_, err := s.db.Exec(`DELETE FROM middleware WHERE id=?`, id)
	return err
}

// ExposedMiddleware returns middleware that belong to at least one enabled pack, with those pack names.
func (s *Store) ExposedMiddleware() ([]*Middleware, map[int64][]string) {
	all, _ := s.ListMiddleware()
	packs, _ := s.ListPacks()
	names := map[int64][]string{}
	for _, p := range packs {
		if !p.Enabled {
			continue
		}
		for _, id := range p.MiddlewareIDs {
			names[id] = append(names[id], p.Name)
		}
	}
	out := []*Middleware{}
	for _, m := range all {
		if len(names[m.ID]) > 0 {
			out = append(out, m)
		}
	}
	return out, names
}

// ---------- audit ----------

type AuditEntry struct {
	ID      int64  `json:"id"`
	TS      string `json:"ts"`
	Client  string `json:"client"`
	MW      string `json:"mw"`
	Tool    string `json:"tool"`
	Action  string `json:"action"`
	Perm    string `json:"perm"`
	Allowed bool   `json:"allowed"`
	Result  string `json:"result"`
	MS      int64  `json:"ms"`
}

func (a *App) audit(e AuditEntry) {
	clip := func(s string, n int) string {
		s = a.vault.Scrub(s)
		if r := []rune(s); len(r) > n {
			return string(r[:n]) + "…"
		}
		return s
	}
	a.store.db.Exec(`INSERT INTO mw_audit(ts,client,mw,tool,action,perm,allowed,result,ms) VALUES(?,?,?,?,?,?,?,?,?)`,
		now(), clip(e.Client, 80), clip(e.MW, 80), e.Tool, clip(e.Action, 600), e.Perm, b2i(e.Allowed), clip(e.Result, 300), e.MS)
	a.store.db.Exec(`DELETE FROM mw_audit WHERE id <= (SELECT MAX(id) FROM mw_audit) - 5000`)
}

func (s *Store) ListAudit(mw string, limit int) []AuditEntry {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	var rows *sql.Rows
	var err error
	if mw != "" {
		rows, err = s.db.Query(`SELECT id,ts,client,mw,tool,action,perm,allowed,result,ms FROM mw_audit WHERE mw=? ORDER BY id DESC LIMIT ?`, mw, limit)
	} else {
		rows, err = s.db.Query(`SELECT id,ts,client,mw,tool,action,perm,allowed,result,ms FROM mw_audit ORDER BY id DESC LIMIT ?`, limit)
	}
	out := []AuditEntry{}
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var e AuditEntry
		var al int
		rows.Scan(&e.ID, &e.TS, &e.Client, &e.MW, &e.Tool, &e.Action, &e.Perm, &al, &e.Result, &e.MS)
		e.Allowed = al != 0
		out = append(out, e)
	}
	return out
}

// ---------- secrets + client cache ----------

func (a *App) mwPassword(m *Middleware) (string, error) {
	if m.pwOverride != nil {
		return *m.pwOverride, nil
	}
	ref := m.Config.PasswordRef
	if ref == "" {
		return "", nil
	}
	v, ok := a.vault.Lookup(ref)
	if !ok {
		return "", fmt.Errorf("中间件「%s」的密码配置项不存在，请在控制台「中间件」里重新填写密码", m.Name)
	}
	if v == "" {
		return "", fmt.Errorf("中间件「%s」的密码还没有填写（待填写），请在控制台「中间件」或「配置管理」里填写", m.Name)
	}
	return v, nil
}

func newMWSecretName() string {
	b := make([]byte, 4)
	rand.Read(b)
	return "mw_" + hex.EncodeToString(b) + "_password"
}

// mwPoolPut caches a client and closes the previous client of the same middleware (config changed).
func (a *App) mwPoolPut(id int64, key string, v any) {
	a.mwmu.Lock()
	defer a.mwmu.Unlock()
	if a.mwPoolKeys == nil {
		a.mwPoolKeys = map[int64]string{}
	}
	if old, ok := a.mwPoolKeys[id]; ok && old != key {
		if ov, ok := a.mwPool.LoadAndDelete(old); ok {
			go closeClient(ov)
		}
	}
	a.mwPoolKeys[id] = key
	a.mwPool.Store(key, v)
}

func (a *App) mwPoolDrop(id int64) {
	a.mwmu.Lock()
	defer a.mwmu.Unlock()
	if old, ok := a.mwPoolKeys[id]; ok {
		if ov, ok := a.mwPool.LoadAndDelete(old); ok {
			go closeClient(ov)
		}
		delete(a.mwPoolKeys, id)
	}
}

func closeClient(v any) {
	switch x := v.(type) {
	case io.Closer:
		x.Close()
	case interface{ Close() }:
		x.Close()
	case interface{ Shutdown() error }:
		x.Shutdown()
	}
}

// scrubErr turns a driver error into a message that never contains a secret.
func (a *App) scrubErr(err error, pw string) string {
	s := err.Error()
	if pw != "" {
		s = strings.ReplaceAll(s, pw, secretMask)
	}
	return a.vault.Scrub(s)
}

// ---------- connection test ----------

func (a *App) TestMiddleware(ctx context.Context, m *Middleware) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	pw, err := a.mwPassword(m)
	if err != nil {
		return "", err
	}
	var msg string
	switch m.Type {
	case "mysql":
		msg, err = a.testMySQL(ctx, m)
	case "redis":
		msg, err = a.testRedis(ctx, m)
	case "mq":
		msg, err = a.testMQ(ctx, m)
	case "websocket":
		msg, err = a.testWS(ctx, m)
	default:
		err = errors.New("未知类型")
	}
	if err != nil {
		return "", errors.New(a.scrubErr(err, pw))
	}
	return msg, nil
}

func (a *App) testMySQL(ctx context.Context, m *Middleware) (string, error) {
	db, err := a.mysqlDB(m)
	if err != nil {
		return "", err
	}
	var ver string
	if err := db.QueryRowContext(ctx, "SELECT VERSION()").Scan(&ver); err != nil {
		a.mwPoolDrop(m.ID)
		return "", err
	}
	return "连接成功，数据库版本 " + ver, nil
}

// ---------- descriptions for the AI ----------

func (a *App) mwSummary(m *Middleware) string {
	on := []string{}
	for _, d := range mwPermsOf(m) {
		if m.Config.Perms[d.Key] {
			on = append(on, d.Label)
		}
	}
	perm := "无（所有操作都会返回无权限）"
	if len(on) > 0 {
		perm = strings.Join(on, "、")
	}
	s := fmt.Sprintf("「%s」（%s；已开启权限：%s", m.Name, m.kindLabel(), perm)
	c := m.Config
	switch m.Type {
	case "mysql":
		if c.Database != "" {
			s += "；默认库：" + c.Database
		}
		if len(c.AllowedDBs) > 0 {
			s += "；只允许库：" + strings.Join(c.AllowedDBs, "、")
		}
		if len(c.AllowedTables) > 0 {
			s += "；只允许表：" + strings.Join(c.AllowedTables, "、")
		}
	case "redis":
		if len(c.KeyPrefixes) > 0 {
			s += "；只允许 key 前缀：" + strings.Join(c.KeyPrefixes, "、")
		}
	case "mq":
		if len(c.Topics) > 0 {
			s += "；只允许：" + strings.Join(c.Topics, "、")
		}
	case "websocket":
		if c.isSQLConsole() {
			if list := m.datasourceListForAI(); list != "" {
				s += "；数据源：" + list
			}
			s += fmt.Sprintf("；只读查询，必须写 LIMIT 且走索引，最多 %d 行", c.maxRows())
		} else if len(c.CommandAllow) > 0 {
			s += "；pod_exec 只允许：" + strings.Join(c.CommandAllow, "、")
		} else {
			s += "；pod_exec 不限制命令"
		}
	}
	if c.Description != "" {
		s += "；说明：" + c.Description
	}
	return s + "）"
}

func mwEnum(ms []*Middleware) []string {
	out := []string{}
	for _, m := range ms {
		out = append(out, m.Name)
	}
	sort.Strings(out)
	return out
}

type mwToolDef struct {
	Name, Type, Desc string
	Props            map[string]any
	Required         []string
	Mode             string
}

func mwToolDefs() []mwToolDef {
	str := func(d string) map[string]any { return map[string]any{"type": "string", "description": d} }
	return []mwToolDef{
		{"db_query", "mysql", "在 MySQL / OceanBase 中间件上执行一条 SQL（一次只能一条）。服务端会解析 SQL 并按权限检查：SELECT/SHOW/DESCRIBE/EXPLAIN 需要「查」，INSERT 需要「增」，UPDATE 需要「改」，DELETE/TRUNCATE 需要「删」，CREATE/ALTER/DROP 需要「DDL」；未开启的权限会返回「无权限」。SELECT 会自动限制返回行数。UPDATE/DELETE 默认必须带 WHERE 条件。值请尽量用 ? 占位符配合 params 传入。",
			map[string]any{"sql": str("一条 SQL 语句"), "params": map[string]any{"type": "array", "description": "按顺序替换 SQL 里的 ? 占位符（可选）", "items": map[string]any{}}}, []string{"sql"}, ""},
		{"db_list_tables", "mysql", "列出 MySQL / OceanBase 中间件里的表（需要「查」权限）。",
			map[string]any{"database": str("库名（可选，默认用中间件的默认库）")}, nil, ""},
		{"db_describe_table", "mysql", "查看一张表的列定义（需要「查」权限）。",
			map[string]any{"table": str("表名，可以写成 库名.表名")}, []string{"table"}, ""},
		{"redis_command", "redis", "在 Redis 中间件上执行一条命令。读命令需要「读」，写命令需要「写」，DEL/HDEL/LPOP 等需要「删」，EVAL 需要「脚本」。FLUSHALL/FLUSHDB/CONFIG/SHUTDOWN/DEBUG/KEYS 等危险命令一律禁止（找 key 请用 redis_scan）。",
			map[string]any{"args": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": `命令和参数，例如 ["HGETALL","user:1"]`}, "command": str("也可以直接写成一行命令，例如 GET user:1（有 args 时忽略）")}, nil, ""},
		{"redis_scan", "redis", "用 SCAN 按模式查找 key（需要「读」权限），不会阻塞 Redis。",
			map[string]any{"match": str("匹配模式，例如 user:*（可选）"), "max": map[string]any{"type": "integer", "description": "最多返回多少个 key，默认 100"}}, nil, ""},
		{"mq_send", "mq", "向消息队列发送一条消息（需要「发送」权限）。Kafka / RocketMQ：topic 是 Topic，key 是消息 key，tag 是 RocketMQ 的 Tag。RabbitMQ：只填 topic 时发到同名队列；同时填 key 时 topic 当作 exchange、key 当作 routing key。",
			map[string]any{"topic": str("Topic / 队列 / exchange"), "body": str("消息内容"), "key": str("消息 key / routing key（可选）"), "tag": str("RocketMQ Tag（可选）")}, []string{"topic", "body"}, ""},
		{"mq_peek", "mq", "查看 Topic / 队列里最近的几条消息（需要「查看消息」权限）。只查看，不提交消费位点；RabbitMQ 会把取出的消息放回队列（会标记为 redelivered）。",
			map[string]any{"topic": str("Topic / 队列名"), "max": map[string]any{"type": "integer", "description": "最多返回几条，默认 10"}}, []string{"topic"}, ""},
		{"mq_list_topics", "mq", "列出消息队列里的 Topic（需要「查看消息」权限；RabbitMQ 不支持列出队列）。", map[string]any{}, nil, ""},
		{"mq_create_topic", "mq", "创建 Topic / 队列（需要「管理」权限）。",
			map[string]any{"topic": str("Topic / 队列名"), "partitions": map[string]any{"type": "integer", "description": "Kafka 分区数 / RocketMQ 队列数（可选）"}}, []string{"topic"}, ""},
		{"pod_read_log", "websocket", "在 WebSocket 终端里查看日志文件末尾（需要「查日志」权限）。服务端固定执行 tail，不会运行其他命令。lines 不填默认 100，最大 2000。连接参数（如 app_code、pod_name）填这个中间件地址里要求的那些。",
			map[string]any{"file": str("日志文件路径，例如 BusinessException.log 或 /var/log/app.log"), "lines": map[string]any{"type": "integer", "description": "末尾行数，默认 100，最大 2000"}}, []string{"file"}, wsModeTerminal},
		{"pod_exec", "websocket", "在 WebSocket 终端里执行一条命令（需要「执行命令」权限，默认关闭）。配置了允许的命令时，管道可以用 | 连接，但每一段的命令都要在允许列表中，不能使用重定向或命令替换。允许列表为空时，命令会原样发到远端 shell。列表里缺的命令请在中间件配置里追加。find 只允许 -name、-mmin、-mtime、-type、-size、-maxdepth；cut 只允许 -c；rg 不能使用 --pre。",
			map[string]any{"command": str("要执行的命令，例如 ls /app/logs"), "timeout": map[string]any{"type": "integer", "description": "超时秒数（可选，不能超过中间件里配置的超时）"}}, []string{"command"}, wsModeTerminal},
		{wsSQLQueryTool, "websocket", "在 WebSocket SQL 控制台中间件上执行一条只读查询。必须是单条 SELECT，必须写 LIMIT（不超过允许的行数，最多 200 行），必须走索引。参数 database 填写该中间件已配置的数据源别名；请根据用户的问题，对照工具说明里列出的数据源及其说明，选择最匹配的一项。",
			map[string]any{"sql": str("一条只读 SELECT，必须带 LIMIT"), "database": str("数据源别名（见工具说明中的数据源列表）")}, []string{"sql", "database"}, wsModeSQLConsole},
	}
}

// mwToolList builds the MCP tool entries for middleware in enabled packs.
func (a *App) mwToolList() []map[string]any {
	ms, packs := a.store.ExposedMiddleware()
	return a.mwToolListFor(ms, packs)
}

// mwToolListFor builds the middleware tool entries for the given middleware (pack names for the description).
func (a *App) mwToolListFor(ms []*Middleware, packs map[int64][]string) []map[string]any {
	byType := map[string][]*Middleware{}
	for _, m := range ms {
		byType[m.Type] = append(byType[m.Type], m)
	}
	out := []map[string]any{}
	for _, d := range mwToolDefs() {
		list := byType[d.Type]
		if d.Mode != "" {
			filtered := []*Middleware{}
			for _, m := range list {
				if m.Config.wsMode() == d.Mode {
					filtered = append(filtered, m)
				}
			}
			list = filtered
		}
		if len(list) == 0 {
			continue
		}
		lines := []string{}
		for _, m := range list {
			lines = append(lines, a.mwSummary(m)+"（流程包："+strings.Join(packs[m.ID], "、")+"）")
		}
		props := map[string]any{"middleware": map[string]any{"type": "string", "enum": mwEnum(list), "description": "要操作的中间件名称"}}
		for k, v := range d.Props {
			props[k] = v
		}
		req := append([]string{"middleware"}, d.Required...)
		if d.Name == wsSQLQueryTool {
			aliases := sqlConsoleAliases(list)
			if len(aliases) > 0 {
				props["database"] = map[string]any{"type": "string", "enum": aliases, "description": "数据源别名。请根据用户的问题，对照下面列出的数据源说明选择最匹配的一项"}
			}
		} else if d.Type == "websocket" {
			for _, n := range wsPlaceholders(list) {
				if isWSInternalPlaceholder(n) {
					continue
				}
				if _, ok := props[n]; ok {
					continue
				}
				props[n] = map[string]any{"type": "string", "description": wsPlaceholderDesc(n)}
				req = append(req, n)
			}
		}
		out = append(out, map[string]any{
			"name":        d.Name,
			"title":       d.Name,
			"description": d.Desc + "\n可用的中间件：\n" + strings.Join(lines, "\n"),
			"inputSchema": map[string]any{"type": "object", "properties": props, "required": req},
		})
	}
	return out
}

func isMWTool(name string) (mwToolDef, bool) {
	for _, d := range mwToolDefs() {
		if d.Name == name {
			return d, true
		}
	}
	return mwToolDef{}, false
}

type mwCall struct {
	a         *App
	m         *Middleware
	tool      string
	client    string
	action    string
	perm      string
	auditNote string
	start     time.Time
}

func (c *mwCall) deny(perm string) string {
	msg := fmt.Sprintf("无权限：中间件「%s」未开启「%s」权限", c.m.Name, permLabel(c.m.Type, perm))
	c.a.audit(AuditEntry{Client: c.client, MW: c.m.Name, Tool: c.tool, Action: c.action, Perm: permLabel(c.m.Type, perm), Allowed: false, Result: msg})
	return msg
}

func (c *mwCall) need(perms ...string) (string, bool) {
	labels := []string{}
	for _, p := range perms {
		if !c.m.Config.Perms[p] {
			return c.deny(p), false
		}
		labels = append(labels, permLabel(c.m.Type, p))
	}
	c.perm = strings.Join(uniq(labels), "+")
	return "", true
}

func (c *mwCall) blocked(msg string) string {
	c.a.audit(AuditEntry{Client: c.client, MW: c.m.Name, Tool: c.tool, Action: c.action, Perm: c.perm, Allowed: false, Result: msg})
	return msg
}

func (c *mwCall) done(result string, err error) (string, bool) {
	ms := time.Since(c.start).Milliseconds()
	if err != nil {
		pw, _ := c.a.mwPassword(c.m)
		msg := "执行失败：" + c.a.scrubErr(err, pw)
		if c.auditNote != "" {
			msg = msg + "（" + c.auditNote + "）"
		}
		c.a.audit(AuditEntry{Client: c.client, MW: c.m.Name, Tool: c.tool, Action: c.action, Perm: c.perm, Allowed: true, Result: msg, MS: ms})
		return msg, true
	}
	resMsg := "成功"
	if c.auditNote != "" {
		resMsg = "成功（" + c.auditNote + "）"
	}
	c.a.audit(AuditEntry{Client: c.client, MW: c.m.Name, Tool: c.tool, Action: c.action, Perm: c.perm, Allowed: true, Result: resMsg, MS: ms})
	pw, _ := c.a.mwPassword(c.m)
	if pw != "" {
		result = strings.ReplaceAll(result, pw, secretMask)
	}
	return c.a.vault.Scrub(result), false
}

func uniq(in []string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func jsonText(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func argStr(args map[string]any, k string) string {
	switch v := args[k].(type) {
	case string:
		return v
	case nil:
		return ""
	case float64:
		return fmt.Sprint(v)
	}
	b, _ := json.Marshal(args[k])
	return string(b)
}

func argInt(args map[string]any, k string, def int) int {
	switch v := args[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case string:
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return def
}

// callMWTool runs one middleware tool. It returns the text for the agent and whether it is an error.
func (a *App) callMWTool(ctx context.Context, client, tool string, args map[string]any) (string, bool) {
	def, _ := isMWTool(tool)
	name := argStr(args, "middleware")
	ms, _ := a.store.ExposedMiddleware()
	var m *Middleware
	avail := []string{}
	for _, x := range ms {
		if x.Type != def.Type {
			continue
		}
		if def.Mode != "" && x.Config.wsMode() != def.Mode {
			continue
		}
		avail = append(avail, x.Name)
		if x.Name == name {
			m = x
		}
	}
	if m == nil {
		msg := fmt.Sprintf("中间件「%s」不存在、类型不匹配，或所在流程包未开启。", name)
		if len(avail) > 0 {
			msg += "可用：" + strings.Join(avail, "、")
		}
		a.audit(AuditEntry{Client: client, MW: name, Tool: tool, Action: "", Allowed: false, Result: msg})
		return msg, true
	}
	c := &mwCall{a: a, m: m, tool: tool, client: client, start: time.Now()}
	switch def.Type {
	case "mysql":
		return a.callDB(ctx, c, args)
	case "redis":
		return a.callRedis(ctx, c, args)
	case "mq":
		return a.callMQ(ctx, c, args)
	case "websocket":
		if def.Name == wsSQLQueryTool {
			return a.callWSSQL(ctx, c, args)
		}
		return a.callWS(ctx, c, args)
	}
	return "未知工具", true
}

func (a *App) callDB(ctx context.Context, c *mwCall, args map[string]any) (string, bool) {
	var sqlText string
	switch c.tool {
	case "db_query":
		sqlText = argStr(args, "sql")
	case "db_list_tables":
		db := strings.TrimSpace(argStr(args, "database"))
		if db == "" {
			db = c.m.Config.Database
		}
		if db == "" {
			sqlText = "SHOW TABLES"
		} else {
			sqlText = "SHOW TABLES FROM " + quoteIdent(db)
		}
	case "db_describe_table":
		t := strings.TrimSpace(argStr(args, "table"))
		if t == "" {
			return "请提供表名", true
		}
		if d, n, ok := strings.Cut(t, "."); ok {
			sqlText = "SHOW COLUMNS FROM " + quoteIdent(d) + "." + quoteIdent(n)
		} else {
			sqlText = "SHOW COLUMNS FROM " + quoteIdent(t)
		}
	}
	c.action = sqlText
	plan, err := classifySQL(sqlText, &c.m.Config)
	if err != nil {
		msg := err.Error()
		if strings.HasPrefix(msg, "无权限") {
			msg = fmt.Sprintf("无权限：中间件「%s」%s", c.m.Name, strings.TrimPrefix(msg, "无权限："))
		}
		return c.blocked(msg), true
	}
	if msg, ok := c.need(plan.Perms...); !ok {
		return msg, true
	}
	var params []any
	if ps, ok := args["params"].([]any); ok {
		for _, p := range ps {
			switch x := p.(type) {
			case map[string]any, []any:
				params = append(params, jsonText(x))
			default:
				params = append(params, x)
			}
		}
	}
	res, err := a.runSQL(ctx, c.m, plan, params)
	if err != nil {
		return c.done("", err)
	}
	if c.tool == "db_list_tables" && len(c.m.Config.AllowedTables) > 0 {
		db := strings.TrimSpace(argStr(args, "database"))
		if db == "" {
			db = c.m.Config.Database
		}
		kept := [][]any{}
		for _, r := range res.Rows {
			if len(r) > 0 && c.m.Config.checkTable(db, fmt.Sprint(r[0])) == nil {
				kept = append(kept, r)
			}
		}
		res.Rows, res.RowCount = kept, len(kept)
	}
	return c.done(jsonText(res), nil)
}
