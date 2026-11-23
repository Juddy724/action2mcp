// Package mwtools exposes configured middleware (databases, Redis, MQ, WebSocket terminals and SQL consoles) as MCP tools with permission checks, audit and secret scrubbing.
package mwtools

import (
	"action2mcp/internal/execution"
	"action2mcp/internal/invoke"
	"action2mcp/internal/mcp"
	"action2mcp/internal/middleware"
	"action2mcp/internal/mwconfig"
	"action2mcp/internal/site"
	"action2mcp/internal/store"
	"action2mcp/internal/vault"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// mwRepository is the persistence surface the middleware service needs.
type Repository interface {
	AppendAudit(e store.AuditEntry)
	EnsureSite(rawURL string) *site.Site
	ExposedMiddleware() ([]*mwconfig.Middleware, map[int64][]string)
	GetMiddleware(id int64) (*mwconfig.Middleware, error)
	SiteByOrigin(origin string) *site.Site
}

// mwSecrets resolves and scrubs vault-backed middleware secrets.
type Secrets interface {
	Lookup(name string) (string, bool)
	Scrub(s string) string
}

// mwLogin is the site-session surface used by WebSocket middleware.
type Login interface {
	Generation(origin string) int64
	GetSiteHeader(rawURL string, name string) (string, error)
	Relogin(site *site.Site, seenGen int64, force bool, interactive bool) error
}

type Options struct {
	Repository Repository
	Secrets    Secrets
	Drivers    *middleware.Drivers
	Cookies    func(rawURL string) ([]execution.Cookie, string)
	Login      func() Login
	Engine     func() *execution.Engine
	Approvals  func() *invoke.Gateway
}

// mwService exposes configured middleware as MCP tools: catalog, permission
// checks, audit, native drivers, WebSocket terminals and SQL consoles.
type Service struct {
	repo      Repository
	secrets   Secrets
	drivers   *middleware.Drivers
	cookies   func(rawURL string) ([]execution.Cookie, string)
	login     func() Login
	engine    func() *execution.Engine
	approvals func() *invoke.Gateway
}

func New(o Options) *Service {
	return &Service{repo: o.Repository, secrets: o.Secrets, drivers: o.Drivers, cookies: o.Cookies, login: o.Login, engine: o.Engine, approvals: o.Approvals}
}

func mwEnum(ms []*mwconfig.Middleware) []string {
	out := []string{}
	for _, m := range ms {
		out = append(out, m.Name)
	}
	sort.Strings(out)
	return out
}

type ToolDef struct {
	Name, Type, Desc string
	Props            map[string]any
	Required         []string
	Mode             string
}

func mwToolDefs() []ToolDef {
	str := func(d string) map[string]any { return map[string]any{"type": "string", "description": d} }
	return []ToolDef{
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
			map[string]any{"file": str("日志文件路径，例如 BusinessException.log 或 /var/log/app.log"), "lines": map[string]any{"type": "integer", "description": "末尾行数，默认 100，最大 2000"}}, []string{"file"}, mwconfig.WSModeTerminal},
		{"pod_exec", "websocket", "在 WebSocket 终端里执行一条命令（需要「执行命令」权限，默认关闭）。配置了允许的命令时，管道可以用 | 连接，但每一段的命令都要在允许列表中，不能使用重定向或命令替换。允许列表为空时，命令会原样发到远端 shell。列表里缺的命令请在中间件配置里追加。find 只允许 -name、-mmin、-mtime、-type、-size、-maxdepth；cut 只允许 -c；rg 不能使用 --pre。",
			map[string]any{"command": str("要执行的命令，例如 ls /app/logs"), "timeout": map[string]any{"type": "integer", "description": "超时秒数（可选，不能超过中间件里配置的超时）"}}, []string{"command"}, mwconfig.WSModeTerminal},
		{mwconfig.WSSQLQueryTool, "websocket", "在 WebSocket SQL 控制台中间件上执行一条只读查询。SELECT 必须是单条、带显式 LIMIT（不超过允许的行数，最多 200 行）且走索引；若中间件开启了「查表结构」权限，也支持 SHOW TABLES / DESCRIBE / DESC / SHOW [FULL] COLUMNS / SHOW INDEX / SHOW CREATE TABLE 查看表列表、表结构与索引（无需 LIMIT 与索引预检）。参数 database 填写该中间件已配置的数据源别名；请根据用户的问题，对照工具说明里列出的数据源及其说明，选择最匹配的一项。",
			map[string]any{"sql": str("一条只读 SELECT（必须带 LIMIT），或已开启「查表结构」时的 SHOW TABLES / DESCRIBE / SHOW COLUMNS / SHOW INDEX / SHOW CREATE TABLE"), "database": str("数据源别名（见工具说明中的数据源列表）"), execution.ApprovalNoteParam: str("操作解释说明与影响分析：请简要说明本次查询的目的、内容以及对业务或系统的影响")}, []string{"sql", "database", execution.ApprovalNoteParam}, mwconfig.WSModeSQLConsole},
		{mwconfig.WSSQLListTablesTool, "websocket", "列出 WebSocket SQL 控制台指定数据源中的数据库表列表（需要「查表结构」权限），避免猜测表名。可选 like 参数按表名模糊过滤（如 %employee%）；查到表名后再用 ws_sql_query 查看表结构（DESCRIBE）或执行 SELECT。",
			map[string]any{"database": str("数据源别名（见工具说明中的数据源列表）"), "like": str("表名模糊匹配模式（可选，支持 % 和 _ 通配符，例如 %employee% 或 ips_%；留空列出全部表）"), execution.ApprovalNoteParam: str("操作解释说明与影响分析：请简要说明本次查询的目的、内容以及对业务或系统的影响")}, []string{"database", execution.ApprovalNoteParam}, mwconfig.WSModeSQLConsole},
	}
}

func IsTool(name string) (ToolDef, bool) {
	for _, d := range mwToolDefs() {
		if d.Name == name {
			return d, true
		}
	}
	return ToolDef{}, false
}

type mwCall struct {
	a         *Service
	m         *mwconfig.Middleware
	tool      string
	client    string
	action    string
	perm      string
	auditNote string
	start     time.Time
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

func mwToolAnnotations(name string) (write bool, destructive, idempotent bool) {
	switch name {
	case "db_list_tables", "db_describe_table", "redis_scan",
		"mq_peek", "mq_list_topics", "pod_read_log", mwconfig.WSSQLQueryTool, mwconfig.WSSQLListTablesTool:
		return false, false, true
	case "db_query":
		return true, true, false
	case "redis_command":
		return true, true, false
	case "mq_send":
		return true, false, false
	case "mq_create_topic":
		return true, true, false
	case "pod_exec":
		return true, true, false
	default:
		return false, false, false
	}
}

func (a *Service) Audit(e store.AuditEntry) {
	clip := func(s string, n int) string {
		s = a.secrets.Scrub(s)
		if r := []rune(s); len(r) > n {
			return string(r[:n]) + "…"
		}
		return s
	}
	e.Client, e.MW, e.Action, e.Result = clip(e.Client, 80), clip(e.MW, 80), clip(e.Action, 600), clip(e.Result, 300)
	a.repo.AppendAudit(e)
}

func (a *Service) Password(m *mwconfig.Middleware) (string, error) {
	if pw, ok := m.PasswordOverride(); ok {
		return pw, nil
	}
	ref := m.Config.PasswordRef
	if ref == "" {
		return "", nil
	}
	v, ok := a.secrets.Lookup(ref)
	if !ok {
		return "", fmt.Errorf("中间件「%s」的密码配置项不存在，请在控制台「中间件」里重新填写密码", m.Name)
	}
	if v == "" {
		return "", fmt.Errorf("中间件「%s」的密码还没有填写（待填写），请在控制台「中间件」或「配置管理」里填写", m.Name)
	}
	return v, nil
}

// scrubErr turns a driver error into a message that never contains a secret.
func (a *Service) ScrubError(err error, pw string) string {
	s := err.Error()
	if pw != "" {
		s = strings.ReplaceAll(s, pw, vault.Mask)
	}
	return a.secrets.Scrub(s)
}

func (a *Service) Test(ctx context.Context, m *mwconfig.Middleware) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	pw, err := a.Password(m)
	if err != nil {
		return "", err
	}
	var msg string
	switch m.Type {
	case "mysql", "redis", "mq":
		msg, err = a.drivers.Test(ctx, a.nativeTarget(m))
	case "websocket":
		msg, err = a.testWS(ctx, m)
	default:
		err = errors.New("未知类型")
	}
	if err != nil {
		return "", errors.New(a.ScrubError(err, pw))
	}
	return msg, nil
}

func (a *Service) Summary(m *mwconfig.Middleware) string {
	on := []string{}
	for _, d := range mwconfig.MWPermsOf(m) {
		if m.Config.Perms[d.Key] {
			on = append(on, d.Label)
		}
	}
	perm := "无（所有操作都会返回无权限）"
	if len(on) > 0 {
		perm = strings.Join(on, "、")
	}
	s := fmt.Sprintf("「%s」（%s；已开启权限：%s", m.Name, m.KindLabel(), perm)
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
		if c.IsSQLConsole() {
			if list := m.DatasourceListForAI(); list != "" {
				s += "；数据源：" + list
			}
			s += fmt.Sprintf("；只读查询，必须写 LIMIT 且走索引，最多 %d 行", c.EffectiveMaxRows())
			if c.Perms["describe"] {
				s += "；支持 ws_sql_list_tables 及 SHOW TABLES / DESCRIBE / SHOW COLUMNS / SHOW INDEX / SHOW CREATE TABLE 查看表列表、表结构与索引"
			}
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

// mwToolList builds the MCP tool entries for middleware in enabled packs.
func (a *Service) ToolList() []map[string]any {
	ms, packs := a.repo.ExposedMiddleware()
	return a.ToolListFor(ms, packs)
}

// mwToolListFor builds the middleware tool entries for the given middleware (pack names for the description).
func (a *Service) ToolListFor(ms []*mwconfig.Middleware, packs map[int64][]string) []map[string]any {
	byType := map[string][]*mwconfig.Middleware{}
	for _, m := range ms {
		byType[m.Type] = append(byType[m.Type], m)
	}
	out := []map[string]any{}
	for _, d := range mwToolDefs() {
		list := byType[d.Type]
		if d.Mode != "" {
			filtered := []*mwconfig.Middleware{}
			for _, m := range list {
				if m.Config.EffectiveWSMode() == d.Mode {
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
			lines = append(lines, a.Summary(m)+"（流程包："+strings.Join(packs[m.ID], "、")+"）")
		}
		props := map[string]any{"middleware": map[string]any{"type": "string", "enum": mwEnum(list), "description": "要操作的中间件名称"}}
		for k, v := range d.Props {
			props[k] = v
		}
		req := append([]string{"middleware"}, d.Required...)
		if d.Name == mwconfig.WSSQLQueryTool || d.Name == mwconfig.WSSQLListTablesTool {
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
		desc := d.Desc
		write, destructive, idempotent := mwToolAnnotations(d.Name)
		if write {
			desc = mcp.ApplyWritePrefix(desc)
		}
		out = append(out, map[string]any{
			"name":        d.Name,
			"title":       d.Name,
			"description": desc + "\n可用的中间件：\n" + strings.Join(lines, "\n"),
			"inputSchema": map[string]any{"type": "object", "properties": props, "required": req},
			"annotations": mcp.Annotations(!write, destructive, idempotent),
		})
	}
	return out
}

func (c *mwCall) deny(perm string) string {
	msg := fmt.Sprintf("无权限：中间件「%s」未开启「%s」权限", c.m.Name, mwconfig.PermLabel(c.m.Type, perm))
	c.a.Audit(store.AuditEntry{Client: c.client, MW: c.m.Name, Tool: c.tool, Action: c.action, Perm: mwconfig.PermLabel(c.m.Type, perm), Allowed: false, Result: msg})
	return msg
}

func (c *mwCall) need(perms ...string) (string, bool) {
	labels := []string{}
	for _, p := range perms {
		if !c.m.Config.Perms[p] {
			return c.deny(p), false
		}
		labels = append(labels, mwconfig.PermLabel(c.m.Type, p))
	}
	c.perm = strings.Join(uniq(labels), "+")
	return "", true
}

func (c *mwCall) blocked(msg string) string {
	c.a.Audit(store.AuditEntry{Client: c.client, MW: c.m.Name, Tool: c.tool, Action: c.action, Perm: c.perm, Allowed: false, Result: msg})
	return msg
}

func isDBQueryTool(name string) bool {
	switch name {
	case mwconfig.WSSQLQueryTool, mwconfig.WSSQLListTablesTool, "db_query", "db_list_tables", "db_describe_table":
		return true
	default:
		return false
	}
}

func (c *mwCall) done(result string, err error) (string, bool) {
	ms := time.Since(c.start).Milliseconds()
	if err != nil {
		pw, _ := c.a.Password(c.m)
		msg := "执行失败：" + c.a.ScrubError(err, pw)
		if c.auditNote != "" {
			msg = msg + "（" + c.auditNote + "）"
		}
		c.a.Audit(store.AuditEntry{Client: c.client, MW: c.m.Name, Tool: c.tool, Action: c.action, Perm: c.perm, Allowed: true, Result: msg, MS: ms})
		return msg, true
	}
	resMsg := "成功"
	if c.auditNote != "" {
		resMsg = "成功（" + c.auditNote + "）"
	}
	c.a.Audit(store.AuditEntry{Client: c.client, MW: c.m.Name, Tool: c.tool, Action: c.action, Perm: c.perm, Allowed: true, Result: resMsg, MS: ms})
	if isDBQueryTool(c.tool) {
		return result, false
	}
	pw, _ := c.a.Password(c.m)
	if pw != "" {
		result = strings.ReplaceAll(result, pw, vault.Mask)
	}
	return c.a.secrets.Scrub(result), false
}

// callMWTool runs one middleware tool. It returns the text for the agent and whether it is an error.
func (a *Service) Call(ctx context.Context, client, tool string, args map[string]any) (string, bool) {
	def, _ := IsTool(tool)
	name := mcp.ArgString(args, "middleware")
	ms, _ := a.repo.ExposedMiddleware()
	var m *mwconfig.Middleware
	avail := []string{}
	for _, x := range ms {
		if x.Type != def.Type {
			continue
		}
		if def.Mode != "" && x.Config.EffectiveWSMode() != def.Mode {
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
		a.Audit(store.AuditEntry{Client: client, MW: name, Tool: tool, Action: "", Allowed: false, Result: msg})
		return msg, true
	}
	c := &mwCall{a: a, m: m, tool: tool, client: client, start: time.Now()}
	switch def.Type {
	case "mysql", "redis", "mq":
		return a.drivers.Execute(ctx, a.nativeTarget(m), tool, args, nativeObserver{c})
	case "websocket":
		if def.Name == mwconfig.WSSQLQueryTool {
			return a.callWSSQL(ctx, c, args)
		}
		if def.Name == mwconfig.WSSQLListTablesTool {
			return a.callWSSQLListTables(ctx, c, args)
		}
		return a.callWS(ctx, c, args)
	}
	return "未知工具", true
}
