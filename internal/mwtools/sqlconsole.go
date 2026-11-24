package mwtools

import (
	"action2mcp/internal/credential"
	"action2mcp/internal/execution"
	"action2mcp/internal/invoke"
	"action2mcp/internal/mcp"
	"action2mcp/internal/mwconfig"
	"action2mcp/internal/sqlguard"
	"action2mcp/internal/vault"
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func formatWSSQLResult(res *execution.CallResult, err error) (string, bool) {
	if err != nil {
		return "执行失败：" + err.Error(), true
	}
	if res == nil {
		return "执行失败：没有返回结果", true
	}
	if res.Outcome != "" && res.Outcome != execution.OutcomeSuccess {
		return execution.FirstNonEmpty(res.Error, res.Body, res.Outcome), true
	}
	if res.Error != "" && res.Outcome != execution.OutcomeSuccess {
		return "执行失败：" + res.Error, true
	}
	text := res.Body
	if res.Relogged {
		text = "（登录已过期，已自动重新登录并重试）\n" + text
	}
	return text, false
}

func walkSQLConsolePlaceholders(m *mwconfig.Middleware, fn func(ref string)) {
	if m == nil {
		return
	}
	add := func(s string) {
		for _, g := range execution.PlaceholderPattern().FindAllStringSubmatch(s, -1) {
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
func HeaderRefs(m *mwconfig.Middleware) []string {
	seen := map[string]bool{}
	var out []string
	walkSQLConsolePlaceholders(m, func(ref string) {
		if credential.IsCookieJarRef(ref) {
			return
		}
		name, ok := credential.HeaderBindingName(ref)
		if !ok {
			return
		}
		key := credential.HeaderKey(name)
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

func sqlConsoleNeedsCookieJar(m *mwconfig.Middleware) bool {
	need := false
	walkSQLConsolePlaceholders(m, func(ref string) {
		if credential.IsCookieJarRef(ref) {
			need = true
		}
	})
	return need
}

func hasUserURLPlaceholders(raw string) bool {
	for _, g := range execution.PlaceholderPattern().FindAllStringSubmatch(raw, -1) {
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

func sqlConsoleAliases(ms []*mwconfig.Middleware) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range ms {
		for _, a := range m.DatasourceAliases() {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

func (a *Service) scrubSQLConsoleText(text string, secrets, config []string, isErr bool) string {
	text = a.engine().ScrubApprovalText(text, secrets)
	if isErr {
		text = vault.ScrubConfigTokens(text, config)
	}
	return text
}

func (a *Service) RefreshSQLConsoleTool(t *execution.Tool, args map[string]any) (*execution.Tool, *mwconfig.Middleware, mwconfig.MWDatasource, error) {
	if t == nil || t.ConsoleBinding().ID == 0 {
		return t, nil, mwconfig.MWDatasource{}, nil
	}
	m, err := a.repo.GetMiddleware(t.ConsoleBinding().ID)
	if err != nil {
		return nil, nil, mwconfig.MWDatasource{}, errors.New("中间件不存在或已删除")
	}
	if !m.Config.IsSQLConsole() {
		return nil, nil, mwconfig.MWDatasource{}, errors.New("该中间件不是 SQL 控制台")
	}
	alias := strings.TrimSpace(mcp.ArgString(args, "database"))
	if alias == "" {
		alias = t.ConsoleBinding().Alias
	}
	ds, err := m.LookupDatasource(alias)
	if err != nil {
		return nil, m, mwconfig.MWDatasource{}, err
	}
	tool, err := m.SQLConsoleTool(ds)
	if err != nil {
		return nil, m, ds, err
	}
	return tool, m, ds, nil
}

func (a *Service) callWSSQL(ctx context.Context, c *mwCall, args map[string]any) (string, bool) {
	if !c.m.Config.IsSQLConsole() {
		return c.blocked("该中间件不是 SQL 控制台，不能用 ws_sql_query 调用"), true
	}
	if !c.m.Config.Perms["select"] && !c.m.Config.Perms["describe"] && !c.m.Config.Perms["list_tables"] {
		msg, _ := c.need("select")
		return msg, true
	}
	sqlText := strings.TrimSpace(mcp.ArgString(args, "sql"))
	alias := strings.TrimSpace(mcp.ArgString(args, "database"))
	c.action = alias + ": " + sqlText
	allowed := c.m.DatasourceAliases()
	needDB := alias == "" && len(allowed) > 1
	if sqlText == "" && needDB {
		return c.blocked("请提供 sql、database（数据源别名）。可用：" + strings.Join(allowed, "、")), true
	}
	if sqlText == "" {
		return c.blocked("请提供 sql"), true
	}
	cfgAll := c.m.AllConfigHideValues()
	ds, err := c.m.LookupDatasource(alias)
	if err != nil {
		return c.blocked(a.scrubSQLConsoleText(err.Error(), nil, cfgAll, true)), true
	}
	cfgVals := ds.ConfigHideValues(&c.m.Config)
	maxRows := ds.EffectiveMaxRows(&c.m.Config)
	kind, err := sqlguard.CheckWithOptions(sqlText, sqlguard.Options{MaxRows: maxRows, AllowDescribe: true, AllowListTables: true})
	if err != nil {
		_, checkErr := sqlguard.CheckWithOptions(sqlText, sqlguard.Options{MaxRows: maxRows, AllowDescribe: c.m.Config.Perms["describe"], AllowListTables: c.m.Config.Perms["list_tables"]})
		return c.blocked(a.scrubSQLConsoleText(checkErr.Error(), nil, cfgVals, true)), true
	}
	switch kind {
	case sqlguard.KindDescribe:
		if msg, ok := c.need("describe"); !ok {
			return msg, true
		}
	case sqlguard.KindListTables:
		if msg, ok := c.need("list_tables"); !ok {
			return msg, true
		}
	default:
		if msg, ok := c.need("select"); !ok {
			return msg, true
		}
	}
	if err := a.ensureSQLConsoleCredentials(c.m, nil); err != nil {
		return c.blocked(a.scrubSQLConsoleText(err.Error(), nil, cfgVals, true)), true
	}
	tool, err := c.m.SQLConsoleTool(ds)
	if err != nil {
		return c.blocked(a.scrubSQLConsoleText(err.Error(), nil, cfgVals, true)), true
	}
	return a.execWSSQLTool(ctx, c, ds, tool, sqlText, args, cfgVals)
}

func (a *Service) execWSSQLTool(ctx context.Context, c *mwCall, ds mwconfig.MWDatasource, tool *execution.Tool, sqlText string, args map[string]any, cfgVals []string) (string, bool) {
	callArgs := map[string]any{"sql": sqlText, "database": ds.Alias}
	prepared, err := a.engine().Prepare(tool, callArgs)
	if err != nil {
		return c.blocked(a.scrubSQLConsoleText(err.Error(), nil, cfgVals, true)), true
	}
	prepared.RedactConsole(c.m.Name, ds.Alias, cfgVals)
	var pending *invoke.Approved
	prefix := ""
	if c.m.Config.SQLConsoleApproval() != "off" {
		_, explanation := execution.ExtractApprovalNote(tool, args)
		if explanation != "" {
			explanation = a.scrubSQLConsoleText(explanation, nil, cfgVals, true)
		}
		pending, err = a.approvals().Wait(ctx, tool, callArgs, prepared, c.client, explanation)
		if err != nil {
			return c.blocked(a.engine().ScrubPrepared(err.Error(), prepared, true)), true
		}
		if !a.approvals().CommitValid(pending) {
			a.approvals().Service().RecordResult(pending.Record.ID, "未执行：中间件在审批期间被修改或已移出已开启的流程包")
			return c.blocked("中间件或请求内容在审批期间变化，未执行，请重新调用"), true
		}
		prepared = pending.Prepared
		prefix = a.approvals().EditPrefix(pending)
	} else {
		c.auditNote = "未审批，直接执行"
	}
	res, err := a.engine().Send(prepared)
	text, isErr := formatWSSQLResult(res, err)
	text = prefix + text
	if isErr {
		text = a.engine().ScrubPrepared(text, prepared, true)
		if strings.Contains(strings.ToLower(sqlText), "information_schema") &&
			(strings.Contains(text, "EXPLAIN") || strings.Contains(text, "索引") || strings.Contains(text, "主键")) {
			text += "\n提示：information_schema 为系统元数据视图，无法通过索引预检；查看表列表请直接执行 SHOW TABLES（或 SHOW TABLES LIKE '%关键字%'），查看表结构/索引请执行 DESCRIBE <table> / SHOW FULL COLUMNS FROM <table> / SHOW INDEX FROM <table>。"
		}
	}
	if pending != nil {
		a.approvals().Service().RecordResult(pending.Record.ID, text)
	}
	out, failed := c.done(text, nil)
	if isErr {
		return out, true
	}
	return out, failed
}

func (a *Service) testWSSQLConsole(ctx context.Context, m *mwconfig.Middleware) (string, error) {
	if err := mwconfig.NormalizeSQLConsole(m); err != nil {
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
		if execution.BindingPlaceholder(v) {
			ref := strings.TrimSpace(v[2 : len(v)-2])
			val, err := a.engine().ResolveWSReference(ref, m.Config.URL, &secrets)
			if err != nil {
				return "", err
			}
			headers.Set(k, val)
		} else if v != "" {
			headers.Set(k, v)
		}
	}
	cookies, _ := a.cookies(m.Config.URL)
	if ch, matched := execution.CookieHeader(cookies, m.Config.URL); ch != "" {
		headers.Set("Cookie", ch)
		execution.RememberSecret(&secrets, ch)
		for _, c := range matched {
			execution.RememberCookieValue(&secrets, c.Value)
		}
	}
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	conn, resp, err := a.engine().DialWS(cctx, m.Config.URL, headers)
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return "", fmt.Errorf("未登录，请先在「登录中心」登录这个网站（HTTP %d）", resp.StatusCode)
		}
		return "", err
	}
	conn.Close()
	return "连接成功，已完成握手（未执行 SQL）", nil
}

func (a *Service) ensureSQLConsoleCredentials(m *mwconfig.Middleware, secrets *[]string) error {
	for _, name := range HeaderRefs(m) {
		if _, err := a.login().GetSiteHeader(m.Config.URL, name); err != nil {
			return err
		}
	}
	if sqlConsoleNeedsCookieJar(m) {
		if _, err := a.engine().ResolveWSReference("header.cookie", m.Config.URL, secrets); err != nil {
			return err
		}
	}
	return nil
}
