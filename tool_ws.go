package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

const (
	outcomeSuccess       = "success"
	outcomeBusinessError = "business_error"
	outcomeGuardRejected = "guard_rejected"
	outcomeAuthFailed    = "auth_failed"
	outcomeUnknown       = "unknown"
)

var defaultAuthKeywords = []string{"token", "unauthorized", "unauth", "expire", "expired", "登录", "过期", "未登录", "凭证"}

func (p *PreparedCall) isWS() bool {
	return strings.EqualFold(p.request.Method, "WS") || p.ws
}

func renderWSMessage(tmpl string, vals map[string]any, deferred *deferredCredentials) (string, error) {
	prefix, tail, ok := splitCommandJSON(tmpl)
	if !ok {
		if strings.Contains(tmpl, "{{") {
			return placeholderRe.ReplaceAllStringFunc(tmpl, func(m string) string {
				return argString(renderValue(vals, placeholderRe.FindStringSubmatch(m)[1], deferred, credentialEncoding{}))
			}), nil
		}
		return tmpl, nil
	}
	dec := json.NewDecoder(strings.NewReader(tail))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return "", fmt.Errorf("消息不是合法 JSON：%w", err)
	}
	if hasDuplicateJSONKeys(tail) {
		return "", errors.New("消息 JSON 含有重复键，已拒绝")
	}
	rendered := renderJSONPlaceholders(v, vals, 0, deferred, 1)
	return strings.TrimRight(prefix, " ") + " " + string(compactJSON(rendered)), nil
}

func hasDuplicateJSONKeys(raw string) bool {
	return dupJSON(json.NewDecoder(strings.NewReader(raw)))
}

func dupJSON(dec *json.Decoder) bool {
	tok, err := dec.Token()
	if err != nil {
		return true
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return false
	}
	switch d {
	case '{':
		seen := map[string]bool{}
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return true
			}
			ks, _ := k.(string)
			if seen[ks] {
				return true
			}
			seen[ks] = true
			if dupJSON(dec) {
				return true
			}
		}
		_, _ = dec.Token()
	case '[':
		for dec.More() {
			if dupJSON(dec) {
				return true
			}
		}
		_, _ = dec.Token()
	}
	return false
}

func extractJSONString(message, path string) (string, error) {
	_, tail, ok := splitCommandJSON(message)
	if !ok {
		return "", errors.New("消息不是「命令 + JSON」格式")
	}
	if hasDuplicateJSONKeys(tail) {
		return "", errors.New("消息 JSON 含有重复键，已拒绝")
	}
	var v any
	dec := json.NewDecoder(strings.NewReader(tail))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	got, ok := jsonPath(v, path)
	if !ok {
		return "", fmt.Errorf("消息中找不到 SQL 路径 %s", path)
	}
	s, ok := got.(string)
	if !ok {
		return "", fmt.Errorf("路径 %s 不是字符串", path)
	}
	return s, nil
}

func replaceJSONString(message, path, value string) (string, error) {
	prefix, tail, ok := splitCommandJSON(message)
	if !ok {
		return "", errors.New("消息不是「命令 + JSON」格式")
	}
	var v any
	dec := json.NewDecoder(strings.NewReader(tail))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return "", err
	}
	if !setJSONPath(&v, path, value) {
		return "", fmt.Errorf("无法替换路径 %s", path)
	}
	return strings.TrimRight(prefix, " ") + " " + string(compactJSON(v)), nil
}

func sqlAliasesFrom(sql string) map[string]bool {
	out := map[string]bool{}
	// Best-effort: checked strictly in the guard visitor already.
	for _, m := range syntheticAliasRe.FindAllString(sql, -1) {
		out[strings.ToLower(m)] = true
	}
	return out
}

func (a *App) dialWS(ctx context.Context, raw string, headers http.Header) (*websocket.Conn, *http.Response, error) {
	if err := a.checkToolDestination(ctx, raw); err != nil {
		return nil, nil, err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, nil, err
	}
	host := u.Hostname()
	d := websocket.Dialer{
		Proxy:            nil,
		HandshakeTimeout: 15 * time.Second,
		NetDialContext:   a.safeNetDial,
		TLSClientConfig:  &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12},
	}
	conn, resp, err := d.DialContext(ctx, u.String(), headers)
	if err != nil {
		return conn, resp, err
	}
	if resp != nil && resp.Body != nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	}
	return conn, resp, nil
}

func (a *App) safeNetDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if err := a.checkToolIP(addr.IP, port); err != nil {
			return nil, err
		}
	}
	dial := (&net.Dialer{}).DialContext
	var last error
	for _, addr := range addrs {
		ip := addr.IP.String()
		if addr.Zone != "" {
			ip += "%" + addr.Zone
		}
		conn, err := dial(ctx, network, net.JoinHostPort(ip, port))
		if err != nil {
			last = err
			continue
		}
		if remote, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
			if err := a.checkToolIP(remote.IP, strconv.Itoa(remote.Port)); err != nil {
				conn.Close()
				return nil, err
			}
		}
		return conn, nil
	}
	if last == nil {
		last = errors.New("无法解析目标地址")
	}
	return nil, last
}

type wsSessionStats struct {
	dials, explain, business, relogins, writes int
}

func (a *App) sendWS(p *PreparedCall, secrets *[]string) (*CallResult, error) {
	if p.configErr != nil {
		return wsResult(p, outcomeGuardRejected, 0, "", p.configErr.Error()), nil
	}
	if err := validateToolConfig("WS", p.wsConfig, true); err != nil {
		return wsResult(p, outcomeGuardRejected, 0, "", err.Error()), nil
	}
	cfg := p.wsConfig
	cfg.applyDefaults()
	budget := 0
	if cfg.Auth != nil && cfg.Auth.RetryRelogin {
		budget = 1
	}
	keywords := defaultAuthKeywords
	if cfg.Auth != nil && len(cfg.Auth.FailMessageMatch) > 0 {
		keywords = cfg.Auth.FailMessageMatch
	}
	var stats wsSessionStats
	p.wsStats = &stats
	var lastRelog bool
	for {
		req, err := p.resolve(func(ref string) (string, error) {
			return a.resolveWSRef(ref, p.request.URL, secrets)
		})
		if err != nil {
			if budget > 0 && isMissingHeaderErr(err) {
				if err2 := a.reloginForWS(p, &stats); err2 != nil {
					return wsResult(p, outcomeAuthFailed, 0, "", err.Error()+"; "+err2.Error()), nil
				}
				budget = 0
				lastRelog = true
				continue
			}
			if isMissingHeaderErr(err) {
				return wsResult(p, outcomeAuthFailed, 0, "", err.Error()), nil
			}
			return nil, err
		}
		messages := make([]string, len(p.wsMessages))
		pairs := []string{}
		values := map[string]string{}
		// p.resolve already applied to request.Body; reconstruct messages from frozen templates
		// by applying the same substitutions stored on the prepared call.
		resolved, err := p.resolveMessages(func(ref string) (string, error) {
			v, err := a.resolveWSRef(ref, p.request.URL, secrets)
			if err == nil {
				values[ref] = v
			}
			return v, err
		})
		if err != nil {
			if budget > 0 && isMissingHeaderErr(err) {
				if err2 := a.reloginForWS(p, &stats); err2 != nil {
					return wsResult(p, outcomeAuthFailed, 0, "", err.Error()+"; "+err2.Error()), nil
				}
				budget = 0
				lastRelog = true
				continue
			}
			if isMissingHeaderErr(err) {
				return wsResult(p, outcomeAuthFailed, 0, "", err.Error()), nil
			}
			return nil, err
		}
		messages = resolved
		_ = req
		_ = pairs

		sql := p.wsSQL
		if cfg.sqlGuardEnabled() {
			got, err := extractJSONString(messages[0], cfg.SQLGuard.Path)
			if err != nil {
				return wsResult(p, outcomeGuardRejected, 0, "", err.Error()), nil
			}
			if got != sql {
				return wsResult(p, outcomeGuardRejected, 0, "", "待执行的 SQL 与批准内容不一致"), nil
			}
			if err := checkGuardedSQL(sql, cfg.maxRows()); err != nil {
				return wsResult(p, outcomeGuardRejected, 0, "", err.Error()), nil
			}
		}

		headers := http.Header{}
		for k, v := range p.previewHeaders(req) { // use resolved headers
			headers.Set(k, v)
		}
		cookies, src := a.CookiesFor(p.request.URL)
		if ch, matched := CookieHeader(cookies, p.request.URL); ch != "" {
			headers.Set("Cookie", ch)
			for _, c := range matched {
				*secrets = append(*secrets, c.Value)
			}
		}
		_ = src

		timeout := time.Duration(cfg.timeout()) * time.Millisecond
		if cfg.sqlGuardEnabled() {
			explainMsg, err := replaceJSONString(messages[0], cfg.SQLGuard.Path, "EXPLAIN "+sql)
			if err != nil {
				return wsResult(p, outcomeGuardRejected, 0, "", err.Error()), nil
			}
			exRes, authFail, err := a.roundTripWS(p, headers, explainMsg, cfg, timeout, &stats, true, keywords, secrets)
			if err != nil && budget > 0 && authFail {
				if err2 := a.reloginForWS(p, &stats); err2 != nil {
					res := wsResult(p, outcomeAuthFailed, 0, "", err.Error())
					res.Relogged = lastRelog
					return res, nil
				}
				budget = 0
				lastRelog = true
				continue
			}
			if err != nil && authFail {
				res := wsResult(p, outcomeAuthFailed, 0, "", err.Error())
				res.Relogged = lastRelog
				return res, nil
			}
			if err != nil {
				res := wsResult(p, outcomeGuardRejected, 0, "", err.Error())
				res.Relogged = lastRelog
				return res, nil
			}
			_ = exRes
		}

		biz, authFail, err := a.roundTripWS(p, headers, messages[0], cfg, timeout, &stats, false, keywords, secrets)
		if err != nil && budget > 0 && authFail && stats.writes == 0 {
			if err2 := a.reloginForWS(p, &stats); err2 != nil {
				res := wsResult(p, outcomeAuthFailed, 0, "", err.Error())
				res.Relogged = lastRelog
				return res, nil
			}
			budget = 0
			lastRelog = true
			continue
		}
		if biz != nil {
			biz.Relogged = lastRelog
			biz.CredSource = src
		}
		if err != nil && biz != nil {
			return biz, nil
		}
		if err != nil {
			return nil, err
		}
		return biz, nil
	}
}

func (p *PreparedCall) previewHeaders(r RequestPreview) map[string]string {
	if r.Headers != nil {
		return r.Headers
	}
	return p.request.Headers
}

func (p *PreparedCall) resolveMessages(resolve func(string) (string, error)) ([]string, error) {
	out := make([]string, len(p.wsMessages))
	for i, tmpl := range p.wsMessages {
		// Reuse the same substitution tokens as request rendering.
		msg, err := p.replaceSubs(tmpl, resolve)
		if err != nil {
			return nil, err
		}
		out[i] = msg
	}
	return out, nil
}

func (p *PreparedCall) replaceSubs(s string, resolve func(string) (string, error)) (string, error) {
	if len(p.subs) == 0 {
		return s, nil
	}
	pairs := []string{}
	values := map[string]string{}
	for _, sub := range p.subs {
		value, ok := values[sub.ref]
		if !ok {
			var err error
			value, err = resolve(sub.ref)
			if err != nil {
				return "", err
			}
			values[sub.ref] = value
		}
		pairs = append(pairs, sub.token, sub.encoding.encode(value))
	}
	return strings.NewReplacer(pairs...).Replace(s), nil
}

func isMissingHeaderErr(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return strings.Contains(s, "站点缺少请求头") || strings.Contains(s, "站点缺少 Cookie")
}

const missingCookieMsg = "站点缺少 Cookie，请在登录中心登录该网站后再试"

func errMissingCookie() error {
	return errors.New(missingCookieMsg)
}

func rememberSecret(secrets *[]string, values ...string) {
	if secrets == nil {
		return
	}
	for _, v := range values {
		if v != "" {
			*secrets = append(*secrets, v)
		}
	}
}

// resolveCookieJar returns the Cookie header the browser would send to rawURL
// from the login-center jar. The value is registered as a secret for redaction.
func (a *App) resolveCookieJar(rawURL string, secrets *[]string) (string, error) {
	cs, _ := a.CookiesFor(rawURL)
	ch, matched := CookieHeader(cs, rawURL)
	if ch == "" {
		return "", errMissingCookie()
	}
	rememberSecret(secrets, ch)
	for _, c := range matched {
		rememberSecret(secrets, c.Value)
	}
	return ch, nil
}

func (a *App) resolveWSRef(ref, rawURL string, secrets *[]string) (string, error) {
	switch {
	case isCookieJarRef(ref):
		return a.resolveCookieJar(rawURL, secrets)
	default:
		if name, ok := headerBindingName(ref); ok {
			v, err := a.GetSiteHeader(rawURL, name)
			if err != nil {
				return "", err
			}
			rememberSecret(secrets, v)
			return v, nil
		}
		if name, ok := cookieBindingName(ref); ok {
			cs, _ := a.CookiesFor(rawURL)
			_, matched := CookieHeader(cs, rawURL)
			var hits []Cookie
			for _, c := range matched {
				if strings.EqualFold(c.Name, name) {
					hits = append(hits, c)
				}
			}
			if len(hits) == 0 {
				return "", fmt.Errorf("站点缺少 Cookie %s，请在登录中心登录该网站后再试", name)
			}
			if len(hits) > 1 && len(hits[0].Path) == len(hits[1].Path) {
				return "", fmt.Errorf("Cookie %s 存在多个匹配项，已拒绝", name)
			}
			rememberSecret(secrets, hits[0].Value)
			return hits[0].Value, nil
		}
		v, err := a.vault.Resolve(ref)
		if err == nil && v != "" {
			rememberSecret(secrets, v)
		}
		return v, err
	}
}

func (a *App) reloginForWS(p *PreparedCall, stats *wsSessionStats) error {
	stats.relogins++
	if a.wsReloginHook != nil {
		return a.wsReloginHook()
	}
	site := a.store.EnsureSite(credOrigin(p.request.URL))
	if site == nil {
		return errors.New("找不到站点登录配置")
	}
	st := a.state(site.Origin)
	if err := a.Relogin(site, a.siteGen(st), false, true); err != nil {
		return err
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		need := false
		for _, sub := range p.subs {
			if isCookieJarRef(sub.ref) {
				continue
			}
			name, ok := headerBindingName(sub.ref)
			if !ok {
				continue
			}
			need = true
			if _, err := a.GetSiteHeader(p.request.URL, name); err == nil {
				need = false
				break
			}
		}
		if !need {
			return nil
		}
		time.Sleep(150 * time.Millisecond)
	}
	return errors.New("重新登录后仍未收获到必需请求头")
}

func wsResult(p *PreparedCall, outcome string, status int, body, errText string) *CallResult {
	res := &CallResult{Method: "WS", URL: p.request.URL, Status: status, Body: body, Error: errText, Outcome: outcome, Headers: map[string]string{}}
	if outcome != outcomeSuccess && res.Error == "" {
		res.Error = body
	}
	return res
}

func (a *App) roundTripWS(p *PreparedCall, headers http.Header, message string, cfg ToolConfig, timeout time.Duration, stats *wsSessionStats, explain bool, keywords []string, secrets *[]string) (*CallResult, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	stats.dials++
	conn, resp, err := a.dialWS(ctx, p.request.URL, headers)
	if err != nil {
		auth := false
		if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403) {
			auth = true
		}
		return nil, auth, err
	}
	defer conn.Close()
	max := int64(cfg.maxBytes())
	conn.SetReadLimit(max)
	deadline := time.Now().Add(timeout)
	conn.SetReadDeadline(deadline)
	conn.SetWriteDeadline(deadline)

	if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
		// May have been sent.
		if !explain {
			stats.writes++
			stats.business++
		} else {
			stats.explain++
		}
		return wsResult(p, outcomeUnknown, 0, "", "写入 WebSocket 消息失败，结果不明"), false, errors.New("写入 WebSocket 消息失败，结果不明")
	}
	if explain {
		stats.explain++
	} else {
		stats.writes++
		stats.business++
	}

	var frames []string
	var total int
	resultCmd := "execResult"
	closeCmds := map[string]bool{"close": true}
	successPath, donePath, messagePath := "data.success", "data.done", "data.message"
	if cfg.Collect != nil {
		if cfg.Collect.ResultCmd != "" {
			resultCmd = cfg.Collect.ResultCmd
		}
		if len(cfg.Collect.CloseCmds) > 0 {
			closeCmds = map[string]bool{}
			for _, c := range cfg.Collect.CloseCmds {
				closeCmds[strings.ToLower(c)] = true
			}
		}
		if cfg.Collect.SuccessPath != "" {
			successPath = cfg.Collect.SuccessPath
		}
		if cfg.Collect.DonePath != "" {
			donePath = cfg.Collect.DonePath
		}
		if cfg.Collect.MessagePath != "" {
			messagePath = cfg.Collect.MessagePath
		}
	}
	var execPayload any
	var execMsg string
	var success *bool
	gotResult := false
	for {
		_, data, err := conn.ReadMessage()
		if err != nil {
			if !gotResult {
				if explain {
					return nil, false, errors.New("无法解析 EXPLAIN 结果，已取消执行")
				}
				return wsResult(p, outcomeUnknown, 0, "", "WebSocket 结果不完整"), false, errors.New("WebSocket 结果不完整")
			}
			break
		}
		total += len(data)
		if int64(total) > max {
			if explain {
				return nil, false, errors.New("无法解析 EXPLAIN 结果，已取消执行")
			}
			return wsResult(p, outcomeUnknown, 0, "", "结果超过大小限制"), false, errors.New("结果超过大小限制")
		}
		text := string(data)
		frames = append(frames, text)
		cmd, tail, ok := splitCommandJSON(text)
		if !ok {
			continue
		}
		cmd = strings.ToLower(strings.TrimSpace(cmd))
		payload, _ := asJSONMap(tail)
		if cmd == strings.ToLower(resultCmd) {
			gotResult = true
			execPayload = payload
			if v, ok := jsonPath(payload, messagePath); ok {
				execMsg = fmt.Sprint(v)
			}
			if v, ok := jsonPath(payload, successPath); ok {
				b := truthy(v)
				success = &b
			}
			if v, ok := jsonPath(payload, donePath); ok && truthy(v) && (success != nil) {
				// done
			}
		}
		if closeCmds[cmd] {
			break
		}
	}
	if execMsg != "" {
		*secrets = append(*secrets, extractLikelySecrets(execMsg)...)
	}
	authFail := success != nil && !*success && messageMatches(execMsg, keywords)
	if explain {
		if authFail {
			return nil, true, errors.New(firstNonEmpty(execMsg, "EXPLAIN 鉴权失败"))
		}
		if success != nil && !*success {
			return nil, false, errors.New(firstNonEmpty(execMsg, "EXPLAIN 失败"))
		}
		if err := interpretExplainPayload(execPayload, p.wsSQL); err != nil {
			return nil, false, err
		}
		return wsResult(p, outcomeSuccess, 0, "", ""), false, nil
	}
	if authFail {
		return wsResult(p, outcomeAuthFailed, 0, execMsg, execMsg), true, errors.New(execMsg)
	}
	if success != nil && !*success {
		res := wsResult(p, outcomeBusinessError, 0, execMsg, execMsg)
		return res, false, nil
	}
	body, truncated, count, err := compactExecResult(execPayload, cfg.maxRows())
	if err != nil {
		return wsResult(p, outcomeUnknown, 0, "", err.Error()), false, err
	}
	res := wsResult(p, outcomeSuccess, 200, body, "")
	res.Truncated = truncated
	res.RowCount = count
	res.ReqBody = message
	return res, false, nil
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case string:
		return x == "true" || x == "1"
	case json.Number:
		return x.String() != "0"
	default:
		return false
	}
}

func messageMatches(msg string, keys []string) bool {
	l := strings.ToLower(msg)
	for _, k := range keys {
		if k != "" && strings.Contains(l, strings.ToLower(k)) {
			return true
		}
	}
	return false
}

func extractLikelySecrets(s string) []string {
	return nil
}

func interpretExplainPayload(payload any, sql string) error {
	data, _ := jsonPath(payload, "data.executeResult")
	if data == nil {
		if d, ok := jsonPath(payload, "data"); ok {
			data = d
		}
	}
	m, _ := data.(map[string]any)
	if m == nil {
		return errors.New("无法解析 EXPLAIN 结果，已取消执行")
	}
	if v, ok := m["success"]; ok && !truthy(v) {
		return errors.New("无法解析 EXPLAIN 结果，已取消执行")
	}
	result, ok := jsonPath(m, "result")
	if !ok {
		if r, ok := m["executeResult"].(map[string]any); ok {
			result, _ = jsonPath(r, "result")
			m = r
		}
	}
	rm, _ := result.(map[string]any)
	if rm == nil {
		return errors.New("无法解析 EXPLAIN 结果，已取消执行")
	}
	cols := parseExplainColumns(rm["columns"])
	rows := parseExplainRows(rm["result"], cols)
	return checkExplainResult(cols, rows, sqlAliasesFrom(sql))
}

func compactExecResult(payload any, maxRows int) (string, bool, int, error) {
	if maxRows <= 0 || maxRows > sqlGuardMaxRowsCap {
		maxRows = sqlGuardMaxRowsCap
	}
	data, _ := jsonPath(payload, "data.executeResult")
	if data == nil {
		if d, ok := jsonPath(payload, "data"); ok {
			data = d
		}
	}
	m, _ := data.(map[string]any)
	if m == nil {
		b, _ := json.Marshal(payload)
		return string(b), false, 0, nil
	}
	result, _ := jsonPath(m, "result")
	if result == nil {
		if er, ok := m["executeResult"].(map[string]any); ok {
			result = er["result"]
			m = er
		}
	}
	rm, _ := result.(map[string]any)
	out := map[string]any{"success": true}
	if v, ok := m["elapsed"]; ok {
		out["elapsed"] = v
	}
	if rm == nil {
		b, _ := json.Marshal(out)
		return string(b), false, 0, nil
	}
	colsRaw, _ := rm["columns"].([]any)
	type colDef struct {
		ID, Name string
	}
	var cols []colDef
	for i, c := range colsRaw {
		id := "C_" + strconv.Itoa(i+1)
		name := id
		if cm, ok := c.(map[string]any); ok {
			if v := firstPresent(cm, "field", "Field"); fmt.Sprint(v) != "" && fmt.Sprint(v) != "<nil>" {
				id = fmt.Sprint(v)
			}
			if v := firstPresent(cm, "title", "realName", "name"); fmt.Sprint(v) != "" && fmt.Sprint(v) != "<nil>" {
				name = fmt.Sprint(v)
			}
		}
		cols = append(cols, colDef{id, name})
	}
	var rowsOut [][]any
	rawRows, _ := rm["result"].([]any)
	total := len(rawRows)
	if c, ok := rm["count"]; ok {
		switch n := c.(type) {
		case json.Number:
			if i, err := n.Int64(); err == nil {
				total = int(i)
			}
		case float64:
			total = int(n)
		}
	}
	truncated := false
	for i, r := range rawRows {
		if i >= maxRows {
			truncated = true
			break
		}
		rmap, _ := r.(map[string]any)
		row := make([]any, len(cols))
		for j, c := range cols {
			if rmap != nil {
				if v, ok := rmap[c.ID]; ok {
					row[j] = v
					continue
				}
				if v, ok := rmap[c.Name]; ok {
					row[j] = v
				}
			}
		}
		rowsOut = append(rowsOut, row)
	}
	if total > len(rowsOut) {
		truncated = true
	}
	colJSON := []map[string]any{}
	for _, c := range cols {
		colJSON = append(colJSON, map[string]any{"id": c.ID, "name": c.Name})
	}
	out["columns"] = colJSON
	out["rows"] = rowsOut
	out["row_count"] = total
	out["truncated"] = truncated
	if truncated {
		out["truncation"] = fmt.Sprintf("结果已截断，只返回前 %d 行（共 %d 行）", maxRows, total)
	}
	b, _ := json.Marshal(out)
	return string(b), truncated, total, nil
}

func (a *App) freezeWSCall(t *Tool, vals map[string]any, d *deferredCredentials, p *PreparedCall) error {
	if !isWSMethod(t.Method) {
		return nil
	}
	p.ws = true
	p.wsConfig = t.Config
	p.configErr = t.configErr
	if t.configErr != nil {
		return t.configErr
	}
	if err := validateToolConfig(t.Method, t.Config, true); err != nil {
		return err
	}
	cfg := t.Config
	cfg.applyDefaults()
	p.wsConfig = cfg
	msgs := cfg.Messages
	if len(msgs) == 0 && t.Body != "" {
		msgs = []string{t.Body}
	}
	out := make([]string, 0, len(msgs))
	for _, tmpl := range msgs {
		msg, err := renderWSMessage(tmpl, vals, d)
		if err != nil {
			return err
		}
		out = append(out, msg)
	}
	p.wsMessages = out
	if cfg.sqlGuardEnabled() {
		if len(out) != 1 {
			return errors.New("开启 SQL 护栏时必须恰好有一条 execute 消息")
		}
		for _, ref := range placeholderRe.FindAllStringSubmatch(valsSQLArea(out[0], cfg.SQLGuard.Path, argString(vals[cfg.SQLGuard.Param])), -1) {
			if isHeaderCookieRef(ref[1]) || isRefName(ref[1]) {
				return errors.New("SQL 或数据源字段不能使用登录后才解析的凭据引用")
			}
		}
		sql, err := extractJSONString(out[0], cfg.SQLGuard.Path)
		if err != nil {
			return err
		}
		want := argString(vals[cfg.SQLGuard.Param])
		if want != "" && sql != want {
			return errors.New("参数中的 SQL 与消息模板中的 SQL 不一致")
		}
		if err := checkGuardedSQL(sql, cfg.maxRows()); err != nil {
			return err
		}
		p.wsSQL = sql
	}
	p.request.Body = strings.Join(out, "\n---\n")
	return nil
}

func valsSQLArea(message, path, sql string) string {
	return sql
}
