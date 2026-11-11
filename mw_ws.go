package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// A WebSocket middleware is a remote shell reached over ws/wss. Login uses the site's
// browser cookies (登录中心). The address and the frames that carry the command live in
// the middleware config, so this file does not name any particular host.

func defaultWSMessages() []string {
	return []string{
		`{"type":"TERMINAL_COMMAND","text":"{{command}}"}`,
		`{"type":"TERMINAL_COMMAND","text":"\r"}`,
	}
}

var (
	wsPlaceholderRe = regexp.MustCompile(`\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}`)
	ansiRe          = regexp.MustCompile("\x1b\\[[0-9;?]*[A-Za-z]|\x1b\\][^\x07]*\x07")
)

func wsPlaceholders(ms []*Middleware) []string {
	seen := map[string]bool{}
	var names []string
	for _, m := range ms {
		blobs := append([]string{m.Config.URL}, m.Config.WSMessages...)
		for _, blob := range blobs {
			for _, g := range wsPlaceholderRe.FindAllStringSubmatch(blob, -1) {
				n := g[1]
				if isWSInternalPlaceholder(n) || seen[n] {
					continue
				}
				seen[n] = true
				names = append(names, n)
			}
		}
	}
	sort.Strings(names)
	return names
}

func wsPlaceholderDesc(name string) string {
	switch name {
	case "app_code":
		return "应用代码"
	case "pod_name":
		return "Pod 名称"
	case "namespace":
		return "命名空间"
	case "service_name":
		return "服务名"
	default:
		return "连接地址中的 " + name
	}
}

func jsonEscape(s string) string {
	q := strconv.Quote(s)
	return q[1 : len(q)-1]
}

// fillWS replaces {{name}}. mode "url" query-escapes values; mode "json" escapes them for a JSON string.
func fillWS(tmpl string, vars map[string]string, mode string) (string, []string) {
	var missing []string
	out := wsPlaceholderRe.ReplaceAllStringFunc(tmpl, func(all string) string {
		n := wsPlaceholderRe.FindStringSubmatch(all)[1]
		v, ok := vars[n]
		if n != "command" && (!ok || strings.TrimSpace(v) == "") {
			missing = append(missing, n)
			return ""
		}
		if mode == "url" {
			return url.QueryEscape(v)
		}
		return jsonEscape(v)
	})
	return out, missing
}

func renderWS(m *Middleware, vars map[string]string) (string, []string, error) {
	raw, miss := fillWS(m.Config.URL, vars, "url")
	msgs := make([]string, 0, len(m.Config.WSMessages))
	for _, t := range m.Config.WSMessages {
		s, ms := fillWS(t, vars, "json")
		msgs = append(msgs, s)
		miss = append(miss, ms...)
	}
	if len(miss) > 0 {
		return "", nil, fmt.Errorf("请提供 %s", strings.Join(uniq(miss), "、"))
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "ws" && u.Scheme != "wss") {
		return "", nil, errors.New("WebSocket 地址不正确")
	}
	return u.String(), msgs, nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func tailCommand(file string, n int) (string, error) {
	file = strings.TrimSpace(file)
	if file == "" {
		return "", errors.New("请提供日志文件路径")
	}
	if strings.ContainsAny(file, "\n\r\x00") {
		return "", errors.New("文件路径不能换行")
	}
	if n < 1 {
		n = 1
	}
	if n > 2000 {
		n = 2000
	}
	return fmt.Sprintf("tail -n %d %s", n, shellQuote(file)), nil
}

func checkExecCommand(command string, allow []string) error {
	command = strings.TrimSpace(command)
	if command == "" {
		return errors.New("请提供要执行的命令")
	}
	if strings.ContainsAny(command, "\n\r\x00") {
		return errors.New("不支持多行命令")
	}
	if len(allow) == 0 {
		return nil
	}
	parts, err := splitUnquotedPipes(command)
	if err != nil {
		return err
	}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			return errors.New("管道两侧都要有命令")
		}
		if err := rejectShellMeta(part); err != nil {
			return err
		}
		fields, err := shellWords(part)
		if err != nil {
			return err
		}
		if len(fields) == 0 {
			return errors.New("管道两侧都要有命令")
		}
		tok := fields[0]
		ok := false
		for _, a := range allow {
			if tok == a {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("命令 %s 不在允许列表中（允许：%s）", tok, strings.Join(allow, "、"))
		}
		if err := checkCommandArgs(tok, fields[1:]); err != nil {
			return err
		}
	}
	return nil
}

// shellWords splits one pipeline stage on unquoted whitespace and drops the quotes.
func shellWords(s string) ([]string, error) {
	var words []string
	var b strings.Builder
	var quote byte
	flush := func() {
		words = append(words, b.String())
		b.Reset()
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
				continue
			}
			b.WriteByte(c)
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case ' ', '\t':
			if b.Len() > 0 {
				flush()
			}
		default:
			b.WriteByte(c)
		}
	}
	if quote != 0 {
		return nil, errors.New("引号未闭合")
	}
	if b.Len() > 0 {
		flush()
	}
	return words, nil
}

// checkCommandArgs applies the extra limits that a bare command name cannot express.
// find and cut can otherwise run -exec / field cuts; rg --pre runs another program.
func checkCommandArgs(cmd string, args []string) error {
	switch cmd {
	case "find":
		return checkFindArgs(args)
	case "cut":
		return checkCutArgs(args)
	case "rg":
		return checkRgArgs(args)
	default:
		return nil
	}
}

func checkFindArgs(args []string) error {
	takesValue := map[string]bool{
		"-name": true, "-mmin": true, "-mtime": true, "-type": true, "-size": true, "-maxdepth": true,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return nil
		}
		if strings.HasPrefix(a, "-") {
			if !takesValue[a] {
				return fmt.Errorf("find 只允许 -name、-mmin、-mtime、-type、-size、-maxdepth，不能使用 %s", a)
			}
			if i+1 >= len(args) {
				return fmt.Errorf("find %s 缺少参数", a)
			}
			i++ // value, including -mmin -30
		}
	}
	return nil
}

func checkCutArgs(args []string) error {
	saw := false
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			continue
		}
		if a == "-c" {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "-") {
				return errors.New("cut -c 需要字符范围，例如 1-200")
			}
			saw = true
			i++
			continue
		}
		if strings.HasPrefix(a, "-c") && len(a) > 2 {
			saw = true
			continue
		}
		if strings.HasPrefix(a, "-") {
			return fmt.Errorf("cut 只允许 -c，不能使用 %s", a)
		}
	}
	if !saw {
		return errors.New("cut 只允许 -c")
	}
	return nil
}

func checkRgArgs(args []string) error {
	takesValue := map[string]bool{
		"-e": true, "-g": true, "-f": true, "-m": true, "-A": true, "-B": true, "-C": true,
		"--regexp": true, "--glob": true, "--file": true, "--iglob": true,
		"--max-count": true, "--before-context": true, "--after-context": true, "--context": true,
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return nil
		}
		if a == "--pre" || strings.HasPrefix(a, "--pre=") || a == "--pre-glob" || strings.HasPrefix(a, "--pre-glob=") {
			return errors.New("rg 不能使用 --pre 或 --pre-glob")
		}
		if takesValue[a] {
			if i+1 >= len(args) {
				return fmt.Errorf("rg %s 缺少参数", a)
			}
			i++
		}
	}
	return nil
}

// splitUnquotedPipes splits a pipeline on | that is outside quotes. || is rejected.
func splitUnquotedPipes(command string) ([]string, error) {
	var parts []string
	var b strings.Builder
	var quote byte
	for i := 0; i < len(command); i++ {
		c := command[i]
		if quote != 0 {
			b.WriteByte(c)
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			b.WriteByte(c)
		case '|':
			if i+1 < len(command) && command[i+1] == '|' {
				return nil, errors.New("不支持 ||，管道请用单个 |")
			}
			parts = append(parts, b.String())
			b.Reset()
		default:
			b.WriteByte(c)
		}
	}
	if quote != 0 {
		return nil, errors.New("引号未闭合")
	}
	parts = append(parts, b.String())
	return parts, nil
}

// rejectShellMeta blocks the metacharacters that can skip the allowlist.
// A pipe has already been split off. Inside single quotes everything is literal;
// inside double quotes $ and backticks still run, so those stay forbidden.
func rejectShellMeta(part string) error {
	var quote byte
	for i := 0; i < len(part); i++ {
		c := part[i]
		if quote == '\'' {
			if c == '\'' {
				quote = 0
			}
			continue
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
				continue
			}
			if c == '$' || c == '`' {
				return errors.New("不能使用命令替换")
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case ';', '&', '<', '>', '`', '$':
			return errors.New("不能使用重定向、命令替换或用分号串联命令")
		}
	}
	return nil
}

func stripANSI(s string) string {
	return ansiRe.ReplaceAllString(s, "")
}

func wsAuthFailed(s string) bool {
	l := strings.ToLower(s)
	return strings.Contains(l, "auth.not.login") || strings.Contains(s, "未登录") || strings.Contains(s, "请先登录") || strings.Contains(l, "not logged in")
}

// isPromptFrame reports whether the last non-empty line looks like a shell prompt.
// When needle is set (the pod name), the frame must also contain it, so a log line
// that merely mentions the pod does not end the session.
func isPromptFrame(frame, needle string) bool {
	if needle != "" && !strings.Contains(frame, needle) {
		return false
	}
	s := strings.ReplaceAll(frame, "\r", "\n")
	lines := strings.Split(s, "\n")
	last := ""
	for i := len(lines) - 1; i >= 0; i-- {
		t := strings.TrimSpace(lines[i])
		if t != "" {
			last = t
			break
		}
	}
	if last == "" || len(last) > 180 {
		return false
	}
	switch last[len(last)-1] {
	case '#', '$', '>':
		return true
	default:
		return false
	}
}

// peelPrompt drops a trailing prompt line and returns the text before it.
func peelPrompt(frame, needle string) (string, bool) {
	if !isPromptFrame(frame, needle) {
		return frame, false
	}
	s := strings.ReplaceAll(frame, "\r", "\n")
	lines := strings.Split(s, "\n")
	i := len(lines) - 1
	for i >= 0 && strings.TrimSpace(lines[i]) == "" {
		i--
	}
	if i >= 0 {
		i--
	}
	for i >= 0 && strings.TrimSpace(lines[i]) == "" {
		i--
	}
	if i < 0 {
		return "", true
	}
	return strings.Join(lines[:i+1], "\n"), true
}

type wsFrame struct {
	text bool
	data string
}

func browserOrigin(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	switch strings.ToLower(u.Scheme) {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

func runWSSession(ctx context.Context, wsURL string, header http.Header, messages []string, promptNeedle string, maxBytes int) (string, bool, error) {
	if maxBytes <= 0 {
		maxBytes = 256 * 1024
	}
	d := websocket.Dialer{HandshakeTimeout: 10 * time.Second, Proxy: http.ProxyFromEnvironment}
	conn, resp, err := d.DialContext(ctx, wsURL, header)
	if err != nil {
		if resp != nil && (resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden) {
			return "", true, fmt.Errorf("WebSocket 握手被拒绝：HTTP %d", resp.StatusCode)
		}
		return "", false, err
	}
	defer conn.Close()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	frames := make(chan wsFrame, 32)
	readErr := make(chan error, 1)
	go func() {
		for {
			typ, b, err := conn.ReadMessage()
			if err != nil {
				readErr <- err
				return
			}
			frames <- wsFrame{text: typ == websocket.TextMessage, data: stripANSI(string(b))}
		}
	}()

	if auth, err := dropBanner(ctx, frames, readErr, time.Second, 250*time.Millisecond); auth || err != nil {
		return "", auth, err
	}
	drainPending(frames) // a banner frame can arrive in the gap before we send
	for _, m := range messages {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(m)); err != nil {
			return "", false, err
		}
	}
	return collectOutput(ctx, frames, readErr, promptNeedle, maxBytes)
}

func drainPending(frames <-chan wsFrame) {
	for {
		select {
		case <-frames:
		default:
			return
		}
	}
}

// dropBanner ignores what the terminal prints on connect (the first prompt), until the
// stream is quiet or max elapses.
func dropBanner(ctx context.Context, frames <-chan wsFrame, readErr <-chan error, max, quiet time.Duration) (bool, error) {
	timer := time.NewTimer(max)
	defer timer.Stop()
	var quietT *time.Timer
	var quietC <-chan time.Time
	stopQuiet := func() {
		if quietT == nil {
			return
		}
		if !quietT.Stop() {
			select {
			case <-quietT.C:
			default:
			}
		}
	}
	defer stopQuiet()
	for {
		select {
		case f := <-frames:
			if wsAuthFailed(f.data) {
				return true, errors.New("未登录")
			}
			if quietT == nil {
				quietT = time.NewTimer(quiet)
			} else {
				stopQuiet()
				quietT.Reset(quiet)
			}
			quietC = quietT.C
		case <-quietC:
			return false, nil
		case <-timer.C:
			return false, nil
		case err := <-readErr:
			return false, err
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
}

func collectOutput(ctx context.Context, frames <-chan wsFrame, readErr <-chan error, needle string, maxBytes int) (string, bool, error) {
	var b strings.Builder
	idle := time.NewTimer(1200 * time.Millisecond)
	idle.Stop()
	defer idle.Stop()
	var idleC <-chan time.Time
	got := false
	appendText := func(s string) (bool, error) {
		if s == "" {
			return false, nil
		}
		if b.Len() >= maxBytes {
			return true, nil
		}
		if b.Len()+len(s) > maxBytes {
			b.WriteString(s[:maxBytes-b.Len()])
			b.WriteString("\n（输出已截断）")
			return true, nil
		}
		b.WriteString(s)
		got = true
		return false, nil
	}
	// handle reports stop when the transcript is complete. auth is only set on stop.
	handle := func(f wsFrame) (stop, auth bool, err error) {
		if !got && wsAuthFailed(f.data) {
			return true, true, errors.New("未登录")
		}
		if body, prompt := peelPrompt(f.data, needle); prompt {
			if full, err := appendText(body); full || err != nil {
				return true, false, err
			}
			if b.Len() > 0 && !strings.HasSuffix(b.String(), "\n") {
				b.WriteByte('\n')
			}
			return true, false, nil
		}
		// Control text (JSON acks) is not part of the terminal transcript.
		if f.text {
			t := strings.TrimSpace(f.data)
			if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
				return false, false, nil
			}
		}
		full, err := appendText(f.data)
		if full || err != nil {
			return true, false, err
		}
		idle.Reset(1200 * time.Millisecond)
		idleC = idle.C
		return false, false, nil
	}
	// The reader sends readErr only after every successful frame is queued. select can
	// still observe the error first, so those frames have to be taken before returning.
	finish := func(err error) (string, bool, error) {
		for {
			select {
			case f := <-frames:
				stop, auth, herr := handle(f)
				if stop {
					if auth {
						return "", true, herr
					}
					return strings.TrimRight(b.String(), "\n"), false, herr
				}
			default:
				if got {
					return strings.TrimRight(b.String(), "\n"), false, nil
				}
				return "", false, err
			}
		}
	}
	for {
		select {
		case f := <-frames:
			stop, auth, err := handle(f)
			if stop {
				if auth {
					return "", true, err
				}
				return strings.TrimRight(b.String(), "\n"), false, err
			}
		case <-idleC:
			if got {
				return strings.TrimRight(b.String(), "\n"), false, nil
			}
			idleC = nil
		case err := <-readErr:
			return finish(err)
		case <-ctx.Done():
			if got {
				return strings.TrimRight(b.String(), "\n") + "\n（已超时，输出可能不完整）", false, nil
			}
			return "", false, errors.New("命令执行超时")
		}
	}
}

func wsVars(args map[string]any, command string) map[string]string {
	vars := map[string]string{"command": command}
	for k, v := range args {
		if k == "middleware" || k == "file" || k == "lines" || k == "timeout" || k == "command" {
			continue
		}
		s := strings.TrimSpace(argStr(args, k))
		if s == "" {
			if t, ok := v.(string); ok {
				s = strings.TrimSpace(t)
			}
		}
		if s != "" {
			vars[k] = s
		}
	}
	return vars
}

func (a *App) callWS(ctx context.Context, c *mwCall, args map[string]any) (string, bool) {
	if c.m.Config.isSQLConsole() {
		return c.blocked("该中间件是 SQL 控制台，请使用 ws_sql_query"), true
	}
	var command string
	var err error
	switch c.tool {
	case "pod_read_log":
		if msg, ok := c.need("log"); !ok {
			return msg, true
		}
		n := argInt(args, "lines", 100)
		command, err = tailCommand(argStr(args, "file"), n)
		c.action = command
		if command == "" {
			c.action = strings.TrimSpace(argStr(args, "file"))
		}
		if err != nil {
			return c.blocked(err.Error()), true
		}
	case "pod_exec":
		if msg, ok := c.need("exec"); !ok {
			return msg, true
		}
		command = strings.TrimSpace(argStr(args, "command"))
		c.action = command
		if err = checkExecCommand(command, c.m.Config.CommandAllow); err != nil {
			return c.blocked(err.Error()), true
		}
	default:
		return "未知工具", true
	}
	timeout := time.Duration(c.m.Config.timeoutSec()) * time.Second
	if t := argInt(args, "timeout", 0); t > 0 {
		if t > c.m.Config.timeoutSec() {
			t = c.m.Config.timeoutSec()
		}
		timeout = time.Duration(t) * time.Second
	}
	vars := wsVars(args, command)
	text, err := a.execWS(ctx, c.m, vars, timeout)
	return c.done(text, err)
}

func (a *App) execWS(ctx context.Context, m *Middleware, vars map[string]string, timeout time.Duration) (string, error) {
	attempt := func() (string, bool, error) {
		wsURL, msgs, err := renderWS(m, vars)
		if err != nil {
			return "", false, err
		}
		cookies, _ := a.CookiesFor(wsURL)
		hdr, _ := CookieHeader(cookies, wsURL)
		h := http.Header{}
		if hdr != "" {
			h.Set("Cookie", hdr)
		}
		cctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return runWSSession(cctx, wsURL, h, msgs, vars["pod_name"], m.Config.maxResultBytes())
	}
	out, auth, err := attempt()
	if !auth {
		return out, err
	}
	origin := browserOrigin(m.Config.URL)
	site := a.store.SiteByOrigin(origin)
	if site == nil {
		site = a.store.EnsureSite(origin + "/")
	}
	if site == nil {
		if err == nil {
			err = errors.New("未登录")
		}
		return "", err
	}
	if rerr := a.Relogin(site, a.siteGen(a.state(site.Origin)), false, true); rerr != nil {
		return "", rerr
	}
	out, _, err = attempt()
	return out, err
}

func (a *App) testWS(ctx context.Context, m *Middleware) (string, error) {
	if m.Config.isSQLConsole() {
		return a.testWSSQLConsole(ctx, m)
	}
	if strings.Contains(m.Config.URL, "{{") {
		dummy := map[string]string{}
		for _, n := range wsPlaceholders([]*Middleware{m}) {
			dummy[n] = "x"
		}
		dummy["command"] = "echo a2m-ok"
		if _, _, err := renderWS(m, dummy); err != nil {
			return "", err
		}
		return "地址格式正确。地址中的参数在调用 pod_read_log / pod_exec 时填入，测试连接未发起真实会话", nil
	}
	vars := map[string]string{"command": "echo a2m-ok"}
	cctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	out, auth, err := func() (string, bool, error) {
		wsURL, msgs, err := renderWS(m, vars)
		if err != nil {
			return "", false, err
		}
		cookies, _ := a.CookiesFor(wsURL)
		hdr, _ := CookieHeader(cookies, wsURL)
		h := http.Header{}
		if hdr != "" {
			h.Set("Cookie", hdr)
		}
		return runWSSession(cctx, wsURL, h, msgs, "", m.Config.maxResultBytes())
	}()
	if auth {
		return "", errors.New("未登录，请先在「登录中心」登录这个网站")
	}
	if err != nil {
		return "", err
	}
	out = strings.TrimSpace(out)
	if len([]rune(out)) > 80 {
		out = string([]rune(out)[:80]) + "…"
	}
	if out == "" {
		return "连接成功", nil
	}
	return "连接成功，输出：" + out, nil
}
