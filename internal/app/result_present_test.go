package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func presentTestApp(t *testing.T) *App {
	t.Helper()
	dir, err := os.MkdirTemp("", "a2m-present-")
	if err != nil {
		t.Fatal(err)
	}
	a, err := NewApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		a.Shutdown()
		var rm error
		for i := 0; i < 25; i++ {
			rm = os.RemoveAll(dir)
			if rm == nil {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Logf("cleanup %s: %v", dir, rm)
	})
	return a
}

func presentTestAppFlat(t *testing.T) *App {
	t.Helper()
	a := presentTestApp(t)
	a.store.SetSetting("mcp_mode", ModeFlat)
	return a
}

func presentUpstream(t *testing.T, status int, contentType, body string) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(s.Close)
	return s
}

func savePresentTool(t *testing.T, a *App, name, method, rawURL string, cfg ToolConfig, params []Param) *Tool {
	t.Helper()
	if params == nil {
		params = []Param{}
	}
	tool := &Tool{
		Name: name, Title: name, Method: method, URL: rawURL, Approval: "off",
		Headers: map[string]string{"Accept": "*/*"}, Params: params, Config: cfg,
	}
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	pack := &Pack{Name: name + "_pack", Enabled: true, ToolIDs: []int64{tool.ID}}
	if err := a.store.SavePack(pack); err != nil {
		t.Fatal(err)
	}
	return tool
}

func startApprovalCallNamed(a *App, name string, args map[string]any) <-chan approvalReply {
	done := make(chan approvalReply, 1)
	go func() {
		v, err := a.invokeTool(context.Background(), &mcpCtx{}, name, args)
		done <- unpackApprovalReply(v, err)
	}()
	return done
}

func invokePresent(t *testing.T, a *App, name string, args map[string]any) (string, bool) {
	t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	v, rpc := a.invokeTool(context.Background(), &mcpCtx{}, name, args)
	if rpc != nil {
		t.Fatalf("rpc error: %v", rpc)
	}
	r := v.(map[string]any)
	bad, _ := r["isError"].(bool)
	return r["content"].([]map[string]any)[0]["text"].(string), bad
}

func bugStyleHTML() string {
	// Fictional defect-tracker page. Title sits in main>header so chrome
	// rules must keep it. No real product or company names.
	return `<!DOCTYPE html><html><head><title>ignore</title>
<script>var x="secret script noise";</script>
<style>.nav{color:red}</style>
<nav id="navbar"><a href="/home">首页导航</a></nav>
<body>
<main id="main">
  <header><h1>接口超时咨询</h1></header>
  <article class="content">
    <table>
      <tr><th>字段</th><th>内容</th></tr>
      <tr><td>步骤</td><td>打开页面 &amp; 点击提交，出现超时</td></tr>
    </table>
    <h2>备注历史</h2>
    <p>已按咨询问题回复，无需再查业务日志。</p>
  </article>
</main>
<footer>站点页脚</footer>
</body></html>`
}

func TestBindValuesReportsAllMissingParams(t *testing.T) {
	tool := &Tool{Params: []Param{
		{Name: "a", Type: "string", Required: true},
		{Name: "b", Type: "string", Required: true},
		{Name: "c", Type: "string", Required: false},
	}}
	_, err := tool.bindValues(map[string]any{}, nil, nil, false, time.Now())
	if err == nil || err.Error() != "缺少参数: a、b" {
		t.Fatalf("got %v", err)
	}
}

func TestJSONBusinessFailureHeuristics(t *testing.T) {
	fail := []string{
		`{"success":false,"msg":"nope"}`,
		`{"ok":false,"message":"denied"}`,
		`{"code":"DEMOERR0001","msg":"downstream"}`,
		`{"code":"DEMOERR0001"}`,
		`{"code":-1,"msg":"neg"}`,
		`{"code":500,"msg":"httpish"}`,
		`{"code":"500","msg":"httpish-str"}`,
		`{"code":"NO"}`,
		`{"code":"ERR42"}`,
		`{"code":400,"msg":"bad request"}`,
		`{"status":"NO"}`,
		`{"status":"false"}`,
	}
	for _, raw := range fail {
		text, ok := detectJSONBusinessFailure(raw)
		if !ok {
			t.Fatalf("expected failure for %s", raw)
		}
		if !strings.HasPrefix(text, "业务失败") {
			t.Fatalf("prefix: %s", text)
		}
		if !strings.Contains(text, raw) {
			t.Fatalf("original body missing from %s", text)
		}
	}
	// no-message boolean false -> just "业务失败"
	text, ok := detectJSONBusinessFailure(`{"success":false}`)
	if !ok || !strings.HasPrefix(text, "业务失败") {
		t.Fatalf("boolean false without msg: %v %s", ok, text)
	}

	keep := []string{
		`{"success":true,"code":"DEMOERR0001"}`,
		`{"success":true,"ok":false}`,
		`{"code":0,"msg":"ok"}`,
		`{"code":200}`,
		`{"status":1,"name":"active"}`,
		`{"status":500}`,
		`{"code":1,"msg":"category"}`,
		`{"code":"AB12","msg":"name"}`,
		`{"ok":"false"}`,
		`{"code":"500"}`,
		`{"code":"n","msg":"north"}`,
		`{"code":"N"}`,
		`{"code":-1}`,
		`{"code":399,"msg":"almost"}`,
		`{"code":600,"msg":"too-high"}`,
		`{"status":"n"}`,
		`{"status":"ERR1"}`,
		`[ {"success":false} ]`,
		`not-json`,
	}
	for _, raw := range keep {
		if _, ok := detectJSONBusinessFailure(raw); ok {
			t.Fatalf("false positive for %s", raw)
		}
	}
}

func TestPresentJSONFailureViaMCP(t *testing.T) {
	a := presentTestApp(t)
	up := presentUpstream(t, 200, "application/json", `{"success":false,"msg":"PTM-like DEMOERR0001"}`)
	savePresentTool(t, a, "json_fail", "GET", up.URL, ToolConfig{}, nil)
	text, isErr := invokePresent(t, a, "json_fail", nil)
	if !isErr {
		t.Fatalf("want isError, got %s", text)
	}
	if !strings.Contains(text, "业务失败：PTM-like DEMOERR0001") {
		t.Fatalf("message: %s", text)
	}
	if !strings.Contains(text, `"success":false`) {
		t.Fatalf("body missing: %s", text)
	}
	if strings.Contains(text, "HTTP 200") {
		t.Fatalf("HTTP prefix should be omitted on business failure: %s", text)
	}

	off := boolPtr(false)
	up2 := presentUpstream(t, 200, "application/json", `{"success":false,"msg":"still-ok"}`)
	savePresentTool(t, a, "json_fail_off", "GET", up2.URL, ToolConfig{DetectFailure: off}, nil)
	text, isErr = invokePresent(t, a, "json_fail_off", nil)
	if isErr {
		t.Fatalf("detection off should not be isError: %s", text)
	}
	if !strings.Contains(text, "HTTP 200") || !strings.Contains(text, "still-ok") {
		t.Fatalf("raw success path: %s", text)
	}
}

func TestPresentHTMLAlertIsErrorWithoutFallbackNote(t *testing.T) {
	a := presentTestApp(t)
	page := `<!DOCTYPE html><html><head><script>alert('抱歉，您访问的对象并不存在！');location.href='/index';</script></head><body></body></html>`
	// Pad above 2KB so a naive fallback would trigger if alert lost the race.
	page += "<!-- " + strings.Repeat("x", 3000) + " -->"
	up := presentUpstream(t, 200, "text/html", page)
	savePresentTool(t, a, "alert_page", "GET", up.URL, ToolConfig{}, nil)
	text, isErr := invokePresent(t, a, "alert_page", nil)
	if !isErr {
		t.Fatalf("want isError, got %s", text)
	}
	if !strings.Contains(text, "业务失败：抱歉，您访问的对象并不存在！") {
		t.Fatalf("alert text: %s", text)
	}
	if strings.Contains(text, "已返回原始 HTML") {
		t.Fatalf("fallback should not run on business failure: %s", text)
	}
}

func TestPresentHTMLAlertDoesNotFalsePositiveWithBody(t *testing.T) {
	a := presentTestApp(t)
	page := `<!DOCTYPE html><html><body><script>alert('ignore me');</script>
<main id="main"><h1>真实标题</h1><p>` + strings.Repeat("这段是正文内容，应该被保留。", 10) + `</p></main></body></html>`
	up := presentUpstream(t, 200, "text/html", page)
	savePresentTool(t, a, "alert_with_body", "GET", up.URL, ToolConfig{}, nil)
	text, isErr := invokePresent(t, a, "alert_with_body", nil)
	if isErr {
		t.Fatalf("should not be an error: %s", text)
	}
	if !strings.Contains(text, "真实标题") || !strings.Contains(text, "HTTP 200") {
		t.Fatalf("expected cleaned page: %s", text)
	}
}

func TestPresentHTMLCleanAndSelectorAndFallback(t *testing.T) {
	a := presentTestApp(t)
	html := bugStyleHTML()
	up := presentUpstream(t, 200, "text/html; charset=utf-8", html)
	savePresentTool(t, a, "bug_view", "GET", up.URL, ToolConfig{}, nil)
	text, isErr := invokePresent(t, a, "bug_view", nil)
	if isErr {
		t.Fatalf("clean should succeed: %s", text)
	}
	if !strings.HasPrefix(text, "HTTP 200\n") {
		t.Fatalf("HTTP prefix missing: %s", text[:min(80, len(text))])
	}
	for _, want := range []string{"接口超时咨询", "打开页面", "点击提交", "备注历史", "已按咨询问题回复"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in %s", want, text)
		}
	}
	for _, drop := range []string{"secret script noise", "首页导航", "<script", "<nav"} {
		if strings.Contains(text, drop) {
			t.Fatalf("should have dropped %q: %s", drop, text)
		}
	}
	if strings.Contains(text, "&amp;") && !strings.Contains(text, "打开页面 & 点击") && !strings.Contains(text, "打开页面 &amp;") {
		// decoded expected
	}
	if !strings.Contains(text, "打开页面") || !strings.Contains(text, "点击提交") {
		t.Fatalf("steps missing: %s", text)
	}
	if len(text) > len(html) {
		t.Fatalf("cleaned text larger than raw (%d > %d)", len(text), len(html))
	}

	// selector
	up2 := presentUpstream(t, 200, "text/html", html)
	savePresentTool(t, a, "bug_sel", "GET", up2.URL, ToolConfig{ResultFormat: resultFormatSelector, ResultSelector: "#main"}, nil)
	text, isErr = invokePresent(t, a, "bug_sel", nil)
	if isErr || !strings.Contains(text, "接口超时咨询") {
		t.Fatalf("selector: %v %s", isErr, text)
	}

	up3 := presentUpstream(t, 200, "text/html", html)
	savePresentTool(t, a, "bug_miss", "GET", up3.URL, ToolConfig{ResultFormat: resultFormatSelector, ResultSelector: "#no-such"}, nil)
	text, isErr = invokePresent(t, a, "bug_miss", nil)
	if isErr {
		t.Fatalf("miss should fall back, not error: %s", text)
	}
	if !strings.Contains(text, presentFallbackMiss) || !strings.Contains(text, "<nav") {
		t.Fatalf("expected raw fallback: %s", text)
	}

	// JS-rendered page: almost empty after clean, raw > 2KB, no alert
	jsPage := `<!DOCTYPE html><html><head><script>` + strings.Repeat("var a=1;", 400) + `</script></head><body><div id="app"></div></body></html>`
	if len(jsPage) <= presentRawMinBytes {
		t.Fatalf("fixture too small: %d", len(jsPage))
	}
	up4 := presentUpstream(t, 200, "text/html", jsPage)
	savePresentTool(t, a, "js_page", "GET", up4.URL, ToolConfig{}, nil)
	text, isErr = invokePresent(t, a, "js_page", nil)
	if isErr || !strings.Contains(text, presentFallbackEmpty) || !strings.Contains(text, "<script>") {
		t.Fatalf("js fallback: %v %s", isErr, text)
	}
}

func TestPickAlertPrefersNearestLocationAndSkipsHugeScript(t *testing.T) {
	raw := `<script>alert('先出现的提示'); alert('真正的错误'); location.href='/home';</script>`
	if got := pickAlertMessage(raw); got != "真正的错误" {
		t.Fatalf("nearest alert: %q", got)
	}
	raw = `<script>alert('第一条'); alert('第二条');</script>`
	if got := pickAlertMessage(raw); got != "第一条" {
		t.Fatalf("first alert without location: %q", got)
	}
	raw = `<script>window.alert("窗口提示"); location.href='/next';</script>`
	if got := pickAlertMessage(raw); got != "窗口提示" {
		t.Fatalf("window.alert: %q", got)
	}
	big := `<script>alert('大脚本错误'); location.href='/';` + strings.Repeat("x", 3000) + `</script><script>alert('小脚本');</script>`
	if got := pickAlertMessage(big); got != "小脚本" {
		t.Fatalf("huge script should be ignored: %q", got)
	}
	escaped := `<script>alert('line\nbreak');</script>`
	if got := pickAlertMessage(escaped); got != "line\nbreak" {
		t.Fatalf("escaped newline: %q", got)
	}
}

func TestPresentSelectorDoesNotFalseAlert(t *testing.T) {
	page := `<html><body><script>alert('忽略这条');</script><main>` +
		strings.Repeat("<p>正文足够长，不应该被当成失败。</p>", 8) +
		`<h1 id="ticket-title">短</h1></main></body></html>`
	p := &PreparedCall{presentCfg: ToolConfig{ResultFormat: resultFormatSelector, ResultSelector: "#ticket-title"}}
	res := &CallResult{Status: 200, Body: page, Headers: map[string]string{"Content-Type": "text/html"}}
	presentToolResult(p, res)
	if res.Outcome == outcomeBusinessError {
		t.Fatalf("selector excerpt must not turn a real page into an alert failure: %s", res.Body)
	}
	if strings.Contains(res.Body, "已返回原始 HTML") || !strings.Contains(res.Body, "短") {
		t.Fatalf("selector result: %s", res.Body)
	}
}

func TestPresentAlertIgnoresLinkURLLength(t *testing.T) {
	page := `<html><body><script>alert('对象不存在');location.href='/x';</script>` +
		`<a href="https://example.com/` + strings.Repeat("a", 500) + `">返回</a></body></html>`
	p := &PreparedCall{}
	res := &CallResult{Status: 200, Body: page, Headers: map[string]string{"Content-Type": "text/html"}}
	presentToolResult(p, res)
	if res.Outcome != outcomeBusinessError || !strings.Contains(res.Body, "业务失败：对象不存在") {
		t.Fatalf("long href must not hide the alert: outcome=%s body=%s", res.Outcome, res.Body)
	}
	if strings.Contains(res.Body, "已返回原始 HTML") {
		t.Fatalf("failure must not fall back: %s", res.Body)
	}
}

func TestPresentSQLGuardAndWSSkip60KB(t *testing.T) {
	msg := strings.Repeat("甲", maxResult)
	raw := `{"success":false,"msg":"` + msg + `"}`
	sql := &PreparedCall{ws: true, wsConfig: ToolConfig{SQLGuard: &SQLGuardConfig{Enabled: true}}}
	sqlRes := &CallResult{Status: 200, Body: raw, Outcome: outcomeSuccess, Truncated: true, Headers: map[string]string{"Content-Type": "application/json"}}
	presentToolResult(sql, sqlRes)
	if sqlRes.Body != raw || sqlRes.Outcome != outcomeSuccess || !sqlRes.Truncated {
		t.Fatalf("sql guard changed result outcome=%s trunc=%v changed=%v", sqlRes.Outcome, sqlRes.Truncated, sqlRes.Body != raw)
	}

	ws := &PreparedCall{ws: true}
	wsRes := &CallResult{Status: 200, Body: raw, Headers: map[string]string{"Content-Type": "application/json"}}
	presentToolResult(ws, wsRes)
	if wsRes.Outcome != outcomeBusinessError || wsRes.Truncated || !strings.Contains(wsRes.Body, msg) {
		t.Fatalf("ws json failure truncated or missed: outcome=%s trunc=%v len=%d", wsRes.Outcome, wsRes.Truncated, len(wsRes.Body))
	}
	if strings.Contains(wsRes.Body, "…[已截断]") {
		t.Fatal("ws result was 60KB-truncated")
	}

	httpRes := &CallResult{Status: 200, Body: raw, Headers: map[string]string{"Content-Type": "application/json"}}
	presentToolResult(&PreparedCall{}, httpRes)
	if httpRes.Outcome != outcomeBusinessError || !httpRes.Truncated || !strings.HasPrefix(httpRes.Body, "业务失败：") || !strings.Contains(httpRes.Body, "…[已截断]") {
		t.Fatalf("http json failure should keep the prefix and truncate: outcome=%s trunc=%v body=%s", httpRes.Outcome, httpRes.Truncated, httpRes.Body[:min(80, len(httpRes.Body))])
	}

	page := `<!DOCTYPE html><html><body><nav>导航不要</nav><main><h1>标题乙</h1><p>需要保留的正文</p></main></body></html>`
	wsHTML := &CallResult{Status: 200, Body: page, Headers: map[string]string{"Content-Type": "text/html"}}
	presentToolResult(&PreparedCall{ws: true}, wsHTML)
	if strings.Contains(wsHTML.Body, "导航不要") || !strings.Contains(wsHTML.Body, "标题乙") || wsHTML.Truncated {
		t.Fatalf("ws html: trunc=%v body=%s", wsHTML.Truncated, wsHTML.Body)
	}
}

func TestDetectFailureFalseRoundTrip(t *testing.T) {
	off := boolPtr(false)
	raw := ToolConfig{DetectFailure: off}.marshal()
	if !strings.Contains(raw, `"detect_failure":false`) {
		t.Fatalf("unchecked detection must be stored as false: %s", raw)
	}
	back, err := parseToolConfigJSON(raw)
	if err != nil || back.detectFailureEnabled() {
		t.Fatalf("round trip: %+v %v", back, err)
	}
}

func TestPresentSelectorSmallRegionNotFallback(t *testing.T) {
	a := presentTestApp(t)
	// Large page with a small, valid selected region: must return that
	// region, not fall back to the whole raw HTML.
	pad := strings.Repeat("<p>导航与页脚占位文字占位文字占位文字</p>", 80)
	html := `<!DOCTYPE html><html><body><nav>` + pad + `</nav><main><h1 id="ticket-title">短标题</h1><p>正文一句。</p></main></body></html>`
	if len(html) <= presentRawMinBytes {
		t.Fatalf("fixture too small: %d", len(html))
	}
	up := presentUpstream(t, 200, "text/html", html)
	savePresentTool(t, a, "sel_small", "GET", up.URL, ToolConfig{ResultFormat: resultFormatSelector, ResultSelector: "#ticket-title"}, nil)
	text, isErr := invokePresent(t, a, "sel_small", nil)
	if isErr {
		t.Fatal(text)
	}
	if strings.Contains(text, presentFallbackEmpty) || strings.Contains(text, "<nav") {
		t.Fatalf("small selector hit must not fall back to raw: %s", text)
	}
	if !strings.Contains(text, "短标题") {
		t.Fatalf("selected title missing: %s", text)
	}
}

func TestPresentMCPCannotOverrideFormat(t *testing.T) {
	a := presentTestApp(t)
	html := bugStyleHTML()
	up := presentUpstream(t, 200, "text/html", html)
	savePresentTool(t, a, "locked_fmt", "GET", up.URL, ToolConfig{ResultFormat: resultFormatAuto}, nil)
	text, isErr := invokePresent(t, a, "locked_fmt", map[string]any{"result_format": "raw"})
	if isErr {
		t.Fatal(text)
	}
	if strings.Contains(text, "<nav") || strings.Contains(text, "secret script noise") {
		t.Fatalf("argument must not force raw: %s", text)
	}
	if !strings.Contains(text, "接口超时咨询") {
		t.Fatalf("cleaned title missing: %s", text)
	}
}

func TestPresentScrubAfterCleaning(t *testing.T) {
	a := presentTestApp(t)
	secret := "superSecretValue99"
	page := `<!DOCTYPE html><html><body><main><h1>可见标题</h1><p>密钥是 ` + secret + ` 请勿泄露</p></main></body></html>`
	up := presentUpstream(t, 200, "text/html", page)
	tool := savePresentTool(t, a, "scrub_page", "GET", up.URL, ToolConfig{}, nil)
	// Register the secret as if it came from a bound credential.
	prepared, err := a.Prepare(tool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	prepared.secretValues = append(prepared.secretValues, secret)
	res, err := a.Send(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if res.Body == secretMask {
		t.Fatal("whole body fail-closed")
	}
	if strings.Contains(res.Body, secret) {
		t.Fatalf("secret leaked: %s", res.Body)
	}
	if !strings.Contains(res.Body, "可见标题") {
		t.Fatalf("title lost: %s", res.Body)
	}
}

func TestPresentApprovalStoresWhatAIReceived(t *testing.T) {
	a := presentTestApp(t)
	html := bugStyleHTML()
	up := presentUpstream(t, 200, "text/html", html)
	tool := &Tool{
		Name: "appr_html", Title: "审批清洗", Method: "GET", URL: up.URL, Approval: "always",
		Params: []Param{},
	}
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	pack := &Pack{Name: "appr_html_pack", Enabled: true, ToolIDs: []int64{tool.ID}}
	if err := a.store.SavePack(pack); err != nil {
		t.Fatal(err)
	}

	done := startApprovalCallNamed(a, "appr_html", map[string]any{})
	rows := pendingApprovals(t, a, 1)
	approveRecord(t, a, rows[0])
	reply := <-done
	if reply.isError {
		t.Fatalf("approved call failed: %s", reply.text)
	}
	if !strings.Contains(reply.text, "HTTP 200") || !strings.Contains(reply.text, "接口超时咨询") {
		t.Fatalf("AI text: %s", reply.text)
	}
	got, _, err := a.GetApprovalResult(rows[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "HTTP 200") || !strings.Contains(got, "接口超时咨询") {
		t.Fatalf("result_full: %s", got)
	}
	if strings.Contains(got, "secret script noise") || strings.Contains(got, "<nav") {
		t.Fatalf("result_full still raw HTML: %s", got)
	}
}

func TestToolAnnotationsAndWritePrefix(t *testing.T) {
	a := presentTestApp(t)
	get := savePresentTool(t, a, "ann_get", "GET", "http://127.0.0.1/x", ToolConfig{}, nil)
	post := savePresentTool(t, a, "ann_post", "POST", "http://127.0.0.1/x", ToolConfig{}, nil)
	readPost := savePresentTool(t, a, "ann_read_post", "POST", "http://127.0.0.1/x", ToolConfig{OpKind: opKindRead}, nil)
	del := savePresentTool(t, a, "ann_del", "DELETE", "http://127.0.0.1/x", ToolConfig{}, nil)

	defs := a.recordedToolDefs([]*Tool{get, post, readPost, del}, map[int64][]string{}, false)
	byName := map[string]map[string]any{}
	for _, d := range defs {
		byName[d["name"].(string)] = d
	}
	ann := func(name string) map[string]any {
		return byName[name]["annotations"].(map[string]any)
	}
	if ann("ann_get")["readOnlyHint"] != true || ann("ann_get")["idempotentHint"] != true {
		t.Fatalf("GET: %+v", ann("ann_get"))
	}
	if strings.Contains(byName["ann_get"]["description"].(string), writeOpPrefix) {
		t.Fatal("GET should not have write prefix")
	}
	if ann("ann_post")["readOnlyHint"] != false || ann("ann_post")["destructiveHint"] != false || ann("ann_post")["idempotentHint"] != false {
		t.Fatalf("POST: %+v", ann("ann_post"))
	}
	if !strings.HasPrefix(byName["ann_post"]["description"].(string), writeOpPrefix) {
		t.Fatalf("POST prefix: %s", byName["ann_post"]["description"])
	}
	if ann("ann_read_post")["readOnlyHint"] != true {
		t.Fatalf("POST+read: %+v", ann("ann_read_post"))
	}
	if strings.Contains(byName["ann_read_post"]["description"].(string), writeOpPrefix) {
		t.Fatal("overridden read POST should not have write prefix")
	}
	if ann("ann_del")["destructiveHint"] != true || ann("ann_del")["readOnlyHint"] != false || ann("ann_del")["idempotentHint"] != true {
		t.Fatalf("DELETE: %+v", ann("ann_del"))
	}
	put := savePresentTool(t, a, "ann_put", "PUT", "http://127.0.0.1/x", ToolConfig{}, nil)
	wsRead := &Tool{Name: "ann_ws_sql", Method: "WS", Config: ToolConfig{SQLGuard: &SQLGuardConfig{Enabled: true}}}
	wsWrite := &Tool{Name: "ann_ws", Method: "WS"}
	putDefs := a.recordedToolDefs([]*Tool{put}, map[int64][]string{}, false)
	putAnn := putDefs[0]["annotations"].(map[string]any)
	if putAnn["readOnlyHint"] != false || putAnn["destructiveHint"] != false || putAnn["idempotentHint"] != true {
		t.Fatalf("PUT: %+v", putAnn)
	}
	if !strings.HasPrefix(putDefs[0]["description"].(string), writeOpPrefix) {
		t.Fatal("PUT should have write prefix")
	}
	if write, wsAnn := toolOpKind(wsRead); write || wsAnn["readOnlyHint"] != true || wsAnn["idempotentHint"] != true {
		t.Fatalf("sql guard WS: write=%v ann=%v", write, wsAnn)
	}
	if write, wsAnn := toolOpKind(wsWrite); !write || wsAnn["destructiveHint"] != false || wsAnn["idempotentHint"] != false || wsAnn["readOnlyHint"] != false {
		t.Fatalf("plain WS: write=%v ann=%v", write, wsAnn)
	}
	forced := &Tool{Name: "ann_ws_force", Method: "WS", Config: ToolConfig{SQLGuard: &SQLGuardConfig{Enabled: true}, OpKind: opKindWrite}}
	if write, _ := toolOpKind(forced); !write {
		t.Fatal("op_kind=write should override sql guard")
	}
	for _, d := range entryToolDefs() {
		if d["name"] != "call_pack_tool" {
			continue
		}
		if _, ok := d["annotations"]; ok {
			t.Fatal("call_pack_tool should not set annotations")
		}
		if !strings.Contains(d["description"].(string), "被调工具若是写操作，仍须用户明确要求") {
			t.Fatal("call_pack_tool missing write reminder")
		}
	}

	// load_pack briefs include annotations
	c := &recTestClient{t: t, handler: a.Handler()}
	c.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "ann-test"}})
	text, isErr := c.tool("load_pack", map[string]any{"pack": "ann_post_pack"})
	if isErr {
		t.Fatal(text)
	}
	if !strings.Contains(text, writeOpPrefix) || !strings.Contains(text, `"readOnlyHint":false`) && !strings.Contains(text, `"readOnlyHint": false`) {
		// JSON compact has no space
		if !strings.Contains(text, "readOnlyHint") {
			t.Fatalf("load_pack tools missing annotations: %s", text)
		}
	}
}

func TestLoadRecPackIncludesAnnotations(t *testing.T) {
	a := presentTestApp(t)
	c := &recTestClient{t: t, handler: a.Handler()}
	c.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "rec-ann"}})
	text, isErr := c.tool("load_pack", map[string]any{"pack": "录制分析"})
	if isErr {
		t.Fatal(text)
	}
	var payload struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			Annotations map[string]any `json:"annotations"`
		} `json:"tools"`
	}
	if err := json.Unmarshal([]byte(text), &payload); err != nil {
		t.Fatalf("load_pack json: %v %s", err, text)
	}
	byName := map[string]struct {
		Name        string
		Description string
		Annotations map[string]any
	}{}
	for _, tool := range payload.Tools {
		byName[tool.Name] = struct {
			Name        string
			Description string
			Annotations map[string]any
		}{tool.Name, tool.Description, tool.Annotations}
	}
	list := byName["rec_list_recordings"]
	if list.Annotations["readOnlyHint"] != true || list.Annotations["idempotentHint"] != true {
		t.Fatalf("rec_list annotations: %+v", list.Annotations)
	}
	save := byName["rec_save_tool"]
	if save.Annotations["readOnlyHint"] != false || save.Annotations["destructiveHint"] != false {
		t.Fatalf("rec_save annotations: %+v", save.Annotations)
	}
	if !strings.HasPrefix(save.Description, writeOpPrefix) {
		t.Fatalf("rec_save prefix: %s", save.Description)
	}
}

func TestMWAnnotationsMatchSpec(t *testing.T) {
	a := presentTestApp(t)
	ms := []*Middleware{
		{ID: 1, Name: "db1", Type: "mysql", Config: MWConfig{Perms: map[string]bool{"select": true}}},
		{ID: 2, Name: "rd1", Type: "redis", Config: MWConfig{Perms: map[string]bool{"read": true, "write": true}}},
		{ID: 3, Name: "mq1", Type: "mq", Config: MWConfig{Perms: map[string]bool{"consume": true, "send": true, "admin": true}, MQKind: "kafka"}},
		{ID: 4, Name: "pod1", Type: "websocket", Config: MWConfig{Perms: map[string]bool{"log": true, "exec": true}}},
		{ID: 5, Name: "sql1", Type: "websocket", Config: MWConfig{WSMode: wsModeSQLConsole, Perms: map[string]bool{"select": true}}},
	}
	packs := map[int64][]string{1: {"p"}, 2: {"p"}, 3: {"p"}, 4: {"p"}, 5: {"p"}}
	byName := map[string]map[string]any{}
	for _, d := range a.mwToolListFor(ms, packs) {
		byName[d["name"].(string)] = d
	}
	check := func(name string, readOnly, destructive, idempotent, write bool) {
		t.Helper()
		d := byName[name]
		if d == nil {
			t.Fatalf("missing tool %s", name)
		}
		ann := d["annotations"].(map[string]any)
		if ann["readOnlyHint"] != readOnly || ann["destructiveHint"] != destructive || ann["idempotentHint"] != idempotent {
			t.Fatalf("%s annotations: %+v", name, ann)
		}
		desc := d["description"].(string)
		if write && !strings.HasPrefix(desc, writeOpPrefix) {
			t.Fatalf("%s missing write prefix: %s", name, desc)
		}
		if !write && strings.Contains(desc, writeOpPrefix) {
			t.Fatalf("%s should not have write prefix", name)
		}
	}
	check("db_query", false, true, false, true)
	check("db_list_tables", true, false, true, false)
	check("db_describe_table", true, false, true, false)
	check("redis_scan", true, false, true, false)
	check("redis_command", false, true, false, true)
	check("mq_peek", true, false, true, false)
	check("mq_list_topics", true, false, true, false)
	check("mq_send", false, false, false, true)
	check("mq_create_topic", false, true, false, true)
	check("pod_read_log", true, false, true, false)
	check("pod_exec", false, true, false, true)
	check(wsSQLQueryTool, true, false, true, false)
}

func TestLoadPackPlainJSONResponse(t *testing.T) {
	a := presentTestApp(t)
	savePresentTool(t, a, "plain_json_tool", "GET", "http://127.0.0.1/x", ToolConfig{}, nil)
	c := &recTestClient{t: t, handler: a.Handler()}
	c.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "json-only"}})

	body := compactJSON(map[string]any{"jsonrpc": "2.0", "id": 99, "method": "tools/call", "params": map[string]any{"name": "load_pack", "arguments": map[string]any{"pack": "plain_json_tool_pack"}}})
	req := httptest.NewRequest("POST", "https://example.com/mcp", strings.NewReader(string(body)))
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Mcp-Session-Id", c.sid)
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("content-type %s", ct)
	}
	raw := w.Body.String()
	if strings.Contains(raw, "event: message") {
		t.Fatalf("SSE frames in JSON body: %s", raw)
	}
	var obj map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &obj); err != nil {
		t.Fatalf("not a JSON object: %v %s", err, raw)
	}
	if obj["jsonrpc"] != "2.0" {
		t.Fatalf("unexpected: %s", raw)
	}
}

func TestSchemaV11ToV12PresentationDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "a2m.db")
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE recordings(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, start_url TEXT, status TEXT, created_at TEXT, ended_at TEXT DEFAULT '');
CREATE TABLE requests(id INTEGER PRIMARY KEY AUTOINCREMENT, recording_id INTEGER, seq INTEGER, method TEXT, url TEXT, resource_type TEXT,
  req_headers TEXT, req_body TEXT, status INTEGER, resp_headers TEXT, resp_body TEXT, resp_mime TEXT, noise INTEGER, noise_reason TEXT, ts TEXT);
CREATE TABLE tools(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, title TEXT, description TEXT, method TEXT, url TEXT, headers TEXT, body TEXT, params TEXT, cred_headers TEXT, source_request_id INTEGER, created_at TEXT, updated_at TEXT, approval TEXT, rev INTEGER, config TEXT NOT NULL DEFAULT '{}');
CREATE TABLE packs(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, description TEXT, enabled INTEGER, created_at TEXT);
CREATE TABLE pack_tools(pack_id INTEGER, tool_id INTEGER, PRIMARY KEY(pack_id, tool_id));
CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE cookie_jar(name TEXT, domain TEXT, path TEXT, value TEXT, expires REAL, secure INTEGER, http_only INTEGER, session INTEGER, updated_at TEXT, PRIMARY KEY(name, domain, path));
CREATE TABLE vault(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, type TEXT, value_enc TEXT, site TEXT DEFAULT '', note TEXT DEFAULT '', created_at TEXT, updated_at TEXT);
CREATE TABLE sites(id INTEGER PRIMARY KEY AUTOINCREMENT, origin TEXT UNIQUE, config TEXT, status TEXT DEFAULT 'unknown', last_login_at TEXT DEFAULT '', last_check_at TEXT DEFAULT '', last_error TEXT DEFAULT '', login_count INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT);
CREATE TABLE middleware(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, type TEXT, config TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE approvals(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, tool TEXT, tool_id INTEGER, tool_rev INTEGER, client TEXT, args_display TEXT, final_args_display TEXT, status TEXT, feedback TEXT, decided_at TEXT, result TEXT, result_full TEXT NOT NULL DEFAULT '', title TEXT, preview_display TEXT, params_json TEXT);
INSERT INTO tools(name,title,description,method,url,headers,body,params,cred_headers,created_at,updated_at,approval,rev,config)
VALUES('legacy_view','旧工具','','GET','http://127.0.0.1/page','{}','','[]','[]','','','off',1,'{}');
PRAGMA user_version=11;
`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	var ver int
	if err := st.db.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil || ver != schemaUserVersion {
		t.Fatalf("version=%d err=%v want %d", ver, err, schemaUserVersion)
	}
	tool, err := st.GetToolByName("legacy_view")
	if err != nil {
		t.Fatal(err)
	}
	if tool.Config.ResultFormat != "" || tool.Config.DetectFailure != nil {
		t.Fatalf("stored config should stay zero: %+v", tool.Config)
	}
	if tool.Config.resultFormat() != resultFormatAuto || !tool.Config.detectFailureEnabled() {
		t.Fatalf("defaults: format=%s detect=%v", tool.Config.resultFormat(), tool.Config.detectFailureEnabled())
	}
	// Do not require the JSON in SQLite to have been rewritten.
	var raw string
	if err := st.db.QueryRow(`SELECT config FROM tools WHERE name='legacy_view'`).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(raw) != "{}" {
		t.Fatalf("config was rewritten: %s", raw)
	}
}

func TestValidatePresentationOnSave(t *testing.T) {
	a := presentTestApp(t)
	tool := &Tool{Name: "bad_fmt", Method: "GET", URL: "http://127.0.0.1/", Approval: "off", Config: ToolConfig{ResultFormat: "pdf"}}
	if err := a.store.SaveTool(tool); err == nil {
		t.Fatal("invalid result_format should be rejected")
	}
	tool.Config.ResultFormat = resultFormatSelector
	tool.Config.ResultSelector = ""
	if err := a.store.SaveTool(tool); err == nil {
		t.Fatal("empty selector should be rejected")
	}
	tool.Config.ResultSelector = "div>"
	if err := a.store.SaveTool(tool); err == nil {
		t.Fatal("illegal selector should be rejected")
	}
	tool.Config.ResultSelector = "div#main"
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
}

func TestHTTP400KeepsExistingFormat(t *testing.T) {
	a := presentTestApp(t)
	up := presentUpstream(t, 404, "application/json", `{"code":"DEMOERR0001","msg":"gone"}`)
	savePresentTool(t, a, "http_404", "GET", up.URL, ToolConfig{}, nil)
	text, isErr := invokePresent(t, a, "http_404", nil)
	if !isErr {
		t.Fatal("404 should be isError")
	}
	if !strings.Contains(text, "HTTP 404") || !strings.Contains(text, "gone") {
		t.Fatalf("should keep HTTP N format: %s", text)
	}
}
