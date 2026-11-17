package result

import (
	"strings"
	"testing"
)

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
	p := Config{ResultFormat: resultFormatSelector, ResultSelector: "#ticket-title"}
	res := &Response{Status: 200, Body: page, Headers: map[string]string{"Content-Type": "text/html"}}
	Present(p, res)
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
	p := Config{}
	res := &Response{Status: 200, Body: page, Headers: map[string]string{"Content-Type": "text/html"}}
	Present(p, res)
	if res.Outcome != outcomeBusinessError || !strings.Contains(res.Body, "业务失败：对象不存在") {
		t.Fatalf("long href must not hide the alert: outcome=%s body=%s", res.Outcome, res.Body)
	}
	if strings.Contains(res.Body, "已返回原始 HTML") {
		t.Fatalf("failure must not fall back: %s", res.Body)
	}
}
func TestPresentSQLGuardAndWSSkip60KB(t *testing.T) {
	msg := strings.Repeat("甲", MaxHTTPBytes)
	raw := `{"success":false,"msg":"` + msg + `"}`
	sql := Config{WebSocket: true, SQLGuard: true}
	sqlRes := &Response{Status: 200, Body: raw, Outcome: outcomeSuccess, Truncated: true, Headers: map[string]string{"Content-Type": "application/json"}}
	Present(sql, sqlRes)
	if sqlRes.Body != raw || sqlRes.Outcome != outcomeSuccess || !sqlRes.Truncated {
		t.Fatalf("sql guard changed result outcome=%s trunc=%v changed=%v", sqlRes.Outcome, sqlRes.Truncated, sqlRes.Body != raw)
	}

	ws := Config{WebSocket: true}
	wsRes := &Response{Status: 200, Body: raw, Headers: map[string]string{"Content-Type": "application/json"}}
	Present(ws, wsRes)
	if wsRes.Outcome != outcomeBusinessError || wsRes.Truncated || !strings.Contains(wsRes.Body, msg) {
		t.Fatalf("ws json failure truncated or missed: outcome=%s trunc=%v len=%d", wsRes.Outcome, wsRes.Truncated, len(wsRes.Body))
	}
	if strings.Contains(wsRes.Body, "…[已截断]") {
		t.Fatal("ws result was 60KB-truncated")
	}

	httpRes := &Response{Status: 200, Body: raw, Headers: map[string]string{"Content-Type": "application/json"}}
	Present(Config{}, httpRes)
	if httpRes.Outcome != outcomeBusinessError || !httpRes.Truncated || !strings.HasPrefix(httpRes.Body, "业务失败：") || !strings.Contains(httpRes.Body, "…[已截断]") {
		t.Fatalf("http json failure should keep the prefix and truncate: outcome=%s trunc=%v body=%s", httpRes.Outcome, httpRes.Truncated, httpRes.Body[:min(80, len(httpRes.Body))])
	}

	page := `<!DOCTYPE html><html><body><nav>导航不要</nav><main><h1>标题乙</h1><p>需要保留的正文</p></main></body></html>`
	wsHTML := &Response{Status: 200, Body: page, Headers: map[string]string{"Content-Type": "text/html"}}
	Present(Config{WebSocket: true}, wsHTML)
	if strings.Contains(wsHTML.Body, "导航不要") || !strings.Contains(wsHTML.Body, "标题乙") || wsHTML.Truncated {
		t.Fatalf("ws html: trunc=%v body=%s", wsHTML.Truncated, wsHTML.Body)
	}
}
