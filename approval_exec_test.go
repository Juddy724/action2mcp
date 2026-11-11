package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPreparedCredentialEncodings(t *testing.T) {
	for _, kind := range []string{"form", "json", "nested", "command"} {
		t.Run(kind, func(t *testing.T) {
			a := approvalTestApp(t)
			secret := privateTestValue(t) + `&="\`
			if err := a.vault.Upsert("encoding", "secret", secret, "", ""); err != nil {
				t.Fatal(err)
			}
			literal := "{{secret.some_name}}"
			var received atomic.Bool
			upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				valid := r.URL.Query().Get("credential") == secret && r.URL.Query().Get("literal") == literal && r.Header.Get("X-Credential") == secret
				if kind == "form" {
					if r.ParseForm() != nil || r.PostForm.Get("credential") != secret || r.PostForm.Get("literal") != literal {
						valid = false
					}
				} else {
					var body map[string]any
					if json.NewDecoder(r.Body).Decode(&body) != nil {
						valid = false
					}
					if kind == "nested" || kind == "command" {
						inner, ok := body["inner"].(string)
						if !ok {
							valid = false
						}
						inner = strings.TrimPrefix(inner, "RUN ")
						if json.Unmarshal([]byte(inner), &body) != nil {
							valid = false
						}
					}
					if body["credential"] != secret || body["literal"] != literal || body["inline"] != "prefix "+secret+" suffix" {
						valid = false
					}
				}
				received.Store(valid)
				w.Header().Set("X-Echo", secret)
				io.WriteString(w, secret)
			}))
			a.httpClient = upstream.Client()
			tool := &Tool{Method: "POST", URL: upstream.URL + "/?credential={{secret.encoding}}&literal={{value}}",
				Headers: map[string]string{"X-Credential": "{{secret.encoding}}", "X-Config": "{{cfg.encoding}}", "Content-Type": "application/json"},
				Params:  []Param{{Name: "value", Type: "string", Required: true}}, Body: `{"credential":"{{secret.encoding}}","literal":"{{value}}","inline":"prefix {{secret.encoding}} suffix"}`}
			if kind == "form" {
				tool.Headers["Content-Type"] = "application/x-www-form-urlencoded"
				tool.Body = "credential={{secret.encoding}}&literal={{value}}"
			} else if kind == "nested" || kind == "command" {
				inner := tool.Body
				if kind == "command" {
					inner = "RUN " + inner
				}
				tool.Body = string(compactJSON(map[string]any{"inner": inner}))
			}
			prepared, err := a.Prepare(tool, map[string]any{"value": literal})
			if err != nil {
				t.Fatal("prepare failed")
			}
			if !strings.Contains(prepared.Preview.URL, "{{secret.encoding}}") || !strings.Contains(prepared.Preview.Headers["X-Config"], "{{cfg.encoding}}") {
				t.Fatal("preview resolved credentials")
			}
			if strings.Contains(string(compactJSON(prepared.Preview)), secret) {
				t.Fatal("preview leaked secret")
			}
			for i := 0; i < 20; i++ {
				next, err := a.Prepare(tool, map[string]any{"value": literal})
				if err != nil || next.PreviewHash != prepared.PreviewHash {
					t.Fatal("preview hash is unstable")
				}
			}
			res, err := a.Send(prepared)
			if err != nil || res.Error != "" || !received.Load() {
				t.Fatal("credential encoding or literal parameter forwarding failed")
			}
			if strings.Contains(res.Body, secret) || strings.Contains(res.URL, url.QueryEscape(secret)) || strings.Contains(res.Headers["X-Echo"], secret) {
				t.Fatal("send leaked secret")
			}
			if _, err := a.Execute(tool, map[string]any{"value": literal}); err != nil {
				t.Fatal("execute failed")
			}
		})
	}
}

func TestParamIsSecret(t *testing.T) {
	a := approvalTestApp(t)
	secret := privateTestValue(t)
	if err := a.vault.Upsert("saved", "plain", secret, "", ""); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		tool  Tool
		param Param
		value any
		want  bool
	}{
		{"flag", Tool{}, Param{Name: "label", Secret: true}, "", true},
		{"name", Tool{}, Param{Name: "api_token"}, "", true},
		{"description", Tool{}, Param{Name: "label", Description: "说明 " + removedSecretDesc}, "", true},
		{"json", Tool{Body: `{"credentials":{"value":"{{label}}"}}`}, Param{Name: "label"}, "", true},
		{"unquoted_json", Tool{Body: `{"password":{{label}}}`}, Param{Name: "label", Type: "integer"}, "", true},
		{"quoted_json", Tool{Body: `{"password":"{{label}}"}`}, Param{Name: "label"}, "", true},
		{"unquoted_nested_json", Tool{Body: `{"credentials":{"other":0,"value":{{label}}}}`}, Param{Name: "label"}, "", true},
		{"json_like", Tool{Body: `{password:{{label}}}`}, Param{Name: "label"}, "", true},
		{"json_like_quoted", Tool{Body: `{password:"{{label}}"}`}, Param{Name: "label"}, "", true},
		{"nested_unquoted", Tool{Body: `{"inner":"{\"password\":{{label}}}"}`}, Param{Name: "label"}, "", true},
		{"nested", Tool{Body: `{"inner":"{\"password\":\"{{label}}\"}"}`}, Param{Name: "label"}, "", true},
		{"header", Tool{Headers: map[string]string{"Authorization": "Bearer {{ label }}"}}, Param{Name: "label"}, "", true},
		{"query", Tool{URL: "https://example.com/?access_token={{label}}"}, Param{Name: "label"}, "", true},
		{"form", Tool{Body: "password={{label}}"}, Param{Name: "label"}, "", true},
		{"vault", Tool{}, Param{Name: "label"}, secret, true},
		{"vault_default", Tool{}, Param{Name: "label", Default: secret}, "", true},
		{"normal", Tool{Body: `{"label":"{{label}}"}`}, Param{Name: "label"}, "ordinary", false},
		{"password_value", Tool{Body: `{"note":"password={{label}}","count":{{count}}}`}, Param{Name: "label"}, "ordinary", false},
		{"form_value", Tool{Body: `note=password={{label}}`}, Param{Name: "label"}, "ordinary", false},
		{"unrelated_placeholder", Tool{Body: `{"password":{{other}},"label":{{label}}}`}, Param{Name: "label"}, "ordinary", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if a.paramIsSecret(&tc.tool, tc.param, tc.value) != tc.want {
				t.Fatal("wrong sensitive parameter classification")
			}
		})
	}
}

func TestPreparedSendScrubsErrors(t *testing.T) {
	a := approvalTestApp(t)
	secret := privateTestValue(t) + `&="\`
	if err := a.vault.Upsert("error_value", "secret", secret, "", ""); err != nil {
		t.Fatal(err)
	}
	a.httpClient = &http.Client{Transport: approvalRoundTripper(func(r *http.Request) (*http.Response, error) { return nil, errors.New("request failed: " + secret) })}
	tool := &Tool{Method: "GET", URL: "http://127.0.0.1:19001/?value={{secret.error_value}}"}
	prepared, err := a.Prepare(tool, nil)
	if err != nil {
		t.Fatal("prepare failed")
	}
	result, err := a.Send(prepared)
	if err != nil || result.Error == "" {
		t.Fatal("expected a scrubbed transport error")
	}
	if strings.Contains(result.Error, secret) || strings.Contains(result.Error, url.QueryEscape(secret)) {
		t.Fatal("send error leaked secret")
	}
	tool.URL = "https://example.com/?value={{secret.missing}}"
	if _, err := a.Prepare(tool, nil); err != nil {
		t.Fatal("prepare resolved a deferred credential")
	}
	if _, err := a.Execute(tool, nil); err == nil {
		t.Fatal("send ignored missing credential")
	}
}

func TestApprovalCommitBoundary(t *testing.T) {
	for _, change := range []string{"update", "delete", "disable", "other_enabled_pack"} {
		t.Run(change, func(t *testing.T) {
			var hits atomic.Int32
			upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
			a := approvalTestApp(t)
			tool, pack := saveApprovalTool(t, a, upstream, "always")
			call := startApprovalCall(a, context.Background(), map[string]any{"value": "one"})
			r := pendingApprovals(t, a, 1)[0]
			switch change {
			case "update":
				tool.Body = `{"different":"{{value}}"}`
				if err := a.store.SaveTool(tool); err != nil {
					t.Fatal(err)
				}
			case "delete":
				if err := a.store.DeleteTool(tool.ID); err != nil {
					t.Fatal(err)
				}
			case "other_enabled_pack":
				if err := a.store.SavePack(&Pack{Name: "另一个开启包", Enabled: true, ToolIDs: []int64{tool.ID}}); err != nil {
					t.Fatal(err)
				}
				fallthrough
			case "disable":
				a.store.SetPackEnabled(pack.ID, false)
			}
			approveRecord(t, a, r)
			reply := getApprovalReply(t, call)
			if change == "other_enabled_pack" {
				if reply.isError || hits.Load() != 1 {
					t.Fatal("enabled membership was not honored")
				}
				return
			}
			if !reply.isError || reply.text != "工具或请求内容在审批期间变化，未执行，请重新调用" || hits.Load() != 0 {
				t.Fatal("commit boundary did not stop execution")
			}
			rows, err := a.ListApprovals("all", 1)
			if err != nil || rows[0].Status != "approved" || rows[0].Result != "未执行：工具在审批期间被修改/关闭/请求内容已变化" {
				t.Fatal("commit failure audit is incorrect")
			}
		})
	}
}

func TestApprovalPreviewExpiryAndPreparedIntegrity(t *testing.T) {
	a := approvalTestApp(t)
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	tool, _ := saveApprovalTool(t, a, upstream, "always")
	tool.Body = `{"date":"{{date}}","value":"{{value}}"}`
	tool.Params = append(tool.Params, Param{Name: "date", Type: "string", Default: "@today"})
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	var day atomic.Int64
	base := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	a.prepareNow = func() time.Time { return base.Add(time.Duration(day.Load()) * 24 * time.Hour) }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	call := startApprovalCall(a, ctx, map[string]any{"value": "one"})
	r := pendingApprovals(t, a, 1)[0]
	day.Store(1)
	err := a.DecideApproval(r.ID, r.Nonce, "approve", nil, "", r.PreviewHash)
	requireApprovalStatus(t, err, 409)
	if !strings.Contains(err.Error(), "预览已过期") {
		t.Fatal("expiry message missing")
	}
	pendingApprovals(t, a, 1)
	preview, err := a.PreviewApproval(r.ID, r.Nonce, map[string]any{"value": "one"})
	if err != nil || preview.PreviewHash == r.PreviewHash {
		t.Fatal("refresh did not update preview hash")
	}
	prepared, err := a.Prepare(tool, map[string]any{"value": "one"})
	if err != nil {
		t.Fatal(err)
	}
	p := &pendingApproval{tool: tool, record: ApprovalRecord{ToolRev: tool.Rev}, prepared: prepared, confirmedHash: prepared.PreviewHash}
	if !a.approvalCommitValid(p) {
		t.Fatal("unchanged prepared request failed integrity check")
	}
	prepared.request.Body += " "
	if a.approvalCommitValid(p) {
		t.Fatal("modified prepared request passed integrity check")
	}
	cancel()
	getApprovalReply(t, call)
}

func TestApprovalFrozenRequestSurvivesRelogin(t *testing.T) {
	a := approvalTestApp(t)
	secret := privateTestValue(t)
	if err := a.vault.Upsert("business", "secret", secret, "", ""); err != nil {
		t.Fatal(err)
	}
	var day atomic.Int64
	base := time.Date(2026, 11, 11, 23, 59, 59, 0, time.UTC)
	a.prepareNow = func() time.Time { return base.Add(time.Duration(day.Load()) * 24 * time.Hour) }
	var businessHits, loginHits atomic.Int32
	var frozen atomic.Bool
	frozen.Store(true)
	session := privateTestValue(t)
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" {
			if r.Method == "POST" {
				loginHits.Add(1)
				http.SetCookie(w, &http.Cookie{Name: "sid", Value: session, Path: "/"})
			}
			io.WriteString(w, `{}`)
			return
		}
		businessHits.Add(1)
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil || body["date"] != base.Format("2006-01-02") || r.URL.Query().Get("date") != base.Format("2006-01-02") {
			frozen.Store(false)
		}
		day.Store(1)
		cookie, err := r.Cookie("sid")
		if err != nil || cookie.Value != session {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("X-Echo", secret)
		io.WriteString(w, secret)
	}))
	tool, _ := saveApprovalTool(t, a, upstream, "always")
	tool.URL = upstream.URL + "/api?date={{date}}"
	tool.Body = `{"date":"{{date}}","value":"{{value}}"}`
	tool.Params = append(tool.Params, Param{Name: "date", Type: "string", Default: "@today"})
	tool.Headers["X-Credential"] = "{{secret.business}}"
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	site := a.store.EnsureSite(tool.URL)
	site.Method = MethodForm
	site.EntryURL = upstream.URL + "/login"
	site.Form = FormLogin{LoginURL: upstream.URL + "/login", Request: &LoginRequest{Method: "POST", URL: upstream.URL + "/login", Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"password":"{{secret.business}}"}`}}
	if err := a.store.SaveSite(site); err != nil {
		t.Fatal(err)
	}
	call := startApprovalCall(a, context.Background(), map[string]any{"value": "one"})
	r := pendingApprovals(t, a, 1)[0]
	approveRecord(t, a, r)
	reply := getApprovalReply(t, call)
	if reply.isError || !strings.Contains(reply.text, "已自动重新登录") || businessHits.Load() != 2 || loginHits.Load() != 1 || !frozen.Load() {
		t.Fatal("approved request changed during relogin or relogin flag was lost")
	}
	if strings.Contains(reply.text, secret) {
		t.Fatal("approved relogin result leaked secret")
	}
}

func TestToolConsoleGuardAndRedirect(t *testing.T) {
	a := approvalTestApp(t)
	var hits atomic.Int32
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "http://127.0.0.1:19002/api", 302)
			return
		}
		hits.Add(1)
	}))
	a.httpClient = upstream.Client()
	a.cfg.Port = 19002
	tool := &Tool{Method: "GET", URL: upstream.URL + "/ok"}
	if res, err := a.Execute(tool, nil); err != nil || res.Error != "" || hits.Load() != 1 {
		t.Fatal("different loopback port was blocked")
	}
	for _, raw := range []string{"http://127.0.0.1:19002/api", "http://127.0.0.1:019002/api", upstream.URL + "/redirect"} {
		tool.URL = raw
		res, err := a.Execute(tool, nil)
		message := ""
		if err != nil {
			message = err.Error()
		} else {
			message = res.Error
		}
		if !strings.Contains(message, "不允许工具访问控制台自身接口") {
			t.Fatal("self-console request was accepted")
		}
	}
	if hits.Load() != 1 {
		t.Fatal("guard contacted console destination")
	}
	var dialed atomic.Bool
	a.httpClient = &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("unexpected dial")
	}}}
	client, closeIdle := a.toolHTTPClient()
	defer closeIdle()
	request, _ := http.NewRequest("GET", "http://127.0.0.1:"+strconv.Itoa(a.cfg.Port)+"/api", nil)
	if _, err := client.Do(request); err == nil || dialed.Load() {
		t.Fatal("replaced client bypassed transport guard")
	}
	transport := client.Transport.(toolTransport).base.(*http.Transport)
	if _, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:19002"); !errors.Is(err, errConsoleRequest) || dialed.Load() {
		t.Fatal("dial guard allowed local destination")
	}
}

func TestStdioApprovalCallPolicy(t *testing.T) {
	for _, method := range []string{"tools/call", "tools/list", "initialize", "ping"} {
		timeout, attempts := stdioCallPolicy(compactJSON(map[string]any{"method": method}))
		if method == "tools/call" {
			if timeout != 35*time.Minute || attempts != 1 {
				t.Fatal("tools/call may retry or timeout during approval")
			}
		} else if timeout != 240*time.Second || attempts != 2 {
			t.Fatal("other methods lost retry policy")
		}
	}
}
