package app

import (
	"action2mcp/internal/analysis"
	"action2mcp/internal/approval"
	"action2mcp/internal/domain"
	"action2mcp/internal/execution"
	"action2mcp/internal/mcp"
	"action2mcp/internal/store"
	"action2mcp/internal/vault"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func approvalAPIRequest(t *testing.T, handler http.Handler, method, path, origin, contentType string, body any) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		t.Fatal("cannot encode API request")
	}
	r := httptest.NewRequest(method, "http://127.0.0.1"+path, bytes.NewReader(b))
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

// Never print a response body: a redaction regression could put a secret in it.
func requireApprovalAPIResponse(t *testing.T, w *httptest.ResponseRecorder, status int, out any) {
	t.Helper()
	if w.Code != status {
		t.Fatalf("HTTP status = %d, want %d", w.Code, status)
	}
	mediaType, _, err := mime.ParseMediaType(w.Header().Get("Content-Type"))
	if err != nil || mediaType != "application/json" || !json.Valid(w.Body.Bytes()) {
		t.Fatal("response must be application/json with a valid JSON body")
	}
	if out != nil && json.Unmarshal(w.Body.Bytes(), out) != nil {
		t.Fatal("cannot decode API response")
	}
}

func listApprovalAPI(t *testing.T, handler http.Handler, origin, status string) []approval.Record {
	t.Helper()
	w := approvalAPIRequest(t, handler, http.MethodPost, "/api/approvals/list", origin, "application/json", map[string]any{"status": status, "limit": 100})
	var rows []approval.Record
	requireApprovalAPIResponse(t, w, http.StatusOK, &rows)
	return rows
}

func TestApprovalAPIRequestGuards(t *testing.T) {
	a := approvalTestApp(t)
	a.cfg.Port = 19000
	handler := a.Handler()
	origin := fmt.Sprintf("http://127.0.0.1:%d", a.cfg.Port)
	var hits atomic.Int32
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	saveApprovalTool(t, a, upstream, "always")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	call := startApprovalCall(a, ctx, map[string]any{"value": "initial"})
	pending := pendingApprovals(t, a, 1)[0]

	for _, endpoint := range []struct {
		name, path string
		body       map[string]any
	}{
		{"list", "/api/approvals/list", map[string]any{"status": "pending"}},
		{"preview", fmt.Sprintf("/api/approvals/%d/preview", pending.ID), map[string]any{"args": map[string]any{"value": "initial"}, "nonce": pending.Nonce}},
		{"decide", fmt.Sprintf("/api/approvals/%d/decide", pending.ID), map[string]any{"action": "approve", "nonce": pending.Nonce, "preview_hash": pending.PreviewHash}},
	} {
		t.Run(endpoint.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, origin, host, contentType string
				status                          int
			}{
				{"missing-origin", "", "127.0.0.1", "application/json", 403},
				{"null-origin", "null", "127.0.0.1", "application/json", 403},
				{"wrong-port", fmt.Sprintf("http://127.0.0.1:%d", a.cfg.Port+1), "127.0.0.1", "application/json", 403},
				{"wrong-origin-host", fmt.Sprintf("http://example.com:%d", a.cfg.Port), "127.0.0.1", "application/json", 403},
				{"wrong-request-host", origin, "example.com", "application/json", 403},
				{"missing-content-type", origin, "127.0.0.1", "", 415},
				{"wrong-content-type", origin, "127.0.0.1", "text/plain", 415},
				{"origin-before-content-type", "", "127.0.0.1", "", 403},
			} {
				t.Run(tc.name, func(t *testing.T) {
					r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+endpoint.path, bytes.NewReader(execution.CompactJSON(endpoint.body)))
					r.Host = tc.host
					if tc.origin != "" {
						r.Header.Set("Origin", tc.origin)
					}
					if tc.contentType != "" {
						r.Header.Set("Content-Type", tc.contentType)
					}
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, r)
					requireApprovalAPIResponse(t, w, tc.status, nil)
				})
			}
			if endpoint.name != "list" {
				for _, nonce := range []string{"", "wrong"} {
					name := "missing-nonce"
					if nonce != "" {
						name = "wrong-nonce"
					}
					t.Run(name, func(t *testing.T) {
						body := map[string]any{}
						for key, value := range endpoint.body {
							if key != "nonce" {
								body[key] = value
							}
						}
						if nonce != "" {
							body["nonce"] = nonce
						}
						w := approvalAPIRequest(t, handler, http.MethodPost, endpoint.path, origin, "application/json", body)
						requireApprovalAPIResponse(t, w, http.StatusForbidden, nil)
					})
				}
			}
		})
	}
	rows := listApprovalAPI(t, handler, origin, "pending")
	if len(rows) != 1 || rows[0].ID != pending.ID || hits.Load() != 0 {
		t.Fatal("rejected API requests changed the pending call or executed it")
	}
	w := approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/approvals/%d/decide", pending.ID), origin, "application/json", map[string]any{"action": "reject", "nonce": pending.Nonce, "feedback": "请修改后再次调用"})
	requireApprovalAPIResponse(t, w, http.StatusOK, nil)
	if !getApprovalReply(t, call).isError || hits.Load() != 0 {
		t.Fatal("rejected call executed")
	}
}

func TestApprovalAPIRejectRetryAndApprove(t *testing.T) {
	for _, action := range []string{"approve", "edit"} {
		t.Run(action, func(t *testing.T) {
			a := approvalTestApp(t)
			a.cfg.Port = 19000
			handler := a.Handler()
			origin := fmt.Sprintf("http://127.0.0.1:%d", a.cfg.Port)
			var hits atomic.Int32
			received := make(chan string, 1)
			upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				var body map[string]string
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				received <- body["value"]
				io.WriteString(w, "ok")
			}))
			saveApprovalTool(t, a, upstream, "always")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			args := map[string]any{"value": "initial"}
			call := startApprovalCall(a, ctx, args)
			pendingApprovals(t, a, 1)
			var pending approval.Record
			for _, host := range []string{"127.0.0.1", "localhost", "[::1]"} {
				for _, contentType := range []string{"application/json", "application/json; charset=utf-8"} {
					w := approvalAPIRequest(t, handler, http.MethodPost, "/api/approvals/list", fmt.Sprintf("http://%s:%d", host, a.cfg.Port), contentType, map[string]any{"status": "pending", "limit": 1})
					var rows []approval.Record
					requireApprovalAPIResponse(t, w, http.StatusOK, &rows)
					if len(rows) != 1 || rows[0].Nonce == "" || rows[0].PreviewHash == "" || rows[0].ArgsDisplay["value"] != "initial" {
						t.Fatal("list did not return the pending approval and its confirmation fields")
					}
					pending = rows[0]
				}
			}
			previewPath := fmt.Sprintf("/api/approvals/%d/preview", pending.ID)
			decidePath := fmt.Sprintf("/api/approvals/%d/decide", pending.ID)
			w := approvalAPIRequest(t, handler, http.MethodPost, previewPath, origin, "application/json; charset=utf-8", map[string]any{"args": args, "nonce": pending.Nonce})
			var preview approval.Preview
			requireApprovalAPIResponse(t, w, http.StatusOK, &preview)
			if preview.PreviewHash != pending.PreviewHash || preview.Preview.Method != "POST" || preview.Preview.Body != `{"value":"initial"}` {
				t.Fatal("preview does not match the listed request")
			}

			for _, tc := range []struct {
				name, action, feedback, hash string
				args                         map[string]any
				status                       int
			}{
				{"invalid-edit", "edit", "", preview.PreviewHash, map[string]any{"value": nil}, 400},
				{"empty-feedback", "reject", "", "", nil, 400},
				{"blank-feedback", "reject", " \t\n ", "", nil, 400},
				{"missing-hash", "approve", "", "", nil, 400},
				{"stale-hash", "approve", "", "stale", nil, 409},
				{"stale-edit-hash", "edit", "", preview.PreviewHash, map[string]any{"value": "changed"}, 409},
			} {
				t.Run(tc.name, func(t *testing.T) {
					w := approvalAPIRequest(t, handler, http.MethodPost, decidePath, origin, "application/json", map[string]any{"action": tc.action, "args": tc.args, "feedback": tc.feedback, "nonce": pending.Nonce, "preview_hash": tc.hash})
					var response struct {
						Error string `json:"error"`
					}
					requireApprovalAPIResponse(t, w, tc.status, &response)
					if tc.status == http.StatusConflict && response.Error != "预览已过期，请刷新后重新确认" {
						t.Fatal("stale preview did not return the refresh message")
					}
					rows := listApprovalAPI(t, handler, origin, "pending")
					if len(rows) != 1 || rows[0].ID != pending.ID || rows[0].Status != "pending" || rows[0].PreviewHash != pending.PreviewHash || hits.Load() != 0 {
						t.Fatal("invalid decision changed the pending approval or executed it")
					}
					select {
					case <-call:
						t.Fatal("invalid decision unblocked the tool call")
					default:
					}
				})
			}
			feedback := "请缩小范围后再次调用"
			w = approvalAPIRequest(t, handler, http.MethodPost, decidePath, origin, "application/json; charset=utf-8", map[string]any{"action": "reject", "nonce": pending.Nonce, "feedback": feedback})
			requireApprovalAPIResponse(t, w, http.StatusOK, nil)
			reply := getApprovalReply(t, call)
			if !reply.isError || !strings.Contains(reply.text, feedback) || !strings.Contains(reply.text, "再次调用") || hits.Load() != 0 {
				t.Fatal("rejection did not return feedback without executing")
			}
			if len(listApprovalAPI(t, handler, origin, "pending")) != 0 {
				t.Fatal("rejected approval is still pending")
			}

			args = map[string]any{"value": "retry"}
			call = startApprovalCall(a, ctx, args)
			pendingApprovals(t, a, 1)
			next := listApprovalAPI(t, handler, origin, "pending")[0]
			if next.ID == pending.ID || next.Nonce == pending.Nonce {
				t.Fatal("retry did not create a new approval")
			}
			expected := "retry"
			if action == "edit" {
				expected = "confirmed"
				args = map[string]any{"value": expected}
			}
			previewPath = fmt.Sprintf("/api/approvals/%d/preview", next.ID)
			decidePath = fmt.Sprintf("/api/approvals/%d/decide", next.ID)
			w = approvalAPIRequest(t, handler, http.MethodPost, previewPath, origin, "application/json", map[string]any{"args": args, "nonce": next.Nonce})
			requireApprovalAPIResponse(t, w, http.StatusOK, &preview)
			if hits.Load() != 0 {
				t.Fatal("target was called before approval")
			}
			decision := map[string]any{"action": action, "nonce": next.Nonce, "preview_hash": preview.PreviewHash}
			if action == "edit" {
				decision["args"] = args
			}
			w = approvalAPIRequest(t, handler, http.MethodPost, decidePath, origin, "application/json", decision)
			var response struct {
				OK bool `json:"ok"`
			}
			requireApprovalAPIResponse(t, w, http.StatusOK, &response)
			if !response.OK || getApprovalReply(t, call).isError || hits.Load() != 1 {
				t.Fatal("approved retry did not execute exactly once")
			}
			if <-received != expected {
				t.Fatal("target received different arguments from the confirmed preview")
			}
			if len(listApprovalAPI(t, handler, origin, "pending")) != 0 {
				t.Fatal("approved approval is still pending")
			}
			for _, path := range []string{previewPath, decidePath} {
				w = approvalAPIRequest(t, handler, http.MethodPost, path, origin, "application/json", decision)
				requireApprovalAPIResponse(t, w, http.StatusConflict, nil)
			}
			if hits.Load() != 1 {
				t.Fatal("replayed decision executed again")
			}
		})
	}
}

func TestApprovalAPIRedactionAndJSONEscaping(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "explicit-secret"
		if legacy {
			name = "legacy-renamed-secret"
		}
		t.Run(name, func(t *testing.T) {
			a := approvalTestApp(t)
			a.cfg.Port = 19000
			handler := a.Handler()
			origin := fmt.Sprintf("http://127.0.0.1:%d", a.cfg.Port)
			secret := privateTestValue(t)
			const script = "<script>alert(1)</script>"
			var hits atomic.Int32
			received := make(chan map[string]any, 1)
			upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				body, err := io.ReadAll(r.Body)
				var args map[string]any
				if err != nil || json.Unmarshal(body, &args) != nil {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				received <- args
				w.Write(body)
			}))
			tool, _ := saveApprovalTool(t, a, upstream, "always")
			tool.Title = script
			tool.Body = `{"value":"{{value}}","label":"{{label}}"}`
			if legacy {
				tool.Body = `{"value":"{{value}}","credentials":{"value":"{{label}}"}}`
			}
			tool.Params = append(tool.Params, domain.Param{Name: "label", Type: "string", Required: true, Secret: !legacy})
			if err := a.store.SaveTool(tool); err != nil {
				t.Fatal("cannot save secret parameter fixture")
			}
			assertSafeJSON := func(w *httptest.ResponseRecorder, status int, out any) {
				t.Helper()
				if strings.Contains(w.Body.String(), secret) {
					t.Fatal("API response leaked a secret")
				}
				if bytes.ContainsAny(w.Body.Bytes(), "<>") {
					t.Fatal("API response contains unescaped HTML")
				}
				requireApprovalAPIResponse(t, w, status, out)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			call := startApprovalCall(a, ctx, map[string]any{"value": script, "label": secret})
			pendingApprovals(t, a, 1)
			w := approvalAPIRequest(t, handler, http.MethodPost, "/api/approvals/list", origin, "application/json", map[string]any{"status": "pending"})
			var rows []approval.Record
			assertSafeJSON(w, http.StatusOK, &rows)
			if len(rows) != 1 || rows[0].Title != script || rows[0].ArgsDisplay["value"] != script || rows[0].ArgsDisplay["label"] != vault.Mask || len(rows[0].Params) != 2 || !rows[0].Params[1].Secret {
				t.Fatal("pending API did not preserve text and redact the secret")
			}
			if !bytes.Contains(w.Body.Bytes(), []byte(`\u003cscript\u003ealert(1)\u003c/script\u003e`)) {
				t.Fatal("script was not returned as a JSON-escaped string")
			}
			pending := rows[0]
			assertStored := func(final bool) {
				t.Helper()
				var argsJSON, finalJSON, previewJSON, other string
				err := a.store.DB().QueryRow(`SELECT args_display,final_args_display,preview_display,tool || title || client || params_json || feedback || result FROM approvals WHERE id=?`, pending.ID).Scan(&argsJSON, &finalJSON, &previewJSON, &other)
				if err != nil {
					t.Fatal("cannot read stored approval")
				}
				stored := argsJSON + finalJSON + previewJSON + other
				if strings.Contains(stored, secret) || strings.Contains(stored, pending.Nonce) {
					t.Fatal("approval row contains a raw secret or nonce")
				}
				var args, finalArgs map[string]string
				var preview approval.Preview
				if json.Unmarshal([]byte(argsJSON), &args) != nil || args["label"] != vault.Mask || json.Unmarshal([]byte(previewJSON), &preview) != nil || !strings.Contains(preview.Preview.Body, vault.Mask) {
					t.Fatal("stored args or preview are not redacted")
				}
				if final && (json.Unmarshal([]byte(finalJSON), &finalArgs) != nil || finalArgs["label"] != vault.Mask) {
					t.Fatal("stored final args are not redacted")
				}
			}
			assertStored(false)
			args := map[string]any{"value": script + " updated", "label": approval.SecretUnchanged}
			previewPath := fmt.Sprintf("/api/approvals/%d/preview", pending.ID)
			decidePath := fmt.Sprintf("/api/approvals/%d/decide", pending.ID)
			w = approvalAPIRequest(t, handler, http.MethodPost, previewPath, origin, "application/json", map[string]any{"args": args, "nonce": pending.Nonce})
			var preview approval.Preview
			assertSafeJSON(w, http.StatusOK, &preview)
			var previewBody map[string]any
			if json.Unmarshal([]byte(preview.Preview.Body), &previewBody) != nil || previewBody["value"] != args["value"] || !strings.Contains(preview.Preview.Body, vault.Mask) {
				t.Fatal("preview did not preserve the text and redact the secret")
			}
			w = approvalAPIRequest(t, handler, http.MethodPost, decidePath, origin, "application/json", map[string]any{"action": "edit", "args": args, "nonce": pending.Nonce, "preview_hash": pending.PreviewHash})
			assertSafeJSON(w, http.StatusConflict, nil)
			if hits.Load() != 0 {
				t.Fatal("secret-bearing request executed before confirmation")
			}
			w = approvalAPIRequest(t, handler, http.MethodPost, decidePath, origin, "application/json", map[string]any{"action": "edit", "args": args, "nonce": pending.Nonce, "preview_hash": preview.PreviewHash})
			assertSafeJSON(w, http.StatusOK, nil)
			reply := getApprovalReply(t, call)
			if reply.isError || strings.Contains(reply.text, secret) || !strings.Contains(reply.text, "用户修改了参数") || hits.Load() != 1 {
				t.Fatal("edited call failed or exposed the secret in its result")
			}
			body := <-received
			label := body["label"]
			if legacy {
				credentials, _ := body["credentials"].(map[string]any)
				label = credentials["value"]
			}
			if body["value"] != args["value"] || label != secret {
				t.Fatal("confirmed request did not preserve the unchanged secret")
			}
			assertStored(true)
			if err := a.store.DeleteTool(tool.ID); err != nil {
				t.Fatal("cannot remove tool before reading history")
			}
			w = approvalAPIRequest(t, handler, http.MethodPost, "/api/approvals/list", origin, "application/json", map[string]any{"status": "all"})
			var history []approval.Record
			assertSafeJSON(w, http.StatusOK, &history)
			if len(history) != 1 || history[0].Status != "edited" || history[0].Nonce != "" || history[0].Title != script || history[0].ArgsDisplay["label"] != vault.Mask || history[0].FinalArgsDisplay["label"] != vault.Mask || history[0].FinalArgsDisplay["value"] != args["value"] || bytes.Contains(w.Body.Bytes(), []byte(`"nonce"`)) {
				t.Fatal("history did not retain redacted snapshots without a nonce")
			}
		})
	}
}

func TestApprovalAPIMCPDiscoveryHasNoApprovalTools(t *testing.T) {
	for _, mode := range []string{mcp.ModeFlat, mcp.ModeTiered} {
		t.Run(mode, func(t *testing.T) {
			a := approvalTestApp(t)
			tool, pack := saveApprovalTool(t, a, newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})), "always")
			tool.Name = "record_value"
			if err := a.store.SaveTool(tool); err != nil {
				t.Fatal(err)
			}
			if err := a.store.SetSettings(map[string]string{"mcp_mode": mode, analysis.SettingEnabled: "on"}); err != nil {
				t.Fatal(err)
			}
			c := &recTestClient{t: t, handler: a.Handler()}
			c.call("initialize", map[string]any{"protocolVersion": "2025-06-18"})
			checkNames := func(names []string) {
				t.Helper()
				if len(names) == 0 {
					t.Fatal("discovery returned no tools")
				}
				for _, name := range names {
					if strings.Contains(strings.ToLower(name), "approv") || name == "rec_reject" || name == "rec_decide" {
						t.Fatal("MCP discovery exposed an approval tool")
					}
				}
			}
			names := c.toolNames()
			checkNames(names)
			if mode == mcp.ModeFlat {
				if !has(names, tool.Name) || !has(names, "rec_save_tool") {
					t.Fatal("flat discovery did not include recorded and built-in tools")
				}
				return
			}
			if !has(names, "load_pack") || has(names, tool.Name) || has(names, "rec_save_tool") {
				t.Fatal("tiered discovery did not start with entry tools")
			}
			for _, load := range []struct {
				id       int64
				expected string
			}{{pack.ID, tool.Name}, {store.RecordingPackID, "rec_save_tool"}} {
				text, isError := c.tool("load_pack", map[string]any{"pack": load.id})
				var output struct {
					Tools []mcp.ToolBrief `json:"tools"`
				}
				if isError || json.Unmarshal([]byte(text), &output) != nil {
					t.Fatal("load_pack did not return a successful JSON tool list")
				}
				var loadedNames []string
				for _, tool := range output.Tools {
					loadedNames = append(loadedNames, tool.Name)
				}
				checkNames(loadedNames)
				if !has(loadedNames, load.expected) {
					t.Fatal("load_pack omitted the expected tool")
				}
			}
			names = c.toolNames()
			checkNames(names)
			if !has(names, tool.Name) || !has(names, "rec_save_tool") {
				t.Fatal("tiered discovery omitted loaded recorded or built-in tools")
			}
		})
	}
}

func TestApprovalAPISettingsTimeout(t *testing.T) {
	a := approvalTestApp(t)
	handler := a.Handler()
	type settings struct {
		Timeout     int    `json:"approval_timeout_secs"`
		Mode        string `json:"mcp_mode"`
		RecAnalysis bool   `json:"rec_analysis"`
	}
	getSettings := func(t *testing.T) settings {
		t.Helper()
		w := approvalAPIRequest(t, handler, http.MethodGet, "/api/settings", "", "", nil)
		var out settings
		requireApprovalAPIResponse(t, w, http.StatusOK, &out)
		return out
	}
	initial := getSettings(t)
	if initial.Timeout != 300 {
		t.Fatalf("default approval timeout = %d, want 300", initial.Timeout)
	}
	want := initial
	for _, timeout := range []int{29, 1801, 30, 1800} {
		t.Run(strconv.Itoa(timeout), func(t *testing.T) {
			w := approvalAPIRequest(t, handler, http.MethodPut, "/api/settings", "", "application/json", map[string]any{"approval_timeout_secs": timeout})
			if timeout < 30 || timeout > 1800 {
				requireApprovalAPIResponse(t, w, http.StatusBadRequest, nil)
			} else {
				want.Timeout = timeout
				var out settings
				requireApprovalAPIResponse(t, w, http.StatusOK, &out)
				if out != want || a.store.GetSetting("approval_timeout_secs", "") != strconv.Itoa(timeout) {
					t.Fatal("timeout-only PUT did not persist the value and preserve other settings")
				}
			}
			if getSettings(t) != want {
				t.Fatal("GET settings does not reflect the stored timeout")
			}
		})
	}
}

func TestApprovalAPIToolHTTPPolicy(t *testing.T) {
	a := approvalTestApp(t)
	handler := a.Handler()
	getTool := func(t *testing.T, id int64) Tool {
		t.Helper()
		w := approvalAPIRequest(t, handler, http.MethodGet, fmt.Sprintf("/api/tools/%d", id), "", "", nil)
		var out struct {
			Tool Tool `json:"tool"`
		}
		requireApprovalAPIResponse(t, w, http.StatusOK, &out)
		return out.Tool
	}
	var write Tool
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE", "GET", "HEAD"} {
		t.Run("default-"+method, func(t *testing.T) {
			body := map[string]any{"name": "default_" + strings.ToLower(method), "method": method, "url": "https://example.com/api"}
			w := approvalAPIRequest(t, handler, http.MethodPost, "/api/tools", "", "application/json", body)
			var created Tool
			requireApprovalAPIResponse(t, w, http.StatusOK, &created)
			want := "always"
			if method == "GET" || method == "HEAD" {
				want = "off"
			}
			if created.ID == 0 || created.Approval != want || getTool(t, created.ID).Approval != want {
				t.Fatal("new tool did not use and persist its method's approval default")
			}
			if method == "POST" {
				write = created
			}
		})
	}
	path := fmt.Sprintf("/api/tools/%d", write.ID)
	for _, method := range []string{http.MethodPost, http.MethodPut} {
		t.Run("illegal-"+method, func(t *testing.T) {
			url, name := "/api/tools", "illegal_policy"
			if method == http.MethodPut {
				url, name = path, write.Name
			}
			w := approvalAPIRequest(t, handler, method, url, "", "application/json", map[string]any{"name": name, "method": "POST", "url": "https://example.com/api", "approval": "once"})
			requireApprovalAPIResponse(t, w, http.StatusBadRequest, nil)
			if getTool(t, write.ID).Approval != "always" {
				t.Fatal("illegal approval changed the existing policy")
			}
		})
	}
	for _, tc := range []struct{ name, method, approval, want string }{
		{"omitted-keeps-always", "GET", "", "always"},
		{"explicit-downgrade", "POST", "off", "off"},
		{"omitted-keeps-off", "POST", "", "off"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := map[string]any{"name": write.Name, "title": tc.name, "method": tc.method, "url": "https://example.com/api"}
			if tc.approval != "" {
				body["approval"] = tc.approval
			}
			w := approvalAPIRequest(t, handler, http.MethodPut, path, "", "application/json", body)
			var updated Tool
			requireApprovalAPIResponse(t, w, http.StatusOK, &updated)
			stored := getTool(t, write.ID)
			if updated.Approval != tc.want || stored.Approval != tc.want || stored.Method != tc.method || stored.Title != tc.name {
				t.Fatal("tool PUT did not preserve or explicitly update approval")
			}
		})
	}
}

func TestApprovalAPILegacyRoutesRemainLocalOnly(t *testing.T) {
	a := approvalTestApp(t)
	a.cfg.Port = 19000
	handler := a.Handler()
	tool := &Tool{Name: "local_policy", Method: "POST", URL: "https://example.com/api", Approval: "always"}
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	toolPath := fmt.Sprintf("/api/tools/%d", tool.ID)
	for _, endpoint := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/api/settings", nil},
		{http.MethodPut, "/api/settings", map[string]any{"approval_timeout_secs": 60}},
		{http.MethodGet, "/api/tools", nil},
		{http.MethodGet, toolPath, nil},
		{http.MethodPost, "/api/tools", map[string]any{"name": "blocked_tool", "method": "POST", "url": "https://example.com/api"}},
		{http.MethodPut, toolPath, map[string]any{"name": tool.Name, "method": "POST", "url": tool.URL, "approval": "off"}},
	} {
		t.Run(endpoint.method+endpoint.path, func(t *testing.T) {
			for _, tc := range []struct{ name, host, origin string }{
				{"foreign-host", "example.com", ""},
				{"foreign-origin", "localhost", "https://example.com"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					r := httptest.NewRequest(endpoint.method, "http://127.0.0.1"+endpoint.path, bytes.NewReader(execution.CompactJSON(endpoint.body)))
					r.Host = tc.host
					r.Header.Set("Content-Type", "application/json")
					if tc.origin != "" {
						r.Header.Set("Origin", tc.origin)
					}
					w := httptest.NewRecorder()
					handler.ServeHTTP(w, r)
					if w.Code != http.StatusForbidden {
						t.Fatalf("localOnly status = %d, want 403", w.Code)
					}
				})
			}
		})
	}
	stored, err := a.store.GetTool(tool.ID)
	if err != nil || stored.Approval != "always" || a.store.GetSetting("approval_timeout_secs", "300") != "300" {
		t.Fatal("blocked request changed a tool policy or setting")
	}
}
