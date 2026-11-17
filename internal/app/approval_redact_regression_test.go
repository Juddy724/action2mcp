package app

import (
	"action2mcp/internal/approval"
	"action2mcp/internal/domain"
	"action2mcp/internal/execution"
	"action2mcp/internal/vault"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func requirePrivateApprovalValuesAbsent(t *testing.T, value any, privateValues ...string) {
	t.Helper()
	text := string(execution.CompactJSON(value))
	for _, private := range privateValues {
		if strings.Contains(text, private) {
			t.Fatal("approval output leaked a private value")
		}
	}
}

func TestApprovalSecretValueMatchesKey(t *testing.T) {
	for _, kind := range []string{"json", "form", "query"} {
		t.Run(kind, func(t *testing.T) {
			a := approvalTestApp(t)
			a.cfg.Port = 19000
			handler := a.Handler()
			const origin = "http://127.0.0.1:19000"
			static := privateTestValue(t)
			const label = "token"
			var hits atomic.Int32
			var received atomic.Bool
			var wantBody, wantURL string
			upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body []byte
				var err error
				if r.Body != nil {
					body, err = io.ReadAll(r.Body)
				}
				received.Store(err == nil && string(body) == wantBody && r.URL.String() == wantURL)
				hits.Add(1)
				io.WriteString(w, "ok")
			}))
			tool, _ := saveApprovalTool(t, a, upstream, "always")
			tool.Params = []domain.Param{{Name: "label", Type: "string", Required: true}}
			tool.Body = `{"password":"{{label}}","token":"` + static + `"}`
			if kind == "form" {
				tool.Headers["Content-Type"] = "application/x-www-form-urlencoded"
				tool.Body = "password={{label}}&token=" + static
			} else if kind == "query" {
				tool.URL += "?password={{label}}&token=" + static
				tool.Body = ""
			}
			wantBody = strings.ReplaceAll(tool.Body, "{{label}}", label)
			wantURL = strings.ReplaceAll(tool.URL, "{{label}}", label)
			if err := a.store.SaveTool(tool); err != nil {
				t.Fatal("cannot save key collision fixture")
			}
			assertPreview := func(preview domain.RequestPreview) {
				t.Helper()
				requirePrivateApprovalValuesAbsent(t, preview, static)
				if kind == "json" {
					var body map[string]string
					if json.Unmarshal([]byte(preview.Body), &body) != nil || len(body) != 2 || body["password"] != vault.Mask || body[vault.Mask] != vault.Mask {
						t.Fatal("preview must scrub both sensitive values, including a matching key")
					}
					return
				}
				raw := preview.Body
				if kind == "query" {
					u, err := url.Parse(preview.URL)
					if err != nil {
						t.Fatal("cannot parse preview URL")
					}
					raw = u.RawQuery
				}
				values, err := url.ParseQuery(raw)
				if err != nil || len(values) != 2 || values.Get("password") != vault.Mask || values.Get(vault.Mask) != vault.Mask {
					t.Fatal("preview must scrub both sensitive assignment values, including a matching key")
				}
			}
			assertRecord := func(record approval.Record) {
				t.Helper()
				requirePrivateApprovalValuesAbsent(t, record, static)
				assertPreview(record.Preview)
				if record.ArgsDisplay["label"] != vault.Mask || len(record.Params) != 1 || !record.Params[0].Secret {
					t.Fatal("approval did not mask the key collision argument")
				}
				if record.Status != "pending" && record.FinalArgsDisplay["label"] != vault.Mask {
					t.Fatal("approval did not mask the final key collision argument")
				}
			}
			args := map[string]any{"label": label}
			prepared, err := a.executor().Prepare(tool, args)
			if err != nil {
				t.Fatal("cannot prepare key collision fixture")
			}
			if renderForTest(t, tool, args).Body != wantBody || renderForTest(t, tool, args).URL != wantURL {
				t.Fatal("preview redaction changed the original execution request")
			}
			assertPreview(prepared.Preview)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			call := startApprovalCall(a, ctx, args)
			pending := pendingApprovals(t, a, 1)[0]
			assertRecord(pending)
			assertStored := func() {
				t.Helper()
				var previewJSON, argsJSON, finalJSON string
				if a.store.DB().QueryRow(`SELECT preview_display,args_display,final_args_display FROM approvals WHERE id=?`, pending.ID).Scan(&previewJSON, &argsJSON, &finalJSON) != nil {
					t.Fatal("cannot read stored key collision approval")
				}
				requirePrivateApprovalValuesAbsent(t, previewJSON+argsJSON+finalJSON, static)
				var preview approval.Preview
				var displayed map[string]string
				if json.Unmarshal([]byte(previewJSON), &preview) != nil || json.Unmarshal([]byte(argsJSON), &displayed) != nil || displayed["label"] != vault.Mask {
					t.Fatal("stored approval arguments are not masked")
				}
				assertPreview(preview.Preview)
			}
			assertStored()
			rows := listApprovalAPI(t, handler, origin, "pending")
			if len(rows) != 1 {
				t.Fatal("pending list API did not return the approval")
			}
			assertRecord(rows[0])
			preview, err := a.approvals().Preview(pending.ID, pending.Nonce, nil)
			if err != nil {
				t.Fatal("cannot preview key collision approval")
			}
			assertPreview(preview.Preview)
			w := approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/approvals/%d/preview", pending.ID), origin, "application/json", map[string]any{"nonce": pending.Nonce})
			requirePrivateApprovalValuesAbsent(t, w.Body.String(), static)
			var apiPreview approval.Preview
			requireApprovalAPIResponse(t, w, http.StatusOK, &apiPreview)
			assertPreview(apiPreview.Preview)
			if hits.Load() != 0 {
				t.Fatal("request executed before approval")
			}
			approveRecord(t, a, pending)
			if getApprovalReply(t, call).isError || hits.Load() != 1 || !received.Load() {
				t.Fatal("approved send changed the original execution request")
			}
			assertStored()
			history := listApprovalAPI(t, handler, origin, "all")
			if len(history) != 1 || history[0].Status != "approved" {
				t.Fatal("history API did not return the approved record")
			}
			assertRecord(history[0])
		})
	}
}

func TestApprovalEmbeddedJSONSecretParam(t *testing.T) {
	for _, kind := range []string{"json", "trailing_comma", "unquoted_outer", "command", "prefixed", "prefixed_malformed", "form", "encoded_form", "query"} {
		for _, action := range []string{"approve", "edit"} {
			t.Run(kind+"/"+action, func(t *testing.T) {
				a := approvalTestApp(t)
				a.cfg.Port = 19000
				handler := a.Handler()
				const origin = "http://127.0.0.1:19000"
				original, replacement := privateTestValue(t), privateTestValue(t)
				var received atomic.Bool
				var wantBody, wantURL string
				upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					var body []byte
					var err error
					if r.Body != nil {
						body, err = io.ReadAll(r.Body)
					}
					received.Store(err == nil && string(body) == wantBody && r.URL.String() == wantURL)
					w.Write(body)
				}))
				tool, _ := saveApprovalTool(t, a, upstream, "always")
				tool.Params = []domain.Param{{Name: "label", Type: "string", Required: true}}
				inner := `{"password":"{{label}}"}`
				if kind == "command" {
					inner = "RUN " + inner
				} else if kind == "prefixed" || kind == "prefixed_malformed" {
					inner = "RUN --option value " + inner
				}
				tool.Body = string(execution.CompactJSON(map[string]string{"payload": inner}))
				if kind == "trailing_comma" || kind == "prefixed_malformed" {
					tool.Body = strings.TrimSuffix(tool.Body, "}") + ",}"
				} else if kind == "unquoted_outer" {
					tool.Body = `{"n":{{n}}.0,"payload":` + string(execution.CompactJSON(inner)) + `}`
					tool.Params = append(tool.Params, domain.Param{Name: "n", Type: "integer", Default: "1"})
				} else if kind == "form" || kind == "encoded_form" || kind == "query" {
					if kind != "form" {
						inner = strings.ReplaceAll(url.QueryEscape(inner), url.QueryEscape("{{label}}"), "{{label}}")
					}
					tool.Body = "payload=" + inner
					tool.Headers["Content-Type"] = "application/x-www-form-urlencoded"
					if kind == "query" {
						tool.URL += "?" + tool.Body
						tool.Body = ""
					}
				}
				if tool.Params[0].Secret || a.vault.FindByValue(original) != "" || a.vault.FindByValue(replacement) != "" {
					t.Fatal("embedded fixture must use an unmarked argument outside the vault")
				}
				if !execution.ParamIsSecret(tool, tool.Params[0]) {
					t.Fatal("embedded sensitive field did not classify its argument as secret")
				}
				if err := a.store.SaveTool(tool); err != nil {
					t.Fatal("cannot save embedded argument fixture")
				}
				assertSafe := func(value any) {
					t.Helper()
					requirePrivateApprovalValuesAbsent(t, value, original, replacement)
				}
				assertRecord := func(record approval.Record) {
					t.Helper()
					assertSafe(record)
					if record.ArgsDisplay["label"] != vault.Mask || !record.Params[0].Secret {
						t.Fatal("embedded argument leaked into the approval card")
					}
					if record.Status != "pending" && record.FinalArgsDisplay["label"] != vault.Mask {
						t.Fatal("embedded final argument leaked into approval history")
					}
				}
				prepared, err := a.executor().Prepare(tool, map[string]any{"label": original})
				if err != nil {
					t.Fatal("cannot prepare embedded argument fixture")
				}
				assertSafe(prepared.Preview)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				call := startApprovalCall(a, ctx, map[string]any{"label": original})
				pending := pendingApprovals(t, a, 1)[0]
				assertRecord(pending)
				rows := listApprovalAPI(t, handler, origin, "pending")
				if len(rows) != 1 {
					t.Fatal("pending API did not return the embedded argument fixture")
				}
				assertRecord(rows[0])
				var edits map[string]any
				label := original
				if action == "edit" {
					edits = map[string]any{"label": replacement}
					label = replacement
				}
				w := approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/approvals/%d/preview", pending.ID), origin, "application/json", map[string]any{"nonce": pending.Nonce, "args": edits})
				assertSafe(w.Body.String())
				var preview approval.Preview
				requireApprovalAPIResponse(t, w, http.StatusOK, &preview)
				assertSafe(preview)
				wantBody = strings.ReplaceAll(strings.ReplaceAll(tool.Body, "{{label}}", label), "{{n}}", "1")
				wantURL = strings.ReplaceAll(tool.URL, "{{label}}", label)
				w = approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/approvals/%d/decide", pending.ID), origin, "application/json", map[string]any{"action": action, "nonce": pending.Nonce, "args": edits, "preview_hash": preview.PreviewHash})
				requireApprovalAPIResponse(t, w, http.StatusOK, nil)
				reply := getApprovalReply(t, call)
				assertSafe(reply.text)
				if reply.isError || !received.Load() {
					t.Fatal("embedded argument was not forwarded unchanged after approval")
				}
				if action == "edit" && !strings.Contains(reply.text, "修改的参数：label）") {
					t.Fatal("edit result prefix must include the secret argument name only")
				}
				history := listApprovalAPI(t, handler, origin, "all")
				wantStatus := "approved"
				if action == "edit" {
					wantStatus = "edited"
				}
				if len(history) != 1 || history[0].Status != wantStatus {
					t.Fatal("history API did not return the completed embedded argument fixture")
				}
				assertRecord(history[0])
				var stored string
				if a.store.DB().QueryRow(`SELECT args_display || final_args_display || preview_display || params_json || result FROM approvals WHERE id=?`, pending.ID).Scan(&stored) != nil {
					t.Fatal("cannot read stored embedded argument approval")
				}
				assertSafe(stored)
			})
		}
	}
}
