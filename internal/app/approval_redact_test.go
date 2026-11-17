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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestApprovalStaticTokenWithMaskedInteger(t *testing.T) {
	for _, kind := range []string{"json", "form", "query"} {
		t.Run(kind, func(t *testing.T) {
			a := approvalTestApp(t)
			a.cfg.Port = 19000
			handler := a.Handler()
			const origin = "http://127.0.0.1:19000"
			token := privateTestValue(t)
			n, err := strconv.ParseUint(privateTestValue(t)[:12], 16, 48)
			if err != nil {
				t.Fatal("cannot create private numeric value")
			}
			label := strconv.FormatUint(n, 10)
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
			tool.Params = []domain.Param{{Name: "label", Type: "integer", Required: true}}
			tool.Body = `{"password":{{label}},"token":"` + token + `"}`
			if kind == "form" {
				tool.Headers["Content-Type"] = "application/x-www-form-urlencoded"
				tool.Body = "password={{label}}&token=" + token
			} else if kind == "query" {
				tool.URL += "?password={{label}}&token=" + token
				tool.Body = ""
			}
			wantBody = strings.ReplaceAll(tool.Body, "{{label}}", label)
			wantURL = strings.ReplaceAll(tool.URL, "{{label}}", label)
			if err := a.store.SaveTool(tool); err != nil {
				t.Fatal("cannot save static token fixture")
			}
			assertSafe := func(value any) {
				t.Helper()
				text := string(execution.CompactJSON(value))
				if strings.Contains(text, token) || strings.Contains(text, label) {
					t.Fatal("approval display leaked a private value")
				}
			}
			assertPreview := func(preview domain.RequestPreview) {
				t.Helper()
				assertSafe(preview)
				if kind == "json" {
					var body map[string]any
					if json.Unmarshal([]byte(preview.Body), &body) != nil || body["password"] != vault.Mask || body["token"] != vault.Mask {
						t.Fatal("preview must contain valid JSON with both sensitive fields masked")
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
				if err != nil || values.Get("password") != vault.Mask || values.Get("token") != vault.Mask {
					t.Fatal("preview must mask both sensitive assignments")
				}
			}
			assertRecord := func(record approval.Record) {
				t.Helper()
				assertSafe(record)
				assertPreview(record.Preview)
				if record.ArgsDisplay["label"] != vault.Mask || len(record.Params) != 1 || !record.Params[0].Secret {
					t.Fatal("approval card did not mask the renamed secret argument")
				}
				if record.Status != "pending" && record.FinalArgsDisplay["label"] != vault.Mask {
					t.Fatal("approval history did not mask the final argument")
				}
			}
			args := map[string]any{"label": float64(n)}
			prepared, err := a.executor().Prepare(tool, args)
			if err != nil {
				t.Fatal("cannot prepare static token fixture")
			}
			if renderForTest(t, tool, args).Body != wantBody || renderForTest(t, tool, args).URL != wantURL {
				t.Fatal("execution render changed the static token or unquoted integer")
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
				if err := a.store.DB().QueryRow(`SELECT preview_display,args_display,final_args_display FROM approvals WHERE id=?`, pending.ID).Scan(&previewJSON, &argsJSON, &finalJSON); err != nil {
					t.Fatal("cannot read stored approval display")
				}
				assertSafe(previewJSON + argsJSON + finalJSON)
				var stored approval.Preview
				if json.Unmarshal([]byte(previewJSON), &stored) != nil {
					t.Fatal("cannot decode stored approval preview")
				}
				assertPreview(stored.Preview)
			}
			assertStored()
			pendingRows := listApprovalAPI(t, handler, origin, "pending")
			if len(pendingRows) != 1 {
				t.Fatal("pending API did not return the approval")
			}
			assertRecord(pendingRows[0])
			preview, err := a.approvals().Preview(pending.ID, pending.Nonce, nil)
			if err != nil {
				t.Fatal("cannot preview pending approval")
			}
			assertPreview(preview.Preview)
			w := approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/approvals/%d/preview", pending.ID), origin, "application/json", map[string]any{"nonce": pending.Nonce})
			assertSafe(w.Body.String())
			var apiPreview approval.Preview
			requireApprovalAPIResponse(t, w, http.StatusOK, &apiPreview)
			assertPreview(apiPreview.Preview)
			if hits.Load() != 0 {
				t.Fatal("request executed before approval")
			}
			approveRecord(t, a, pending)
			if getApprovalReply(t, call).isError || hits.Load() != 1 || !received.Load() {
				t.Fatal("approved target request changed the static token or unquoted integer")
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
