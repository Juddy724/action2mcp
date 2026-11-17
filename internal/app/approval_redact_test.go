package app

import (
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
			tool.Params = []Param{{Name: "label", Type: "integer", Required: true}}
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
				text := string(compactJSON(value))
				if strings.Contains(text, token) || strings.Contains(text, label) {
					t.Fatal("approval display leaked a private value")
				}
			}
			assertPreview := func(preview RequestPreview) {
				t.Helper()
				assertSafe(preview)
				if kind == "json" {
					var body map[string]any
					if json.Unmarshal([]byte(preview.Body), &body) != nil || body["password"] != secretMask || body["token"] != secretMask {
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
				if err != nil || values.Get("password") != secretMask || values.Get("token") != secretMask {
					t.Fatal("preview must mask both sensitive assignments")
				}
			}
			assertRecord := func(record ApprovalRecord) {
				t.Helper()
				assertSafe(record)
				assertPreview(record.Preview)
				if record.ArgsDisplay["label"] != secretMask || len(record.Params) != 1 || !record.Params[0].Secret {
					t.Fatal("approval card did not mask the renamed secret argument")
				}
				if record.Status != "pending" && record.FinalArgsDisplay["label"] != secretMask {
					t.Fatal("approval history did not mask the final argument")
				}
			}
			args := map[string]any{"label": float64(n)}
			prepared, err := a.Prepare(tool, args)
			if err != nil {
				t.Fatal("cannot prepare static token fixture")
			}
			if prepared.request.Body != wantBody || prepared.request.URL != wantURL {
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
				if err := a.store.db.QueryRow(`SELECT preview_display,args_display,final_args_display FROM approvals WHERE id=?`, pending.ID).Scan(&previewJSON, &argsJSON, &finalJSON); err != nil {
					t.Fatal("cannot read stored approval display")
				}
				assertSafe(previewJSON + argsJSON + finalJSON)
				var stored ApprovalPreview
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
			preview, err := a.PreviewApproval(pending.ID, pending.Nonce, nil)
			if err != nil {
				t.Fatal("cannot preview pending approval")
			}
			assertPreview(preview.Preview)
			w := approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/approvals/%d/preview", pending.ID), origin, "application/json", map[string]any{"nonce": pending.Nonce})
			assertSafe(w.Body.String())
			var apiPreview ApprovalPreview
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

func TestPreparedJSONMaskQuoting(t *testing.T) {
	a := approvalTestApp(t)
	for _, tc := range []struct {
		name, body, want string
	}{
		{"unquoted", `{"value":{{label}}}`, `{"value":42}`},
		{"array", `[{{label}}]`, `[42]`},
		{"quoted", `{"value":"{{label}}"}`, `{"value":42}`},
		{"inline", `{"value":"prefix {{label}} suffix"}`, `{"value":"prefix 42 suffix"}`},
		{"escaped", `{"value":"escaped \" quote {{label}} suffix"}`, `{"value":"escaped \" quote 42 suffix"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tool := &Tool{Method: "POST", URL: "https://example.com/", Body: tc.body,
				Params: []Param{{Name: "label", Type: "integer", Required: true, Secret: true}}}
			prepared, err := a.Prepare(tool, map[string]any{"label": 42})
			if err != nil || !json.Valid([]byte(prepared.Preview.Body)) || !strings.Contains(prepared.Preview.Body, secretMask) {
				t.Fatal("mask substitution broke preview JSON")
			}
			if prepared.request.Body != tc.want {
				t.Fatal("preview mask quoting changed execution rendering")
			}
		})
	}
}

func TestRedactPreviewMalformedAssignments(t *testing.T) {
	secret := privateTestValue(t)
	escaped := string(compactJSON(secret + `\"&,;`))
	cases := []struct {
		name, body, contentType, want string
	}{
		{"bare_mask", `{"password":******,"token":"` + secret + `"}`, "application/json", `{"password":"******","token":"******"}`},
		{"json_like", `{password:` + secret + `,token:'` + secret + `',note:'visible'}`, "", `{password:"******",token:'******',note:'visible'}`},
		{"assignments", `password="` + secret + `";token=` + secret + `&note=visible`, "text/plain", `password="******";token=******&note=visible`},
		{"escaped_value", `{"broken":,"token":` + escaped + `,"note":"visible"}`, "application/json", `{"broken":,"token":"******","note":"visible"}`},
		{"truncated", `{"password":"` + secret, "application/json", `{"password":"******"`},
		{"composite", `{credentials:{value:'` + secret + `',note:'visible'},broken:}`, "", `{credentials:"******",broken:}`},
		{"form", "password=" + secret + "&token=" + secret, "application/x-www-form-urlencoded", "password=******&token=******"},
		{"encoded_form_key", "p%61ssword=" + secret + "&t%6fken=" + secret, "application/x-www-form-urlencoded", "p%61ssword=******&t%6fken=******"},
		{"untyped_form", "password=" + secret + "&token=" + secret, "", "password=******&token=******"},
		{"placeholders", `{"broken":,"password":{{secret.saved}},"token":"{{cfg.saved}}"}`, "", `{"broken":,"password":"{{secret.saved}}","token":"{{cfg.saved}}"}`},
		{"quoted_non_key", `{"note":"password=` + secret + `,token=` + secret + `",broken:}`, "", `{"note":"password=` + secret + `,token=` + secret + `",broken:}`},
		{"unquoted_non_key", "note=password=" + secret, "", "note=password=" + secret},
		{"form_non_key", "note=password=" + secret, "application/x-www-form-urlencoded", "note=password=" + secret},
		{"excluded_key", `{"passwordStrength":"` + secret + `",broken:}`, "", `{"passwordStrength":"` + secret + `",broken:}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			preview := redactPreview(RequestPreview{Body: tc.body, Headers: map[string]string{"Content-Type": tc.contentType}})
			if preview.Body != tc.want {
				t.Fatal("lexical redaction missed a sensitive assignment or changed a non-key value")
			}
		})
	}
	for _, prefix := range []string{"", "RUN "} {
		body := string(compactJSON(map[string]any{"inner": prefix + `{"password":******,"token":"` + secret + `"}`}))
		preview := redactPreview(RequestPreview{Body: body})
		var outer map[string]string
		var inner map[string]string
		if json.Unmarshal([]byte(preview.Body), &outer) != nil || json.Unmarshal([]byte(strings.TrimPrefix(outer["inner"], prefix)), &inner) != nil || inner["password"] != secretMask || inner["token"] != secretMask {
			t.Fatal("nested malformed JSON retained sensitive values")
		}
	}
}
