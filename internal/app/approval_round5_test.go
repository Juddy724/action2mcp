package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestApprovalVerbatimWholeParam(t *testing.T) {
	renderBody := func(text string) string {
		value, _ := json.Marshal(text)
		return `{"data":` + string(value) + `}`
	}
	for _, value := range []struct{ name, text string }{
		{"json", `{"note":"old","id":" 123 "}`},
		{"scalar", " 123 "},
		{"form", "note=old&id=+123+&password=visible"},
		{"mask_literal", `{"note":"old","id":" 123 ","literal":"prefix******suffix"}`},
		{"encoded_mask", "note=old&id=%252A%252A%252A%252A%252A%252A"},
	} {
		for _, action := range []string{"approve", "edit"} {
			t.Run(value.name+"/"+action, func(t *testing.T) {
				a := approvalTestApp(t)
				a.cfg.Port = 19000
				const origin = "http://127.0.0.1:19000"
				want := value.text
				if action == "edit" {
					want = strings.ReplaceAll(want, "old", "new")
				}
				wantBody := renderBody(want)
				var received atomic.Bool
				var hits atomic.Int32
				upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, err := io.ReadAll(r.Body)
					received.Store(err == nil && string(body) == wantBody)
					hits.Add(1)
					io.WriteString(w, "ok")
				}))
				tool, _ := saveApprovalTool(t, a, upstream, "always")
				tool.Body = `{"data":"{{label}}"}`
				tool.Params = []Param{{Name: "label", Type: "string", Required: true}}
				if a.store.SaveTool(tool) != nil {
					t.Fatal("cannot save verbatim argument fixture")
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				call := startApprovalCall(a, ctx, map[string]any{"label": value.text, "untouched": "original"})
				pending := pendingApprovals(t, a, 1)[0]
				if pending.Params[0].Secret || pending.ArgsDisplay["label"] != value.text || pending.Preview.Body != renderBody(value.text) {
					t.Fatal("approval card or preview changed public argument bytes")
				}
				var args map[string]any
				if action == "edit" {
					args = map[string]any{"label": want}
				}
				handler := a.Handler()
				w := approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/approvals/%d/preview", pending.ID), origin, "application/json", map[string]any{"nonce": pending.Nonce, "args": args})
				var preview ApprovalPreview
				requireApprovalAPIResponse(t, w, http.StatusOK, &preview)
				if preview.Preview.Body != wantBody || hits.Load() != 0 {
					t.Fatal("confirmed preview changed argument bytes or executed the request")
				}
				if value.name == "json" && action == "edit" {
					otherArgs := map[string]any{"label": strings.Replace(want, `" 123 "`, `"123"`, 1)}
					other, err := a.PreviewApproval(pending.ID, pending.Nonce, otherArgs)
					if err != nil || other.PreviewHash == preview.PreviewHash {
						t.Fatal("preview hash did not bind the exact argument whitespace")
					}
					requireApprovalStatus(t, a.DecideApproval(pending.ID, pending.Nonce, "edit", otherArgs, "", preview.PreviewHash), http.StatusConflict)
					if hits.Load() != 0 {
						t.Fatal("request with a mismatched preview hash executed")
					}
				}
				w = approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/approvals/%d/decide", pending.ID), origin, "application/json", map[string]any{"nonce": pending.Nonce, "action": action, "args": args, "preview_hash": preview.PreviewHash})
				requireApprovalAPIResponse(t, w, http.StatusOK, nil)
				if getApprovalReply(t, call).isError || hits.Load() != 1 || !received.Load() {
					t.Fatal("send did not match the byte-faithful confirmed preview")
				}
				history := listApprovalAPI(t, handler, origin, "all")
				if len(history) != 1 || history[0].ArgsDisplay["label"] != value.text || history[0].FinalArgsDisplay["label"] != want || history[0].FinalArgsDisplay["untouched"] != "original" || history[0].Preview.Body != wantBody {
					t.Fatal("approval history changed a whole parameter or lost an untouched parameter")
				}
				var originalJSON, finalJSON string
				var originalArgs, finalArgs map[string]string
				if a.store.db.QueryRow(`SELECT args_display,final_args_display FROM approvals WHERE id=?`, pending.ID).Scan(&originalJSON, &finalJSON) != nil || json.Unmarshal([]byte(originalJSON), &originalArgs) != nil || json.Unmarshal([]byte(finalJSON), &finalArgs) != nil || originalArgs["label"] != value.text || finalArgs["label"] != want {
					t.Fatal("persisted argument displays changed the original or submitted text")
				}
			})
		}
	}
}

func TestApprovalWholeParamReplacement(t *testing.T) {
	a := approvalTestApp(t)
	tool := &Tool{Body: `{"data":"{{label}}"}`, Params: []Param{{Name: "label", Type: "string"}}}
	for _, tc := range []struct{ original, edit any }{
		{`{"note":"old","retained":true}`, `{"note":"new"}`},
		{"note=old&retained=visible", "note=new"},
		{map[string]any{"note": "old", "retained": true}, map[string]any{"note": "new"}},
		{[]any{"old", "retained"}, []any{"new"}},
		{map[string]any{"note": "old"}, ` {"note":"new","id":" 123 "} `},
	} {
		p := &pendingApproval{tool: tool, args: map[string]any{"label": tc.original, "untouched": "original"}}
		merged, err := a.editApprovalArgs(p, map[string]any{"label": tc.edit})
		if err != nil || !reflect.DeepEqual(merged["label"], tc.edit) || merged["untouched"] != "original" {
			t.Fatal("whole-parameter replacement retained a subpath or rewrote submitted text")
		}
	}
}

func TestApprovalWholeSecretParameter(t *testing.T) {
	for _, kind := range []string{"mask", "unchanged_marker", "replace", "reject_embedded_mask"} {
		t.Run(kind, func(t *testing.T) {
			a := approvalTestApp(t)
			a.cfg.Port = 19000
			const origin = "http://127.0.0.1:19000"
			original, replacement := privateTestValue(t), privateTestValue(t)
			want := original
			edit := secretMask
			switch kind {
			case "unchanged_marker":
				edit = ApprovalSecretUnchanged
			case "replace", "reject_embedded_mask":
				edit, want = replacement, replacement
			}
			var hits atomic.Int32
			var received atomic.Bool
			upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]string
				received.Store(json.NewDecoder(r.Body).Decode(&body) == nil && body["data"] == want)
				hits.Add(1)
				io.WriteString(w, want)
			}))
			tool, _ := saveApprovalTool(t, a, upstream, "always")
			tool.Body = `{"data":"{{label}}"}`
			tool.Params = []Param{{Name: "label", Type: "string", Required: true, Secret: true}}
			if a.store.SaveTool(tool) != nil {
				t.Fatal("cannot save whole-secret fixture")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			call := startApprovalCall(a, ctx, map[string]any{"label": original})
			pending := pendingApprovals(t, a, 1)[0]
			if pending.ArgsDisplay["label"] != secretMask {
				t.Fatal("secret argument was not wholly masked")
			}
			handler := a.Handler()
			if kind == "reject_embedded_mask" {
				for _, invalid := range []any{"prefix" + secretMask, secretMask + "suffix", `{"password":"******","note":"new"}`, map[string]any{"nested": secretMask}} {
					for _, endpoint := range []string{"preview", "decide"} {
						w := approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/approvals/%d/%s", pending.ID, endpoint), origin, "application/json", map[string]any{"nonce": pending.Nonce, "args": map[string]any{"label": invalid}, "action": "edit", "preview_hash": pending.PreviewHash})
						requireApprovalAPIResponse(t, w, http.StatusBadRequest, nil)
						requirePrivateApprovalValuesAbsent(t, w.Body.String(), original, replacement)
					}
				}
				if hits.Load() != 0 || len(pendingApprovals(t, a, 1)) != 1 {
					t.Fatal("invalid secret edit executed or ended the pending call")
				}
			}
			args := map[string]any{"label": edit}
			preview, err := a.PreviewApproval(pending.ID, pending.Nonce, args)
			if err != nil {
				t.Fatal("whole-secret preview failed")
			}
			if kind == "mask" || kind == "unchanged_marker" {
				if preview.PreviewHash != pending.PreviewHash {
					t.Fatal("unchanged secret marker changed the bound request")
				}
			} else if preview.PreviewHash == pending.PreviewHash {
				t.Fatal("replacement secret did not change the bound request")
			}
			if a.DecideApproval(pending.ID, pending.Nonce, "edit", args, "", preview.PreviewHash) != nil {
				t.Fatal("whole-secret decision failed")
			}
			reply := getApprovalReply(t, call)
			requirePrivateApprovalValuesAbsent(t, reply.text, original, replacement)
			if reply.isError || hits.Load() != 1 || !received.Load() {
				t.Fatal("whole-secret edit sent the wrong complete value")
			}
			history := listApprovalAPI(t, handler, origin, "all")
			requirePrivateApprovalValuesAbsent(t, history, original, replacement)
			if len(history) != 1 || history[0].FinalArgsDisplay["label"] != secretMask {
				t.Fatal("whole-secret history did not retain the wholesale mask")
			}
		})
	}
}

func TestApprovalBase64SubstringOutputs(t *testing.T) {
	// The suffix creates both alphabet differences and actual padding.
	private := privateTestValue(t) + "/ab\uffffx"
	for _, encoding := range []struct {
		name string
		enc  *base64.Encoding
	}{
		{"std", base64.StdEncoding}, {"raw_std", base64.RawStdEncoding},
		{"url", base64.URLEncoding}, {"raw_url", base64.RawURLEncoding},
	} {
		for _, suffix := range []struct{ name, text string }{{"bare", ""}, {"comma", ","}, {"junk", "xyz!"}} {
			for _, failure := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/failure_%t", encoding.name, suffix.name, failure), func(t *testing.T) {
					encoded := encoding.enc.EncodeToString([]byte(private))
					original := encoded + suffix.text
					failureText := ""
					if failure {
						failureText = "failed for " + original
					}
					exerciseApprovalRedaction(t, approvalRedactionFixture{
						configure: func(tool *Tool) { tool.Body = `{"token":"` + private + `","data":"{{label}}"}` },
						args:      map[string]any{"label": original}, edits: map[string]any{"label": "edited " + original},
						private: []string{private, encoded}, responseText: "before " + original + " after", failureText: failureText,
						checkArgs: func(t *testing.T, args map[string]string) {
							if args["label"] != original && args["label"] != "edited "+original {
								t.Fatal("public base64 argument was not displayed verbatim")
							}
						},
						checkExecution: func(p RequestPreview, args map[string]any) bool {
							var body map[string]string
							return json.Unmarshal([]byte(p.Body), &body) == nil && body["token"] == private && body["data"] == args["label"]
						},
						checkResult: func(t *testing.T, result string) {
							if result != "HTTP 200" && !strings.Contains(result, secretMask+suffix.text) {
								t.Fatal("base64 substring scrub lost the mask or trailing text")
							}
						},
					})
				})
			}
		}
	}
}

func TestApprovalURLUserinfoDisplaysAndErrors(t *testing.T) {
	for _, scheme := range []string{"http", "https", "ws", "wss", "odd+transport", "odd_scheme"} {
		for _, source := range []string{"static", "template", "header_static", "header_template"} {
			if scheme == "odd_scheme" && !strings.HasPrefix(source, "header_") {
				continue // net/http rejects this scheme before invoking the transport.
			}
			for _, failure := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/failure_%t", scheme, source, failure), func(t *testing.T) {
					private := privateTestValue(t)
					rawURL := scheme + "://demo:" + private + "@example.com/api"
					template := strings.HasSuffix(source, "template")
					header := strings.HasPrefix(source, "header_")
					failureText := ""
					if failure {
						failureText = "request failed for " + rawURL
					}
					exerciseApprovalRedaction(t, approvalRedactionFixture{
						configure: func(tool *Tool) {
							value := rawURL
							if template {
								value = scheme + "://demo:{{label}}@example.com/api"
							}
							tool.Body = `{"note":"visible"}`
							if header {
								tool.Headers["X-Target"] = "connect " + value + " next"
							} else {
								tool.URL = value
							}
						},
						args: map[string]any{"label": private}, private: []string{private}, secretLabel: template, failureText: failureText,
						checkPrepared: func(t *testing.T, p *PreparedCall) {
							if !slices.Contains(p.secretValues, private) {
								t.Fatal("URL userinfo password was not collected for error scrubbing")
							}
						},
						checkResult: func(t *testing.T, result string) {
							if failure && !strings.Contains(result, "demo:"+secretMask+"@") {
								t.Fatal("URL userinfo error lost the username or password mask")
							}
						},
						checkExecution: func(p RequestPreview, _ map[string]any) bool {
							if header {
								return strings.Contains(p.Headers["X-Target"], rawURL)
							}
							return p.URL == rawURL
						},
						checkPreview: func(t *testing.T, p RequestPreview) {
							value := p.URL
							if header {
								value = p.Headers["X-Target"]
							}
							if !strings.Contains(value, "demo:"+secretMask+"@") {
								t.Fatal("URL userinfo preview lost the username or password mask")
							}
						},
					})
				})
			}
		}
	}
}

func TestApprovalContainerResourceBounds(t *testing.T) {
	a := approvalTestApp(t)
	private := privateTestValue(t)
	for _, tc := range []struct{ name, body string }{
		{"deep_array", strings.Repeat("[", 60000) + `{"password":"` + private + `","label":"{{label}}"}` + strings.Repeat("]", 60000)},
		{"wide_array", "[" + strings.Repeat("0,", 60000) + `{"password":"` + private + `","label":"{{label}}"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tool := &Tool{Method: "POST", URL: "https://example.com/api", Body: tc.body, Params: []Param{{Name: "label", Type: "string"}}}
			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			start := time.Now()
			preview := redactPreview(RequestPreview{Body: tc.body})
			prepared, err := a.Prepare(tool, map[string]any{"label": private})
			secret := paramIsSecret(tool, tool.Params[0])
			display := a.approvalArgs(tool, map[string]any{"label": private}, nil)
			elapsed := time.Since(start)
			runtime.ReadMemStats(&after)
			if elapsed >= 2*time.Second {
				t.Fatal("bounded approval analysis exceeded two seconds")
			}
			allocated := after.TotalAlloc - before.TotalAlloc
			if allocated > 64<<20 {
				t.Fatal("bounded approval analysis exceeded its allocation allowance")
			}
			if err != nil || !secret || preview.Body != secretMask || prepared.Preview.Body != secretMask || display["label"] != secretMask {
				t.Fatal("over-limit approval container did not fail closed")
			}
			requirePrivateApprovalValuesAbsent(t, prepared.Preview, private)
			t.Logf("analysis took %s and allocated %.1f MiB", elapsed, float64(allocated)/(1<<20))
		})
	}
}

func TestApprovalHTMLLookaheadResourceBound(t *testing.T) {
	a := approvalTestApp(t)
	private := privateTestValue(t) + `<&"`
	text := strings.Repeat("&", 160000)
	start := time.Now()
	got := a.scrubApprovalText(text, []string{private})
	elapsed := time.Since(start)
	if elapsed >= time.Second {
		t.Fatal("HTML lookahead exceeded one second on unterminated entities")
	}
	if got != text {
		t.Fatal("unterminated entities changed during scrubbing")
	}
	if a.scrubApprovalText("before "+html.EscapeString(private)+" after", []string{private}) != "before "+secretMask+" after" {
		t.Fatal("bounded HTML entity scrubbing missed a private value")
	}
	t.Logf("unterminated HTML scan took %s", elapsed)
}
