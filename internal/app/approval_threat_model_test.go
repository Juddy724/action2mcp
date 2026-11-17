package app

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

func TestApprovalWhitespaceUserinfoContainers(t *testing.T) {
	for _, scheme := range []string{"http", "https", "ws", "wss", "odd+transport", "odd_scheme"} {
		for _, source := range []string{"header", "embedded_header", "body", "json_body", "query"} {
			for _, template := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/template_%t", scheme, source, template), func(t *testing.T) {
					private := privateTestValue(t)
					raw := " \t" + scheme + "://demo:" + private + "@example.com/api \t"
					masked := strings.Replace(raw, private, secretMask, 1)
					wireText := func(p RequestPreview) string {
						switch source {
						case "header", "embedded_header":
							return p.Headers["X-Target"]
						case "json_body":
							var body map[string]string
							if json.Unmarshal([]byte(p.Body), &body) == nil {
								return body["target"]
							}
						case "query":
							if u, err := url.Parse(p.URL); err == nil {
								return u.Query().Get("target")
							}
						default:
							return p.Body
						}
						return ""
					}
					exerciseApprovalRedaction(t, approvalRedactionFixture{
						configure: func(tool *Tool) {
							value := raw
							if template {
								value = strings.Replace(raw, private, "{{label}}", 1)
							}
							tool.Body = ""
							switch source {
							case "header":
								tool.Headers["X-Target"] = value
							case "embedded_header":
								tool.Headers["X-Target"] = "connect" + value + "next"
							case "json_body":
								tool.Body = string(compactJSON(map[string]string{"target": value}))
							case "query":
								tool.URL += "?target=" + strings.ReplaceAll(url.QueryEscape(value), url.QueryEscape("{{label}}"), "{{label}}")
							default:
								tool.Headers["Content-Type"] = "text/plain"
								tool.Body = value
							}
						},
						args: map[string]any{"label": private}, private: []string{private}, secretLabel: template,
						failureText: "request failed: " + raw,
						checkPrepared: func(t *testing.T, p *PreparedCall) {
							if !slices.Contains(p.secretValues, private) {
								t.Fatal("whitespace userinfo password was not collected")
							}
						},
						checkExecution: func(p RequestPreview, _ map[string]any) bool {
							want := raw
							if source == "embedded_header" {
								want = "connect" + raw + "next"
							}
							return wireText(p) == want
						},
						checkPreview: func(t *testing.T, p RequestPreview) {
							want := masked
							if source == "embedded_header" {
								want = "connect" + masked + "next"
							}
							// Query masks use the same URL encoding as execution.
							if wireText(p) != want {
								t.Fatal("userinfo masking changed surrounding whitespace or text")
							}
						},
						checkResult: func(t *testing.T, result string) {
							if !strings.Contains(result, "demo:"+secretMask+"@") {
								t.Fatal("userinfo error or history lost its password mask")
							}
						},
					})
				})
			}
		}
	}
}

func TestApprovalWhitespaceToolURL(t *testing.T) {
	for _, scheme := range []string{"http", "https", "ws", "wss", "odd+transport", "odd_scheme"} {
		t.Run(scheme, func(t *testing.T) {
			a := approvalTestApp(t)
			a.cfg.Port = 19000
			private := privateTestValue(t)
			raw := " " + scheme + "://demo:" + private + "@example.com/api "
			var hits atomic.Int32
			upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); io.WriteString(w, "ok") }))
			tool, _ := saveApprovalTool(t, a, upstream, "always")
			tool.URL, tool.Body, tool.Params = raw, "", nil
			if a.store.SaveTool(tool) != nil {
				t.Fatal("cannot save whitespace URL fixture")
			}
			p, err := a.Prepare(tool, nil)
			if err != nil || p.request.URL != raw || !slices.Contains(p.secretValues, private) || p.Preview.URL != strings.Replace(raw, private, secretMask, 1) {
				t.Fatal("whitespace tool URL was changed or its password was not masked")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			call := startApprovalCall(a, ctx, nil)
			pending := pendingApprovals(t, a, 1)[0]
			requirePrivateApprovalValuesAbsent(t, pending, private)
			approveRecord(t, a, pending)
			reply := getApprovalReply(t, call)
			requirePrivateApprovalValuesAbsent(t, reply.text, private)
			// net/http rejects the raw surrounding whitespace; approval must not
			// silently trim the execution URL to make it sendable.
			if !reply.isError || hits.Load() != 0 || !strings.Contains(reply.text, "demo:"+secretMask+"@") {
				t.Fatal("raw whitespace URL was normalized or its error was not masked")
			}
			history, err := a.ListApprovals("all", 100)
			requirePrivateApprovalValuesAbsent(t, history, private)
			if err != nil || len(history) != 1 || history[0].Preview.URL != p.Preview.URL || !strings.Contains(history[0].Result, "demo:"+secretMask+"@") {
				t.Fatal("whitespace URL history lost the preview or scrubbed error")
			}
		})
	}
}

func TestApprovalPublicMaskTokenIsLiteral(t *testing.T) {
	a := approvalTestApp(t)
	for _, body := range []string{`{"data":{{label}}}`, `{"data":"{{label}}"}`, "label={{label}}"} {
		tool := &Tool{Method: "POST", URL: "https://example.com/api?label={{label}}", Body: body, Params: []Param{{Name: "label", Type: "string"}}}
		p, err := a.Prepare(tool, map[string]any{"label": secretMask})
		if err != nil || p.Preview.Body != p.request.Body || p.Preview.URL != p.request.URL || a.approvalArgs(tool, map[string]any{"label": secretMask}, nil)["label"] != secretMask {
			t.Fatal("public mask literal changed during preview rendering")
		}
	}
}

func TestApprovalStaticSecretBesidePlaceholder(t *testing.T) {
	for _, kind := range []string{"json", "form", "header", "userinfo"} {
		t.Run(kind, func(t *testing.T) {
			static, original, replacement := privateTestValue(t), privateTestValue(t), privateTestValue(t)
			exerciseApprovalRedaction(t, approvalRedactionFixture{
				configure: func(tool *Tool) {
					value := static + "{{label}}"
					switch kind {
					case "form":
						tool.Headers["Content-Type"] = "application/x-www-form-urlencoded"
						tool.Body = "password=" + value
					case "header":
						tool.Body = ""
						tool.Headers["Authorization"] = "Bearer " + value
					case "userinfo":
						tool.Body = ""
						tool.Headers["X-Target"] = " https://demo:" + value + "@example.com/api"
					default:
						tool.Body = `{"password":"` + value + `"}`
					}
				},
				args: map[string]any{"label": original}, edits: map[string]any{"label": replacement},
				private: []string{static, original, replacement}, secretLabel: true, failureText: "failed: " + static + replacement,
				checkPrepared: func(t *testing.T, p *PreparedCall) {
					if !slices.Contains(p.secretValues, static) && !slices.Contains(p.secretValues, "Bearer "+static) {
						t.Fatal("static portion of a sensitive template scalar was not collected")
					}
				},
				checkExecution: func(p RequestPreview, args map[string]any) bool {
					return strings.Contains(p.Body+p.Headers["Authorization"]+p.Headers["X-Target"], static+argString(args["label"]))
				},
			})
		})
	}
}
