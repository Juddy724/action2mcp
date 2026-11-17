package execution

import (
	"action2mcp/internal/domain"
	"action2mcp/internal/vault"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
)

type approvalRedactionFixture struct {
	configure      func(*Tool)
	args, edits    map[string]any
	private        []string
	secretLabel    bool
	failureText    string
	responseText   string
	checkExecution func(domain.RequestPreview, map[string]any) bool
	checkPrepared  func(*testing.T, *PreparedCall)
	checkResult    func(*testing.T, string)
	checkPreview   func(*testing.T, domain.RequestPreview)
	checkArgs      func(*testing.T, map[string]string)
}

func approvalEncodingFixtures(private string) []string {
	left, right, _ := strings.Cut(private, "/")
	first := fmt.Sprintf(`\u%04x`, left[0]) + left[1:]
	return []string{
		private, left + "%2f" + right, left + "%2F" + right,
		left + "%252f" + right, left + "%252F" + right,
		first + "/" + right, first + `\u002F` + right,
		first + `\u002f` + right, left + `\/` + right,
		url.QueryEscape(private), url.PathEscape(private),
		base64.StdEncoding.EncodeToString([]byte(private)),
	}
}

func TestApprovalFormValueBoundariesOwner(t *testing.T) {
	for _, kind := range []string{"comma", "quoted_suffix", "invalid_escape", "semicolon"} {
		t.Run(kind, func(t *testing.T) {
			left, right := privateTestValue(t), privateTestValue(t)
			value := left + "," + right
			if kind == "quoted_suffix" {
				value = `"` + left + `"` + right
			} else if kind == "invalid_escape" {
				value = left + "%ZZ}" + right
			} else if kind == "semicolon" {
				value = left + ";" + right
			}
			body := "password=" + value + "&note=visible"
			exerciseApprovalRedaction(t, approvalRedactionFixture{
				configure: func(tool *Tool) {
					tool.Params = nil
					tool.Headers["Content-Type"] = "application/x-www-form-urlencoded"
					tool.Body = body
				},
				private:        []string{left, right},
				checkExecution: func(p domain.RequestPreview, _ map[string]any) bool { return p.Body == body },
				checkPreview: func(t *testing.T, p domain.RequestPreview) {
					if p.Body != "password="+vault.Mask+"&note=visible" {
						t.Fatal("form redaction lost the real delimiter or public sibling")
					}
				},
			})
		})
	}
}

func TestApprovalHeaderContainersOwner(t *testing.T) {
	for _, kind := range []string{"json", "url", "plain", "sensitive_json", "sensitive_form", "embedded_query"} {
		t.Run(kind, func(t *testing.T) {
			original, replacement := privateTestValue(t), privateTestValue(t)
			key, value := "X-Meta", `{"password":"{{label}}"}`
			switch kind {
			case "url":
				key, value = "Referer", "https://example.com/?token={{label}}"
			case "plain":
				value = "opaque {{label}}"
			case "sensitive_json":
				key = "Authorization"
			case "sensitive_form":
				key, value = "Authorization", "password={{label}}&note=visible"
			case "embedded_query":
				value = `{"meta":"?token={{label}}&note=visible"}`
			}
			exerciseApprovalRedaction(t, approvalRedactionFixture{
				configure: func(tool *Tool) { tool.Body = ""; tool.Headers[key] = value },
				args:      map[string]any{"label": original}, edits: map[string]any{"label": replacement},
				private: []string{original, replacement}, secretLabel: true,
				checkExecution: func(p domain.RequestPreview, args map[string]any) bool {
					return p.Headers[key] == strings.ReplaceAll(value, "{{label}}", args["label"].(string))
				},
				checkPreview: func(t *testing.T, p domain.RequestPreview) {
					if !strings.Contains(p.Headers[key], vault.Mask) {
						t.Fatal("header preview did not mask its confidential content")
					}
				},
			})
		})
	}
}

func TestApprovalPublicArgumentTextIsVerbatimOwner(t *testing.T) {
	for _, kind := range []string{"json_array", "form", "query", "encoded_form", "double_encoded_form", "command"} {
		t.Run(kind, func(t *testing.T) {
			value := func(note string) string {
				switch kind {
				case "form":
					return "password=visible&note=" + note
				case "query":
					return "?password=visible&note=" + note
				case "encoded_form":
					return url.QueryEscape("password=visible&note=" + note)
				case "double_encoded_form":
					return url.QueryEscape(url.QueryEscape("password=visible&note=" + note))
				case "command":
					return `RUN {"password":"visible","note":"` + note + `"}`
				default:
					return `[{"password":"visible","note":"` + note + `"}]`
				}
			}
			exerciseApprovalRedaction(t, approvalRedactionFixture{
				configure: func(tool *Tool) { tool.Body = `{"data":"{{label}}"}` },
				args:      map[string]any{"label": value("old")}, edits: map[string]any{"label": value("new")},
				checkExecution: func(p domain.RequestPreview, args map[string]any) bool {
					var body map[string]string
					return json.Unmarshal([]byte(p.Body), &body) == nil && body["data"] == args["label"]
				},
				checkPreview: func(t *testing.T, p domain.RequestPreview) {
					var body map[string]string
					if json.Unmarshal([]byte(p.Body), &body) != nil || body["data"] != value("old") && body["data"] != value("new") {
						t.Fatal("public argument preview changed its rendered text")
					}
				},
			})
		})
	}
}

func TestApprovalAmbiguousContainersFailClosedOwner(t *testing.T) {
	for _, kind := range []string{"semicolon", "bad_escape", "fragment_semicolon", "path_escape", "json_garbage", "embedded_garbage"} {
		t.Run(kind, func(t *testing.T) {
			original, replacement := privateTestValue(t), privateTestValue(t)
			exerciseApprovalRedaction(t, approvalRedactionFixture{
				configure: func(tool *Tool) {
					tool.Body = ""
					switch kind {
					case "semicolon":
						tool.URL += "?password={{label}};x"
					case "bad_escape":
						tool.URL += "?password={{label}}%ZZ"
					case "fragment_semicolon":
						tool.URL += "#label={{label}};x"
					case "path_escape":
						// Header URL errors exercise the same parser without making
						// the execution destination itself invalid.
						tool.Headers["Referer"] = "https://example.com/%ZZ/{{label}}"
					case "json_garbage":
						tool.Body = `{"label":"{{label}}"} trailing`
					case "embedded_garbage":
						tool.Body = `{"data":"RUN {\"label\":\"{{label}}\"} trailing"}`
					}
				},
				args: map[string]any{"label": original}, edits: map[string]any{"label": replacement},
				private: []string{original, replacement}, secretLabel: true,
				checkExecution: func(p domain.RequestPreview, args map[string]any) bool {
					return strings.Contains(p.URL+p.Body+p.Headers["Referer"], args["label"].(string))
				},
			})
		})
	}
}

func TestApprovalDuplicateEscapedKeysOwner(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"object", `{"password":"{{label}}","pass\u0077ord":"public"}`},
		{"array", `[{"PASSWORD":"{{label}}","pass\u0077ord":"public"}]`},
		{"embedded", `{"data":"{\"PASSWORD\":\"{{label}}\",\"pass\\u0077ord\":\"public\"}"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			original, replacement := privateTestValue(t), privateTestValue(t)
			exerciseApprovalRedaction(t, approvalRedactionFixture{
				configure: func(tool *Tool) { tool.Body = tc.body },
				args:      map[string]any{"label": original}, edits: map[string]any{"label": replacement},
				private: []string{original, replacement}, secretLabel: true,
				checkExecution: func(p domain.RequestPreview, args map[string]any) bool {
					if tc.name != "embedded" {
						return p.Body == strings.ReplaceAll(tc.body, "{{label}}", args["label"].(string))
					}
					return strings.Contains(p.Body, args["label"].(string)) && strings.Contains(p.Body, "public")
				},
			})
		})
	}
}

func TestApprovalEncodingAwareDisplaysAndErrorsOwner(t *testing.T) {
	private := privateTestValue(t) + "/" + privateTestValue(t)
	variants := approvalEncodingFixtures(private)
	original := strings.Join(variants, " ")
	replacement := "edited " + original
	exerciseApprovalRedaction(t, approvalRedactionFixture{
		configure: func(tool *Tool) { tool.Body = `{"token":"` + private + `","data":"{{label}}"}` },
		args:      map[string]any{"label": original}, edits: map[string]any{"label": replacement},
		private: variants, failureText: original,
		checkExecution: func(p domain.RequestPreview, args map[string]any) bool {
			var body map[string]string
			return json.Unmarshal([]byte(p.Body), &body) == nil && body["token"] == private && body["data"] == args["label"]
		},
	})
}

func TestApprovalStaticTemplateLiteralsOwner(t *testing.T) {
	for _, kind := range []string{"query", "fragment", "header", "header_json", "header_url", "body", "nested", "sensitive_nested", "embedded_form", "form"} {
		t.Run(kind, func(t *testing.T) {
			private := privateTestValue(t)
			exerciseApprovalRedaction(t, approvalRedactionFixture{
				configure: func(tool *Tool) {
					tool.Params, tool.Body = nil, ""
					tool.URL = "https://example.com/x"
					switch kind {
					case "query":
						tool.URL += "?token=" + private
					case "fragment":
						tool.URL += "#token=" + private
					case "header":
						tool.Headers["Authorization"] = "Bearer " + private
					case "header_json":
						tool.Headers["X-Meta"] = `{"token":"` + private + `"}`
					case "header_url":
						tool.Headers["Referer"] = "https://example.com/?token=" + private
					case "body":
						tool.Body = `{"token":"` + private + `"}`
					case "nested", "sensitive_nested":
						key := "data"
						if kind == "sensitive_nested" {
							key = "credentials"
						}
						tool.Body = string(CompactJSON(map[string]string{key: `RUN {"password":"` + private + `"}`}))
					case "embedded_form":
						tool.Body = string(CompactJSON(map[string]string{"data": "password=" + private + "&note=visible"}))
					case "form":
						tool.Headers["Content-Type"] = "application/x-www-form-urlencoded"
						tool.Body = "password=" + private + "&note=visible"
					}
				},
				private: []string{private}, failureText: "request failed: " + private,
				checkExecution: func(p domain.RequestPreview, _ map[string]any) bool {
					return strings.Contains(p.URL+p.Body+p.Headers["Authorization"]+p.Headers["X-Meta"]+p.Headers["Referer"], private)
				},
			})
		})
	}
}
func TestApprovalWhitespaceUserinfoContainersOwner(t *testing.T) {
	for _, scheme := range []string{"http", "https", "ws", "wss", "odd+transport", "odd_scheme"} {
		for _, source := range []string{"header", "embedded_header", "body", "json_body", "query"} {
			for _, template := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/template_%t", scheme, source, template), func(t *testing.T) {
					private := privateTestValue(t)
					raw := " \t" + scheme + "://demo:" + private + "@example.com/api \t"
					masked := strings.Replace(raw, private, vault.Mask, 1)
					wireText := func(p domain.RequestPreview) string {
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
								tool.Body = string(CompactJSON(map[string]string{"target": value}))
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
						checkExecution: func(p domain.RequestPreview, _ map[string]any) bool {
							want := raw
							if source == "embedded_header" {
								want = "connect" + raw + "next"
							}
							return wireText(p) == want
						},
						checkPreview: func(t *testing.T, p domain.RequestPreview) {
							want := masked
							if source == "embedded_header" {
								want = "connect" + masked + "next"
							}
							// Query masks use the same URL encoding as
							if wireText(p) != want {
								t.Fatal("userinfo masking changed surrounding whitespace or text")
							}
						},
						checkResult: func(t *testing.T, result string) {
							if !strings.Contains(result, "demo:"+vault.Mask+"@") {
								t.Fatal("userinfo error or history lost its password mask")
							}
						},
					})
				})
			}
		}
	}
}
func TestApprovalStaticSecretBesidePlaceholderOwner(t *testing.T) {
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
				checkExecution: func(p domain.RequestPreview, args map[string]any) bool {
					return strings.Contains(p.Body+p.Headers["Authorization"]+p.Headers["X-Target"], static+domain.ArgumentText(args["label"]))
				},
			})
		})
	}
}
func privateTestValue(t *testing.T) string {
	t.Helper()
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal("cannot create test value")
	}
	return hex.EncodeToString(b[:])
}
func wrapApprovalJSONDepth(inner string, depth int) string {
	return strings.Repeat("[", depth) + inner + strings.Repeat("]", depth)
}

func exerciseApprovalRedaction(t *testing.T, f approvalRedactionFixture) {
	t.Helper()
	e := New(Options{})
	tool := &Tool{Method: "POST", URL: "https://example.com/api", Headers: map[string]string{"Content-Type": "application/json"}, Params: []domain.Param{{Name: "label", Type: "string", Required: true}}}
	f.configure(tool)
	for _, args := range []map[string]any{f.args, f.edits} {
		if args == nil {
			continue
		}
		p, err := e.Prepare(tool, args)
		if err != nil {
			t.Fatal(err)
		}
		if !f.checkExecution(p.request, args) {
			t.Fatal("redaction changed a raw execution value")
		}
		if f.checkPrepared != nil {
			f.checkPrepared(t, p)
		}
		if f.checkPreview != nil {
			f.checkPreview(t, p.Preview)
		}
		for _, private := range f.private {
			if strings.Contains(string(CompactJSON(p.Preview)), private) {
				t.Fatal("preview leaked private value")
			}
		}
		if f.checkArgs != nil {
			f.checkArgs(t, e.ApprovalArgs(tool, args, nil))
		}
	}
}

func requirePrivateApprovalValuesAbsent(t *testing.T, value any, privateValues ...string) {
	t.Helper()
	text := string(CompactJSON(value))
	for _, private := range privateValues {
		if strings.Contains(text, private) {
			t.Fatal("approval output leaked a private value")
		}
	}
}
