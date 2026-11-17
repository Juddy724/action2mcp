package app

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

type approvalRedactionFixture struct {
	configure      func(*Tool)
	args, edits    map[string]any
	private        []string
	secretLabel    bool
	failureText    string
	responseText   string
	checkExecution func(RequestPreview, map[string]any) bool
	checkPrepared  func(*testing.T, *PreparedCall)
	checkResult    func(*testing.T, string)
	checkPreview   func(*testing.T, RequestPreview)
	checkArgs      func(*testing.T, map[string]string)
}

// Exercise every persisted and user-visible surface with the same fixture, and
// compare the actual approved HTTP request privately against its execution render.
func exerciseApprovalRedaction(t *testing.T, f approvalRedactionFixture) {
	t.Helper()
	a := approvalTestApp(t)
	a.cfg.Port = 19000
	const origin = "http://127.0.0.1:19000"
	var received atomic.Bool
	var hits atomic.Int32
	var want RequestPreview
	checkWire := func(r *http.Request) {
		var body []byte
		var err error
		if r.Body != nil {
			body, err = io.ReadAll(r.Body)
		}
		valid := err == nil && r.Method == want.Method && r.URL.String() == want.URL && string(body) == want.Body
		for key, value := range want.Headers {
			valid = valid && r.Header.Get(key) == value
		}
		received.Store(valid)
		hits.Add(1)
	}
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checkWire(r)
		if f.responseText != "" {
			w.Header().Set("X-Echo", f.responseText)
			io.WriteString(w, f.responseText)
		} else {
			io.WriteString(w, "ok")
		}
	}))
	tool, _ := saveApprovalTool(t, a, upstream, "always")
	tool.Params = []Param{{Name: "label", Type: "string", Required: true}}
	f.configure(tool)
	if f.failureText != "" {
		a.httpClient = &http.Client{Transport: approvalRoundTripper(func(r *http.Request) (*http.Response, error) {
			checkWire(r)
			return nil, &net.OpError{Op: "dial", Net: "tcp", Err: fmt.Errorf("%w: %s", syscall.ECONNREFUSED, f.failureText)}
		})}
	}
	for _, p := range tool.Params {
		if p.Name == "label" && paramIsSecret(tool, p) != f.secretLabel {
			t.Fatal("template sensitivity classification is incorrect")
		}
	}
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal("cannot save redaction fixture")
	}
	assertSafe := func(value any) {
		t.Helper()
		requirePrivateApprovalValuesAbsent(t, value, f.private...)
		text := string(compactJSON(value))
		for _, private := range f.private {
			escaped := string(compactJSON(private))
			if strings.Contains(text, escaped[1:len(escaped)-1]) {
				t.Fatal("approval output leaked an encoded private value")
			}
		}
	}
	assertPreview := func(preview RequestPreview) {
		t.Helper()
		assertSafe(preview)
		if f.checkPreview != nil {
			f.checkPreview(t, preview)
		}
	}
	prepare := func(args map[string]any) *PreparedCall {
		t.Helper()
		p, err := a.Prepare(tool, args)
		if err != nil {
			t.Fatal("cannot prepare redaction fixture")
		}
		if !f.checkExecution(p.request, args) {
			t.Fatal("redaction changed a raw execution value")
		}
		if f.checkPrepared != nil {
			f.checkPrepared(t, p)
		}
		assertPreview(p.Preview)
		return p
	}
	prepare(f.args)
	finalArgs := f.args
	action := "approve"
	if f.edits != nil {
		finalArgs, action = f.edits, "edit"
	}
	want = prepare(finalArgs).request
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	call := startApprovalCall(a, ctx, f.args)
	pending := pendingApprovals(t, a, 1)[0]
	assertRecord := func(record ApprovalRecord) {
		t.Helper()
		// Public arguments are already known to the caller and remain verbatim.
		safeRecord := record
		safeRecord.ArgsDisplay, safeRecord.FinalArgsDisplay = nil, nil
		assertSafe(safeRecord)
		assertPreview(record.Preview)
		for _, p := range record.Params {
			if p.Name == "label" && (p.Secret != f.secretLabel || f.secretLabel && record.ArgsDisplay["label"] != secretMask) {
				t.Fatal("approval card has incorrect argument sensitivity")
			}
		}
		if record.Status != "pending" && f.secretLabel && record.FinalArgsDisplay["label"] != secretMask {
			t.Fatal("approval history did not mask the final secret argument")
		}
		if label, present := f.args["label"]; present && !f.secretLabel {
			if record.ArgsDisplay["label"] != argString(label) {
				t.Fatal("approval card changed a public argument")
			}
			if record.Status != "pending" && record.FinalArgsDisplay["label"] != argString(finalArgs["label"]) {
				t.Fatal("approval history changed a public argument")
			}
		}
		if f.checkArgs != nil {
			f.checkArgs(t, record.ArgsDisplay)
			if record.Status != "pending" {
				f.checkArgs(t, record.FinalArgsDisplay)
			}
		}
	}
	assertStored := func() {
		t.Helper()
		var stored string
		if a.store.db.QueryRow(`SELECT preview_display || params_json || result FROM approvals WHERE id=?`, pending.ID).Scan(&stored) != nil {
			t.Fatal("cannot read stored approval displays")
		}
		assertSafe(stored)
		var argsJSON, finalJSON string
		if a.store.db.QueryRow(`SELECT args_display,final_args_display FROM approvals WHERE id=?`, pending.ID).Scan(&argsJSON, &finalJSON) != nil {
			t.Fatal("cannot read stored argument displays")
		}
		for i, text := range []string{argsJSON, finalJSON} {
			if i == 1 && (text == "" || text == "{}") {
				continue // No final arguments are stored until the decision.
			}
			var displayed map[string]string
			if json.Unmarshal([]byte(text), &displayed) != nil {
				t.Fatal("cannot decode stored argument displays")
			}
			want := f.args
			if i == 1 {
				want = finalArgs
			}
			for key, value := range want {
				expected := argString(value)
				if key == "label" && f.secretLabel {
					expected = secretMask
				}
				if displayed[key] != expected {
					t.Fatal("persisted arguments lost a whole-secret mask or changed public text")
				}
			}
			if f.secretLabel {
				assertSafe(text)
			}
		}
	}
	assertRecord(pending)
	assertStored()
	handler := a.Handler()
	rows := listApprovalAPI(t, handler, origin, "pending")
	if len(rows) != 1 {
		t.Fatal("pending API did not return the fixture")
	}
	assertRecord(rows[0])
	preview, err := a.PreviewApproval(pending.ID, pending.Nonce, f.edits)
	if err != nil {
		t.Fatal("cannot preview the redaction fixture")
	}
	assertPreview(preview.Preview)
	w := approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/approvals/%d/preview", pending.ID), origin, "application/json", map[string]any{"nonce": pending.Nonce, "args": f.edits})
	assertSafe(w.Body.String())
	var apiPreview ApprovalPreview
	requireApprovalAPIResponse(t, w, http.StatusOK, &apiPreview)
	assertPreview(apiPreview.Preview)
	if hits.Load() != 0 {
		t.Fatal("redaction fixture executed before approval")
	}
	w = approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/approvals/%d/decide", pending.ID), origin, "application/json", map[string]any{
		"action": action, "nonce": pending.Nonce, "args": f.edits, "preview_hash": apiPreview.PreviewHash,
	})
	requireApprovalAPIResponse(t, w, http.StatusOK, nil)
	reply := getApprovalReply(t, call)
	assertSafe(reply.text)
	if f.checkResult != nil {
		f.checkResult(t, reply.text)
	}
	if reply.isError != (f.failureText != "") || !received.Load() || hits.Load() != 1 {
		t.Fatal("approved send did not preserve the execution request and expected outcome")
	}
	if action == "edit" && !strings.Contains(reply.text, "修改的参数：label") {
		t.Fatal("edit result prefix omitted the changed argument")
	}
	assertStored()
	history := listApprovalAPI(t, handler, origin, "all")
	if len(history) != 1 || history[0].Status != map[string]string{"approve": "approved", "edit": "edited"}[action] {
		t.Fatal("history API did not return the completed fixture")
	}
	assertRecord(history[0])
	if f.checkResult != nil {
		f.checkResult(t, history[0].Result)
	}
	if f.failureText != "" && history[0].Result == "" {
		t.Fatal("approval history did not store the scrubbed failure")
	}
}

func TestApprovalFormValueBoundaries(t *testing.T) {
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
				checkExecution: func(p RequestPreview, _ map[string]any) bool { return p.Body == body },
				checkPreview: func(t *testing.T, p RequestPreview) {
					if p.Body != "password="+secretMask+"&note=visible" {
						t.Fatal("form redaction lost the real delimiter or public sibling")
					}
				},
			})
		})
	}
}

func TestApprovalHeaderContainers(t *testing.T) {
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
				checkExecution: func(p RequestPreview, args map[string]any) bool {
					return p.Headers[key] == strings.ReplaceAll(value, "{{label}}", args["label"].(string))
				},
				checkPreview: func(t *testing.T, p RequestPreview) {
					if !strings.Contains(p.Headers[key], secretMask) {
						t.Fatal("header preview did not mask its confidential content")
					}
				},
			})
		})
	}
}

func TestApprovalPublicArgumentTextIsVerbatim(t *testing.T) {
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
				checkExecution: func(p RequestPreview, args map[string]any) bool {
					var body map[string]string
					return json.Unmarshal([]byte(p.Body), &body) == nil && body["data"] == args["label"]
				},
				checkPreview: func(t *testing.T, p RequestPreview) {
					var body map[string]string
					if json.Unmarshal([]byte(p.Body), &body) != nil || body["data"] != value("old") && body["data"] != value("new") {
						t.Fatal("public argument preview changed its rendered text")
					}
				},
			})
		})
	}
}

func TestApprovalAmbiguousContainersFailClosed(t *testing.T) {
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
				checkExecution: func(p RequestPreview, args map[string]any) bool {
					return strings.Contains(p.URL+p.Body+p.Headers["Referer"], args["label"].(string))
				},
			})
		})
	}
}

func TestApprovalDuplicateEscapedKeys(t *testing.T) {
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
				checkExecution: func(p RequestPreview, args map[string]any) bool {
					if tc.name != "embedded" {
						return p.Body == strings.ReplaceAll(tc.body, "{{label}}", args["label"].(string))
					}
					return strings.Contains(p.Body, args["label"].(string)) && strings.Contains(p.Body, "public")
				},
			})
		})
	}
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

func TestApprovalEncodingAwareDisplaysAndErrors(t *testing.T) {
	private := privateTestValue(t) + "/" + privateTestValue(t)
	variants := approvalEncodingFixtures(private)
	original := strings.Join(variants, " ")
	replacement := "edited " + original
	exerciseApprovalRedaction(t, approvalRedactionFixture{
		configure: func(tool *Tool) { tool.Body = `{"token":"` + private + `","data":"{{label}}"}` },
		args:      map[string]any{"label": original}, edits: map[string]any{"label": replacement},
		private: variants, failureText: original,
		checkExecution: func(p RequestPreview, args map[string]any) bool {
			var body map[string]string
			return json.Unmarshal([]byte(p.Body), &body) == nil && body["token"] == private && body["data"] == args["label"]
		},
	})
}

func TestApprovalEncodedLiteralScrub(t *testing.T) {
	for _, source := range []string{"known", "vault"} {
		t.Run(source, func(t *testing.T) {
			a := approvalTestApp(t)
			private := privateTestValue(t) + "/" + privateTestValue(t) + `+ space 😺é<&"'>`
			values := []string{private}
			if source == "vault" {
				if a.vault.Upsert("encoding", "secret", private, "", "") != nil {
					t.Fatal("cannot store private fixture")
				}
				values = nil
			}
			variants := append(approvalEncodingFixtures(private), html.EscapeString(private))
			variants = append(variants,
				strings.ToLower(url.PathEscape(private)),
				url.QueryEscape(url.PathEscape(private)),
				strings.ReplaceAll(strings.ReplaceAll(private, "😺", `\uD83D\uDE3A`), "é", `\u00E9`),
			)
			for _, value := range []string{private, url.QueryEscape(private), html.EscapeString(private)} {
				for i := 0; i < 9; i++ {
					encoded := string(compactJSON(value))
					value = encoded[1 : len(encoded)-1]
					variants = append(variants, value)
				}
			}
			for i, variant := range variants {
				got := a.scrubApprovalText("before "+variant+" after", values)
				if got != "before "+secretMask+" after" {
					t.Fatalf("encoded literal was not scrubbed at variant %d", i)
				}
			}
		})
	}
}

func TestApprovalStaticTemplateLiterals(t *testing.T) {
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
						tool.Body = string(compactJSON(map[string]string{key: `RUN {"password":"` + private + `"}`}))
					case "embedded_form":
						tool.Body = string(compactJSON(map[string]string{"data": "password=" + private + "&note=visible"}))
					case "form":
						tool.Headers["Content-Type"] = "application/x-www-form-urlencoded"
						tool.Body = "password=" + private + "&note=visible"
					}
				},
				private: []string{private}, failureText: "request failed: " + private,
				checkExecution: func(p RequestPreview, _ map[string]any) bool {
					return strings.Contains(p.URL+p.Body+p.Headers["Authorization"]+p.Headers["X-Meta"]+p.Headers["Referer"], private)
				},
			})
		})
	}
}

func TestApprovalTemplateContainerAnalysis(t *testing.T) {
	cases := []struct {
		name string
		tool Tool
		want bool
	}{
		{"unicode_key", Tool{Body: `{"pass\u0077ord":"{{label}}"}`}, true},
		{"duplicate_nested", Tool{Body: `{"data":"{\"password\":\"{{label}}\",\"pass\\u0077ord\":\"public\"}"}`}, true},
		{"embedded_form", Tool{Body: `{"data":"password={{label}}&note=visible"}`}, true},
		{"sensitive_embedded_json", Tool{Body: `{"credentials":"{\"plain\":\"{{label}}\"}"}`}, true},
		{"sensitive_embedded_url", Tool{Body: `{"credentials":"https://example.com/?plain={{label}}"}`}, true},
		{"public_query_semicolon", Tool{URL: "https://example.com/?other=public;bad&label={{label}}"}, true},
		{"public_query_escape", Tool{URL: "https://example.com/?other=%ZZ&label={{label}}"}, true},
		{"fragment_escape", Tool{URL: "https://example.com/#label={{label}}%ZZ"}, true},
		{"path_escape", Tool{URL: "https://example.com/%ZZ/{{label}}"}, true},
		{"body_parse_failure", Tool{Body: `{"data":"{{label}}"} trailing`}, true},
		{"embedded_parse_failure", Tool{Body: `{"data":"RUN {\"plain\":\"{{label}}\"} trailing"}`}, true},
		{"quoted_non_key", Tool{Body: `{"note":"password={{label}}"}`}, false},
		{"unquoted_non_key", Tool{Body: `note=password={{label}}`}, false},
		{"excluded_key", Tool{Body: `{"passwordStrength":"{{label}}"}`}, false},
		{"public_embedded_sibling", Tool{Body: `{"data":"RUN {\"broken\":} trailing","label":"{{label}}"}`}, false},
		{"deep_secret", Tool{Body: strings.Repeat("[", 100) + `{"password":"{{label}}"}` + strings.Repeat("]", 100)}, true},
		{"deep_public", Tool{Body: strings.Repeat("[", 100) + `{"label":"{{label}}"}` + strings.Repeat("]", 100)}, true},
		{"shallow_public", Tool{Body: strings.Repeat("[", 10) + `{"label":"{{label}}"}` + strings.Repeat("]", 10)}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if paramIsSecret(&tc.tool, Param{Name: "label"}) != tc.want {
				t.Fatal("template container analysis violated its confidentiality boundary")
			}
		})
	}
}

func TestApprovalHeaderPreviewStructuralWalk(t *testing.T) {
	private := privateTestValue(t)
	preview := redactPreview(RequestPreview{Headers: map[string]string{
		"X-Meta":  `{"password":"` + private + `"}`,
		"Referer": "https://example.com/?token=" + private,
		"X-Form":  "password=" + private + "&note=visible",
	}})
	requirePrivateApprovalValuesAbsent(t, preview, private)
	for _, value := range preview.Headers {
		if !strings.Contains(value, secretMask) {
			t.Fatal("header preview did not structurally mask a sensitive field")
		}
	}
}

func TestApprovalSendEncodedResolvedConfig(t *testing.T) {
	a := approvalTestApp(t)
	private := privateTestValue(t) + "/" + privateTestValue(t)
	if a.vault.Upsert("display_config", "plain", private, "", "") != nil {
		t.Fatal("cannot store deferred config fixture")
	}
	variants := approvalEncodingFixtures(private)
	var received atomic.Bool
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		received.Store(err == nil && string(body) == private && r.URL.Query().Get("value") == private)
		w.Header().Set("X-Echo", strings.Join(variants, " "))
		io.WriteString(w, strings.Join(variants, " "))
	}))
	a.httpClient = upstream.Client()
	tool := &Tool{Method: "POST", URL: upstream.URL + "/?value={{cfg.display_config}}", Body: "{{cfg.display_config}}"}
	prepared, err := a.Prepare(tool, nil)
	if err != nil || !strings.Contains(prepared.Preview.Body, "{{cfg.display_config}}") {
		t.Fatal("prepare did not preserve the deferred configuration reference")
	}
	res, err := a.Send(prepared)
	if err != nil || res.Error != "" || !received.Load() {
		t.Fatal("send changed the resolved configuration value")
	}
	for _, text := range []string{res.Body, res.URL, res.ReqBody, res.Headers["X-Echo"]} {
		for _, variant := range variants {
			if strings.Contains(text, variant) {
				t.Fatal("send returned an encoded configuration literal")
			}
		}
	}
}

func TestApprovalScrubPreservesEncodingGrammars(t *testing.T) {
	a := approvalTestApp(t)
	private := privateTestValue(t) + `%2F&amp;/` + privateTestValue(t)
	unicode := strings.ReplaceAll(private, "/", `\u002F`)
	for i, variant := range []string{
		unicode,
		html.EscapeString(unicode),
		url.QueryEscape(html.EscapeString(unicode)),
		url.QueryEscape(url.QueryEscape(unicode)),
	} {
		if a.scrubApprovalText("before "+variant+" after", []string{private}) != "before "+secretMask+" after" {
			t.Fatalf("mixed encoding grammar was not scrubbed at variant %d", i)
		}
	}
}

func TestApprovalMalformedJSONQuotedSuffix(t *testing.T) {
	left, right := privateTestValue(t), privateTestValue(t)
	preview := redactPreview(RequestPreview{Body: `{"password":"` + left + `"` + right + `,"note":"visible"}`})
	requirePrivateApprovalValuesAbsent(t, preview, left, right)
	if !strings.Contains(preview.Body, `"note":"visible"`) || !strings.Contains(preview.Body, secretMask) {
		t.Fatal("malformed JSON redaction lost the field boundary or public sibling")
	}
}
