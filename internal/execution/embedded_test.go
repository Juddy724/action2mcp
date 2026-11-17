package execution

import (
	"action2mcp/internal/domain"
	"action2mcp/internal/vault"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
)

func TestApprovalEmbeddedJSONPreview(t *testing.T) {
	for _, kind := range []string{"valid", "malformed", "prefixed", "array", "form", "query", "mislabeled_json", "mislabeled_malformed"} {
		t.Run(kind, func(t *testing.T) {
			a := New(Options{})
			private := privateTestValue(t)
			inner := `RUN {"token":"` + private + `"}`
			if kind == "prefixed" {
				inner = "RUN --option value " + strings.TrimPrefix(inner, "RUN ")
			} else if kind == "array" {
				inner = `RUN [{"token":"` + private + `"}]`
			}
			tool := &Tool{Method: "POST", URL: "https://example.com/", Headers: map[string]string{"Content-Type": "application/json"}, Body: string(CompactJSON(map[string]string{"payload": inner}))}
			if kind == "malformed" || kind == "mislabeled_malformed" {
				tool.Body = `{"n":{{cfg.n}},"payload":` + string(CompactJSON(inner)) + `}`
			} else if kind == "form" {
				tool.Headers["Content-Type"] = "application/x-www-form-urlencoded"
				tool.Body = "payload=" + url.QueryEscape(inner)
			} else if kind == "query" {
				tool.URL += "?payload=" + url.QueryEscape(inner)
				tool.Body = ""
			}
			if strings.HasPrefix(kind, "mislabeled_") {
				tool.Headers["Content-Type"] = "application/x-www-form-urlencoded"
			}
			if kind == "malformed" {
				requirePrivateApprovalValuesAbsent(t, RedactPreviewAssignments(tool.Body), private)
			}
			assertPreview := func(preview domain.RequestPreview) {
				t.Helper()
				requirePrivateApprovalValuesAbsent(t, preview, private)
				payload := preview.Body
				if kind == "form" {
					payload = tolerantForm(payload).Get("payload")
				} else if kind == "query" {
					u, err := url.Parse(preview.URL)
					if err != nil {
						t.Fatal("cannot parse embedded preview URL")
					}
					payload = u.Query().Get("payload")
				} else if kind != "malformed" && kind != "mislabeled_malformed" {
					var outer map[string]string
					if json.Unmarshal([]byte(preview.Body), &outer) != nil {
						t.Fatal("embedded JSON redaction broke the outer document")
					}
					payload = outer["payload"]
				}
				if !strings.Contains(payload, "RUN ") || !strings.Contains(payload, vault.Mask) || !strings.Contains(payload, "token") {
					t.Fatal("embedded JSON preview lost its prefix, key, or mask")
				}
			}
			assertPreview(RedactPreview(domain.RequestPreview{Method: tool.Method, URL: tool.URL, Headers: tool.Headers, Body: tool.Body}))
			prepared, err := a.Prepare(tool, nil)
			if err != nil {
				t.Fatal("cannot prepare embedded JSON fixture")
			}
			if !strings.Contains(prepared.request.Body+prepared.request.URL, private) {
				t.Fatal("embedded preview redaction changed the execution request")
			}
			assertPreview(prepared.Preview)
		})
	}
}

// Parse each pair separately: url.ParseQuery discards an entire pair containing
// a semicolon or bad escape. Retain that pair so token=... always gets masked.
func tolerantForm(body string) url.Values {
	vals := url.Values{}
	for _, pair := range strings.Split(body, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		if decoded, err := url.QueryUnescape(k); err == nil {
			k = decoded
		}
		if decoded, err := url.QueryUnescape(v); err == nil {
			v = decoded
		}
		vals[k] = append(vals[k], v)
	}
	return vals
}
