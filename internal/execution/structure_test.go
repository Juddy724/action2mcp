package execution

import (
	"action2mcp/internal/domain"
	"action2mcp/internal/vault"
	"strings"
	"testing"
)

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
			if ParamIsSecret(&tc.tool, domain.Param{Name: "label"}) != tc.want {
				t.Fatal("template container analysis violated its confidentiality boundary")
			}
		})
	}
}

func TestApprovalHeaderPreviewStructuralWalk(t *testing.T) {
	private := privateTestValue(t)
	preview := RedactPreview(domain.RequestPreview{Headers: map[string]string{
		"X-Meta":  `{"password":"` + private + `"}`,
		"Referer": "https://example.com/?token=" + private,
		"X-Form":  "password=" + private + "&note=visible",
	}})
	requirePrivateApprovalValuesAbsent(t, preview, private)
	for _, value := range preview.Headers {
		if !strings.Contains(value, vault.Mask) {
			t.Fatal("header preview did not structurally mask a sensitive field")
		}
	}
}

func TestApprovalMalformedJSONQuotedSuffix(t *testing.T) {
	left, right := privateTestValue(t), privateTestValue(t)
	preview := RedactPreview(domain.RequestPreview{Body: `{"password":"` + left + `"` + right + `,"note":"visible"}`})
	requirePrivateApprovalValuesAbsent(t, preview, left, right)
	if !strings.Contains(preview.Body, `"note":"visible"`) || !strings.Contains(preview.Body, vault.Mask) {
		t.Fatal("malformed JSON redaction lost the field boundary or public sibling")
	}
}
