package execution

import (
	"action2mcp/internal/domain"
	"action2mcp/internal/vault"
	"encoding/json"
	"strings"
	"testing"
)

func TestPreparedJSONMaskQuoting(t *testing.T) {
	a := New(Options{})
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
				Params: []domain.Param{{Name: "label", Type: "integer", Required: true, Secret: true}}}
			prepared, err := a.Prepare(tool, map[string]any{"label": 42})
			if err != nil || !json.Valid([]byte(prepared.Preview.Body)) || !strings.Contains(prepared.Preview.Body, vault.Mask) {
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
	escaped := string(CompactJSON(secret + `\"&,;`))
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
			preview := RedactPreview(domain.RequestPreview{Body: tc.body, Headers: map[string]string{"Content-Type": tc.contentType}})
			if preview.Body != tc.want {
				t.Fatal("lexical redaction missed a sensitive assignment or changed a non-key value")
			}
		})
	}
	for _, prefix := range []string{"", "RUN "} {
		body := string(CompactJSON(map[string]any{"inner": prefix + `{"password":******,"token":"` + secret + `"}`}))
		preview := RedactPreview(domain.RequestPreview{Body: body})
		var outer map[string]string
		var inner map[string]string
		if json.Unmarshal([]byte(preview.Body), &outer) != nil || json.Unmarshal([]byte(strings.TrimPrefix(outer["inner"], prefix)), &inner) != nil || inner["password"] != vault.Mask || inner["token"] != vault.Mask {
			t.Fatal("nested malformed JSON retained sensitive values")
		}
	}
}
