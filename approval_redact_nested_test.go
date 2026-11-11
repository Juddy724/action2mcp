package main

import "testing"

func TestRedactPreviewMalformedNestedJSONString(t *testing.T) {
	for _, body := range []string{
		`{"password":"x","n":{{cfg.n}},"payload":"{\"token\":\"STATIC\"}"}`,
		`{"password":"x","n":******,"payload":"{\"token\":\"STATIC\"}"}`,
	} {
		got := redactPreview(RequestPreview{Body: body, Headers: map[string]string{}}).Body
		if containsStr(got, "STATIC") {
			t.Fatalf("leak: %s", got)
		}
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
