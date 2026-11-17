package app

import "testing"

func TestRedactPreviewMalformedNestedJSONString(t *testing.T) {
	private := privateTestValue(t)
	for _, body := range []string{
		`{"password":"x","n":{{cfg.n}},"payload":"{\"token\":\"` + private + `\"}"}`,
		`{"password":"x","n":******,"payload":"{\"token\":\"` + private + `\"}"}`,
	} {
		got := redactPreview(RequestPreview{Body: body, Headers: map[string]string{}}).Body
		if containsStr(got, private) {
			t.Fatal("nested malformed template leaked a private value")
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
