package login

import "testing"

func TestExtractCSRF(t *testing.T) {
	cases := map[string]string{
		`<input type="hidden" name="csrf_token" value="abc123">`: "abc123",
		`<input value='zz9' type=hidden name='csrf_token'>`:      "zz9",
		`<meta name="csrf-token" content="m3ta">`:                "m3ta",
		`<script>window.csrf_token = "js7788aa";</script>`:       "js7788aa",
	}
	for html, want := range cases {
		if _, got := extractCSRF(html, ""); got != want {
			t.Errorf("%s: got %q want %q", html, got, want)
		}
	}
}
