package credential

import "testing"

func TestReferenceAndReplayPolicy(t *testing.T) {
	for _, name := range []string{"secret.token", "cfg.user"} {
		if !IsServerRef(name, false) {
			t.Fatalf("vault ref rejected: %q", name)
		}
	}
	for _, name := range []string{"HEADER.Authorization", "cookie.sid"} {
		if IsServerRef(name, false) || !IsServerRef(name, true) {
			t.Fatalf("transport ref boundary: %q", name)
		}
	}
	if !IsCookieJarRef("Header.Cookie") || IsCookieJarRef("header.authorization") {
		t.Fatal("cookie jar binding")
	}
	if !ValidName("fixture_1") || ValidName("fixture-token") {
		t.Fatal("configuration name policy")
	}
	headers, creds := SanitizeHeaders(map[string]string{"Host": "example.com", "Authorization": "fixture", "Content-Type": "application/json", "Sec-Fetch-Site": "same-origin"})
	if len(headers) != 1 || headers["Content-Type"] != "application/json" || len(creds) != 1 || creds[0] != "authorization" {
		t.Fatalf("replay policy: %#v %#v", headers, creds)
	}
	if !ShouldDropHeader("HOST") || ShouldDropHeader("Content-Type") {
		t.Fatal("immutable drop policy")
	}
}
