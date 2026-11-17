package login

import (
	"strings"
	"testing"
)

func TestRequiredSiteHeadersSkipsCookieJarRef(t *testing.T) {
	a := testLoginService(t)
	raw := "wss://sql.example.com/api/ws"
	a.options.MiddlewareBindings = func() []MiddlewareBinding {
		return []MiddlewareBinding{{URL: raw, Names: []string{"cookie", "sso-epctoken"}}}
	}
	site := a.repo.EnsureSite(raw)
	if site == nil {
		t.Fatal("expected site for wss URL")
	}
	need := a.requiredSiteHeaders(site)
	for _, n := range need {
		if strings.EqualFold(n, "cookie") {
			t.Fatalf("required headers should exclude cookie: %v", need)
		}
	}
	if len(need) != 1 || need[0] != "sso-epctoken" {
		t.Fatalf("required headers=%v", need)
	}
}
