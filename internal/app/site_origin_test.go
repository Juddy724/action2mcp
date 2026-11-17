package app

import (
	"strings"
	"testing"
)

func TestOriginMappingWSToHTTP(t *testing.T) {
	cases := []struct{ in, want string }{
		{"wss://sql.example.com/api/ws/execute", "https://sql.example.com"},
		{"ws://sql.example.com:80/x", "http://sql.example.com"},
		{"wss://sql.example.com:443/", "https://sql.example.com"},
		{"https://sql.example.com:443/", "https://sql.example.com"},
		{"http://app.example.com/login", "http://app.example.com"},
		{"sql.example.com", "https://sql.example.com"},
	}
	for _, c := range cases {
		if got := credOrigin(c.in); got != c.want {
			t.Fatalf("credOrigin(%q)=%q want %q", c.in, got, c.want)
		}
		if got := originOf(c.in); got != c.want {
			t.Fatalf("originOf(%q)=%q want %q", c.in, got, c.want)
		}
		if got := browserOrigin(c.in); got != c.want {
			t.Fatalf("browserOrigin(%q)=%q want %q", c.in, got, c.want)
		}
		if got := normalizeOrigin(c.in); got != c.want {
			t.Fatalf("normalizeOrigin(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func TestEnsureSiteMapsWebSocketOrigin(t *testing.T) {
	a, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Shutdown()
	s := a.store.EnsureSite("wss://sql.example.com/api/ws/execute")
	if s == nil || s.Origin != "https://sql.example.com" {
		t.Fatalf("origin=%v", s)
	}
	if got := a.store.SiteByOrigin("wss://sql.example.com"); got == nil || got.ID != s.ID {
		t.Fatal("wss lookup did not find the https site")
	}
	if got := a.store.SiteByOrigin("https://sql.example.com"); got == nil || got.ID != s.ID {
		t.Fatal("https lookup missed the site")
	}
	if again := a.store.EnsureSite("ws://sql.example.com/other"); again.ID != s.ID {
		t.Fatal("ws and wss of the same host created two sites")
	}
}

func TestSaveSiteMapsOriginAndRejectsWSLoginURL(t *testing.T) {
	a, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Shutdown()
	s := &Site{Origin: "wss://sql.example.com", Name: "sql", Method: MethodManual}
	if err := a.store.SaveSite(s); err != nil {
		t.Fatal(err)
	}
	if s.Origin != "https://sql.example.com" {
		t.Fatalf("saved origin %q", s.Origin)
	}
	s.EntryURL = "wss://sql.example.com/login"
	if err := a.store.SaveSite(s); err == nil || !strings.Contains(err.Error(), "http") {
		t.Fatalf("expected http(s) error, got %v", err)
	}
	s.EntryURL = "http://sql.example.com/login"
	if err := a.store.SaveSite(s); err != nil {
		t.Fatal(err)
	}
}

func TestMigrateWSSiteOrigins(t *testing.T) {
	a, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Shutdown()
	_, err = a.store.db.Exec(`INSERT INTO sites(origin,config,status,last_login_at,last_check_at,last_error,login_count,created_at,updated_at)
VALUES('wss://sql.example.com', '{"name":"sql","entry_url":"wss://sql.example.com/console"}', 'unknown','','','',0,'','')`)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.store.migrateWSSiteOrigins(); err != nil {
		t.Fatal(err)
	}
	s := a.store.SiteByOrigin("https://sql.example.com")
	if s == nil || s.Origin != "https://sql.example.com" {
		t.Fatalf("migrated site=%v", s)
	}
	if s.EntryURL != "https://sql.example.com/console" {
		t.Fatalf("entry %q", s.EntryURL)
	}
	var n int
	if err := a.store.db.QueryRow(`SELECT COUNT(*) FROM sites WHERE origin LIKE 'ws%'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("leftover ws origins n=%d err=%v", n, err)
	}
}

func TestMigrateWSSiteOriginConflictKeepsHTTP(t *testing.T) {
	a, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Shutdown()
	keep := &Site{Origin: "https://sql.example.com", Name: "keep", Method: MethodManual}
	if err := a.store.SaveSite(keep); err != nil {
		t.Fatal(err)
	}
	_, err = a.store.db.Exec(`INSERT INTO sites(origin,config,status,last_login_at,last_check_at,last_error,login_count,created_at,updated_at)
VALUES('wss://sql.example.com', '{"name":"dup"}', 'unknown','','','',0,'','')`)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.store.migrateWSSiteOrigins(); err != nil {
		t.Fatal(err)
	}
	s := a.store.SiteByOrigin("https://sql.example.com")
	if s == nil || s.ID != keep.ID || s.Name != "keep" {
		t.Fatalf("kept the wrong row: %+v", s)
	}
	var n int
	a.store.db.QueryRow(`SELECT COUNT(*) FROM sites`).Scan(&n)
	if n != 1 {
		t.Fatalf("sites=%d", n)
	}
}

func TestNewAppEnsuresHTTPSiteForWSMiddleware(t *testing.T) {
	dir := t.TempDir()
	a, err := NewApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	m := sqlConsoleTestMW("sqlconsole", "wss://sql.example.com/api/ws")
	if err := a.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}
	a.Shutdown()
	a2, err := NewApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a2.Shutdown()
	s := a2.store.SiteByOrigin("https://sql.example.com")
	if s == nil || s.Origin != "https://sql.example.com" {
		t.Fatalf("middleware did not register an http(s) login site: %v", s)
	}
}
