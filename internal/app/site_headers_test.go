package app

import (
	"path/filepath"
	"testing"
)

func testAppWithVault(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(filepath.Join(dir, "a2m.db"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := OpenVault(s.db, filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	a := &App{store: s, vault: v, dataDir: dir, cfg: Config{Port: 7788}}
	t.Cleanup(func() { s.db.Close() })
	return a
}

func TestCredOriginMapping(t *testing.T) {
	if got := credOrigin("wss://sql.example.com/api/ws/execute"); got != "https://sql.example.com" {
		t.Fatalf("got %q", got)
	}
	if got := credOrigin("ws://sql.example.com:80/x"); got != "http://sql.example.com" {
		t.Fatalf("got %q", got)
	}
	if got := credOrigin("https://sql.example.com:443/"); got != "https://sql.example.com" {
		t.Fatalf("got %q", got)
	}
	if credOrigin("https://other.example.com") == credOrigin("https://sql.example.com") {
		t.Fatal("origins should differ")
	}
}

func TestSiteHeadersEncryptedAndGeneration(t *testing.T) {
	a := testAppWithVault(t)
	token := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	if err := a.HarvestRequestHeader("hop1", "https://sql.example.com/api/x", "sso-epctoken", token); err != nil {
		t.Fatal(err)
	}
	if a.store.siteHeaderPlaintextExists(token) {
		t.Fatal("plaintext token written to site_headers")
	}
	got, err := a.GetSiteHeader("wss://sql.example.com/api/ws/execute", "SSO-EPCTOKEN")
	if err != nil || got != token {
		t.Fatalf("lookup: %q %v", got, err)
	}
	// Same-name cookie origin must not be required here; header lookup is by cred origin.
	if _, err := a.GetSiteHeader("https://other.example.com/", "sso-epctoken"); err == nil {
		t.Fatal("cross-origin lookup should fail")
	}
	secrets, err := a.SiteHeaderSecrets("wss://sql.example.com/path")
	if err != nil || len(secrets) != 1 || secrets[0] != token {
		t.Fatalf("secrets=%v %v", secrets, err)
	}

	// Restart: reopen vault+store and match before any Send.
	dir := a.dataDir
	a.store.db.Close()
	s, err := OpenStore(filepath.Join(dir, "a2m.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	v, err := OpenVault(s.db, filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	a2 := &App{store: s, vault: v, dataDir: dir}
	got, err = a2.GetSiteHeader("https://sql.example.com/api", "sso-epctoken")
	if err != nil || got != token {
		t.Fatalf("after reopen: %q %v", got, err)
	}
	if err := a2.ClearSiteHeaders("https://sql.example.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := a2.GetSiteHeader("https://sql.example.com", "sso-epctoken"); err == nil {
		t.Fatal("expected missing after clear")
	}
}

func TestHarvestHopDoesNotCrossOrigin(t *testing.T) {
	a := testAppWithVault(t)
	a.TrackHarvestHop("req1", "https://a.example.com/login")
	// Late extra header with a different URL must not be stored under the wrong origin,
	// and also must not be stored under the new origin without a unique hop bind when it conflicts.
	if err := a.HarvestRequestHeader("req1", "https://b.example.com/api", "sso-epctoken", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GetSiteHeader("https://b.example.com", "sso-epctoken"); err == nil {
		t.Fatal("cross-origin extra header should not be stored")
	}
	if _, err := a.GetSiteHeader("https://a.example.com", "sso-epctoken"); err == nil {
		t.Fatal("should not attribute the new origin token to the old hop origin")
	}
}

func TestGuardFloorCannotBeDisabledViaSaveTool(t *testing.T) {
	s := testStore(t)
	t1 := &Tool{Name: "sql_ws", Method: "WS", URL: "wss://sql.example.com/ws",
		Config: ToolConfig{Messages: []string{`execute {"data":{"sql":"{{sql}}"},"token":"{{header.sso-epctoken}}"}`}, SQLGuard: &SQLGuardConfig{Enabled: true, Param: "sql", MaxRows: 10}}}
	if err := s.SaveTool(t1); err != nil {
		t.Fatal(err)
	}
	if t1.Approval != "always" || !t1.Config.sqlGuardEnabled() || t1.Config.maxRows() != 10 {
		t.Fatalf("saved: approval=%s guard=%v rows=%d", t1.Approval, t1.Config.sqlGuardEnabled(), t1.Config.maxRows())
	}
	// Import-like overwrite cannot disable.
	t2 := &Tool{Name: "sql_ws", Method: "WS", URL: "wss://sql.example.com/ws", Approval: "off",
		Config: ToolConfig{Messages: []string{`execute {"data":{"sql":"{{sql}}"}`}, SQLGuard: &SQLGuardConfig{Enabled: false, MaxRows: 200}}}
	if err := s.SaveTool(t2); err != nil {
		// name unique will update? SaveTool with ID=0 tries INSERT and fails unique.
		t.Log(err)
	}
	t2.ID = t1.ID
	t2.Name = "sql_ws"
	if err := s.SaveTool(t2); err != nil {
		t.Fatal(err)
	}
	got, _ := s.GetTool(t1.ID)
	if !got.Config.sqlGuardEnabled() {
		t.Fatal("guard was disabled without AllowDisableGuard")
	}
	if got.Config.maxRows() != 10 {
		t.Fatalf("max_rows relaxed to %d", got.Config.maxRows())
	}
	if got.Approval != "always" {
		t.Fatalf("approval lowered to %s", got.Approval)
	}

	// Console can disable but cannot also lower approval.
	dis := *got
	dis.AllowDisableGuard = true
	dis.Config.SQLGuard = &SQLGuardConfig{Enabled: false}
	dis.Approval = "off"
	if err := s.SaveTool(&dis); err == nil {
		t.Fatal("expected error disabling guard and lowering approval")
	}
	dis.Approval = "always"
	if err := s.SaveTool(&dis); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetTool(t1.ID)
	if got.Config.sqlGuardEnabled() {
		t.Fatal("console should be able to disable guard while keeping always")
	}
	if got.Approval != "always" {
		t.Fatal(got.Approval)
	}
}
