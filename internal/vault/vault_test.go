package vault

import (
	"database/sql"
	"encoding/json"
	_ "modernc.org/sqlite"
	"path/filepath"
	"strings"
	"testing"
)

func TestSnapshotsEncryptionAndSiteHeaderBinding(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "fixture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	_, err = db.Exec(`CREATE TABLE vault(id INTEGER PRIMARY KEY, name TEXT UNIQUE, type TEXT, value_enc TEXT, site TEXT, note TEXT, created_at TEXT, updated_at TEXT)`)
	if err != nil {
		t.Fatal(err)
	}
	v, err := OpenVault(db, filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	const secret = "fixture-secret-0123"
	if err := v.Upsert("fixture_token", "secret", secret, "https://example.com", ""); err != nil {
		t.Fatal(err)
	}
	if err := v.Upsert("fixture_user", "plain", "example-user", "https://example.com", ""); err != nil {
		t.Fatal(err)
	}
	snapshot := v.SecretValues()
	snapshot["fixture_token"] = "changed"
	if got, _ := v.Lookup("fixture_token"); got != secret {
		t.Fatal("secret snapshot escaped cache")
	}
	if _, ok := snapshot["fixture_user"]; ok {
		t.Fatal("plain config leaked into secret-only snapshot")
	}
	values := v.ForSite("https://example.com")
	values["fixture_token"] = SiteValue{Type: "plain", Value: "changed"}
	if got, _ := v.Lookup("fixture_token"); got != secret {
		t.Fatal("site snapshot escaped cache")
	}
	var encrypted string
	if err := db.QueryRow(`SELECT value_enc FROM vault WHERE name='fixture_token'`).Scan(&encrypted); err != nil || strings.Contains(encrypted, secret) {
		t.Fatalf("at-rest value: err=%v", err)
	}
	v2, err := OpenVault(db, filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := v2.Lookup("fixture_token"); got != secret {
		t.Fatal("shared-key reopen changed encrypted value")
	}
	enc, err := v.EncryptSiteHeader("https://example.com", "authorization", secret)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := v2.DecryptSiteHeader("https://example.com", "authorization", enc); err != nil || got != secret {
		t.Fatalf("site-header roundtrip: %v", err)
	}
	for _, binding := range [][2]string{{"https://other.example", "authorization"}, {"https://example.com", "x-token"}} {
		if _, err := v.DecryptSiteHeader(binding[0], binding[1], enc); err == nil {
			t.Fatal("site/header associated data was not bound")
		}
	}
}

func TestScrubPreservesJSONNumbers(t *testing.T) {
	raw := `{"head":{"code":"00000000"},"body":{"list":[{"elapse":12345678,"traceId":"abc12345678xyz"}]}}`
	scrubbed := ScrubSecretText(raw, nil, []string{"12345678"})
	if strings.Contains(scrubbed, "12345678") {
		t.Fatalf("secret leaked: %s", scrubbed)
	}
	if !json.Valid([]byte(scrubbed)) {
		t.Fatalf("scrubbed output is no longer valid JSON: %s", scrubbed)
	}
	if !strings.Contains(scrubbed, `"elapse":"******"`) {
		t.Fatalf("expected quoted mask for JSON number, got: %s", scrubbed)
	}
	if !strings.Contains(scrubbed, `"traceId":"abc******xyz"`) {
		t.Fatalf("expected inline mask inside JSON string, got: %s", scrubbed)
	}
}

func TestScrubShortPureDigitSecretRespectsDigitBoundaries(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "fixture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE vault(id INTEGER PRIMARY KEY, name TEXT UNIQUE, type TEXT, value_enc TEXT, site TEXT, note TEXT, created_at TEXT, updated_at TEXT)`); err != nil {
		t.Fatal(err)
	}
	v, err := OpenVault(db, filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Upsert("short_pin", "secret", "123", "", ""); err != nil {
		t.Fatal(err)
	}
	if err := v.Upsert("short_zero", "secret", "000", "", ""); err != nil {
		t.Fatal(err)
	}

	// Must NOT corrupt longer numbers / error codes / business codes.
	if got := v.Scrub("Error 1235 (0A000): prepared statement disabled; code=C_1000"); got != "Error 1235 (0A000): prepared statement disabled; code=C_1000" {
		t.Fatalf("short numeric secret corrupted longer numbers: %q", got)
	}
	// Must STILL mask standalone short numeric secrets.
	if got := v.Scrub(`pin=123&code="000"`); got != `pin=******&code="******"` {
		t.Fatalf("standalone short numeric secrets were not masked: %q", got)
	}
	if got := v.Scrub(`{"pin":123}`); got != `{"pin":"******"}` {
		t.Fatalf("JSON numeric secret was not masked cleanly: %q", got)
	}
}
