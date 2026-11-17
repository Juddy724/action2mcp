package login

import (
	"action2mcp/internal/browser"
	"action2mcp/internal/execution"
	sitecfg "action2mcp/internal/site"
	"action2mcp/internal/vault"
	"database/sql"
	"errors"
	_ "modernc.org/sqlite"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
)

type loginTestRepository struct {
	*sitecfg.Repository
	db      *sql.DB
	mu      sync.Mutex
	cookies []Cookie
}

func (r *loginTestRepository) AllCookies() []Cookie {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]Cookie(nil), r.cookies...)
}
func (r *loginTestRepository) ReplaceCookies(c []Cookie) {
	r.mu.Lock()
	r.cookies = append([]Cookie(nil), c...)
	r.mu.Unlock()
}
func (r *loginTestRepository) ListTools() ([]*execution.Tool, error) { return nil, nil }

type fixtureBrowsers struct{ repo *loginTestRepository }

func (f fixtureBrowsers) AcquireBrowser() (*browser.Session, error) {
	return nil, errors.New("browser intentionally unavailable")
}
func (f fixtureBrowsers) ReleaseBrowser(*browser.Session) {}
func (f fixtureBrowsers) OpenVisibleTab(string) (*browser.Session, *browser.Tab, error) {
	return nil, nil, errors.New("browser intentionally unavailable")
}
func (f fixtureBrowsers) ApplyCookies(c []Cookie)              { f.repo.ReplaceCookies(c) }
func (f fixtureBrowsers) CookiesFor(string) ([]Cookie, string) { return f.repo.AllCookies(), "fixture" }
func testLoginService(t *testing.T) *Service {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS sites(id INTEGER PRIMARY KEY AUTOINCREMENT, origin TEXT UNIQUE, config TEXT, status TEXT DEFAULT 'unknown', last_login_at TEXT DEFAULT '', last_check_at TEXT DEFAULT '', last_error TEXT DEFAULT '', login_count INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS site_headers(
		origin TEXT NOT NULL,
		name TEXT NOT NULL,
		value_enc TEXT NOT NULL,
		generation INTEGER NOT NULL DEFAULT 0,
		updated_at TEXT,
		PRIMARY KEY(origin, name)
	);
CREATE TABLE IF NOT EXISTS site_header_gens(
		origin TEXT PRIMARY KEY,
		generation INTEGER NOT NULL,
		started_at TEXT
	);
CREATE TABLE IF NOT EXISTS vault(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, type TEXT, value_enc TEXT, site TEXT DEFAULT '', note TEXT DEFAULT '', created_at TEXT, updated_at TEXT);`); err != nil {
		t.Fatal(err)
	}
	v, err := vault.OpenVault(db, filepath.Join(t.TempDir(), "vault.key"))
	if err != nil {
		t.Fatal(err)
	}
	repo := &loginTestRepository{Repository: sitecfg.NewRepository(db), db: db}
	quit := make(chan struct{})
	probe := execution.New(execution.Options{Vault: v, ConsolePort: 19000, HTTPClient: &http.Client{}}).Call
	a := New(Options{Repository: repo, HeaderDB: db, Vault: v, Browsers: fixtureBrowsers{repo}, Quit: quit, Probe: probe, MiddlewareBindings: func() []MiddlewareBinding { return nil }})
	t.Cleanup(func() {
		for _, s := range repo.ListSites() {
			_ = a.CancelLogin(s)
		}
		close(quit)
		db.Close()
	})
	return a
}
