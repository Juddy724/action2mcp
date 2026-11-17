package site

import (
	"database/sql"
	_ "modernc.org/sqlite"
	"path/filepath"
	"sync"
	"testing"
)

func TestAtomicSiteUpdateSharesManualWriterLock(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "fixture.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE sites(id INTEGER PRIMARY KEY AUTOINCREMENT, origin TEXT UNIQUE, config TEXT, status TEXT, last_login_at TEXT, last_check_at TEXT, last_error TEXT, login_count INTEGER, created_at TEXT, updated_at TEXT)`)
	if err != nil {
		t.Fatal(err)
	}
	repo := NewRepository(db)
	original := &Site{Origin: "https://example.com", Method: MethodSSO, Name: "fixture"}
	if err := repo.SaveSite(original); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errors := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Go(func() {
			_, err := repo.UpdateSite(original.Origin, func(current *Site) (*Site, bool, error) { current.Name += "."; return current, true, nil })
			errors <- err
		})
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := repo.GetSite(original.ID)
	if err != nil || got.Name != "fixture...................." {
		t.Fatalf("lost update: %#v, %v", got, err)
	}
	_, err = repo.UpdateSite(original.Origin, func(current *Site) (*Site, bool, error) { current.Name = "not-saved"; return current, false, nil })
	if err != nil {
		t.Fatal(err)
	}
	got, _ = repo.GetSite(original.ID)
	if got.Name == "not-saved" {
		t.Fatal("decision-only update wrote configuration")
	}
}
