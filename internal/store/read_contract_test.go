package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

// Empty results are legitimate; query failures must remain distinguishable at
// repository methods that return errors. The upgrade bug opened a different,
// valid empty database, so error propagation alone could not detect it.
func TestCatalogReadEmptyMissingAndClosedDatabase(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "a2m.db"))
	if err != nil {
		t.Fatal(err)
	}
	if v, e := s.ListTools(); e != nil || len(v) != 0 {
		t.Fatalf("empty tools=%v err=%v", v, e)
	}
	if v, e := s.ExposedTools(); e != nil || len(v) != 0 {
		t.Fatalf("empty exposed tools=%v err=%v", v, e)
	}
	if v, e := s.ListPacks(); e != nil || len(v) != 0 {
		t.Fatalf("empty packs=%v err=%v", v, e)
	}
	if v, e := s.ListMiddleware(); e != nil || len(v) != 0 {
		t.Fatalf("empty middleware=%v err=%v", v, e)
	}
	if _, e := s.GetTool(999); !errors.Is(e, sql.ErrNoRows) {
		t.Fatalf("missing tool err=%v", e)
	}
	if _, e := s.GetMiddleware(999); e == nil {
		t.Fatalf("missing middleware err=%v", e)
	}
	if e := s.DB().Close(); e != nil {
		t.Fatal(e)
	}
	if v, e := s.ListTools(); e == nil {
		t.Fatalf("closed tools=%v nil error", v)
	}
	if v, e := s.ExposedTools(); e == nil {
		t.Fatalf("closed exposed tools=%v nil error", v)
	}
	if v, e := s.ListPacks(); e == nil {
		t.Fatalf("closed packs=%v nil error", v)
	}
	if v, e := s.ListMiddleware(); e == nil {
		t.Fatalf("closed middleware=%v nil error", v)
	}
}
