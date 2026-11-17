package app

import (
	"action2mcp/internal/store"
	"encoding/json"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// moduleRoot is the repository root. Tests used to read README.md and web/
// relative to the package directory when that package was the module root.
func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "\n…[已截断]"
	}
	return s
}

// Independent schema/limit expectations: repository internals stay private and
// an unintended schema-version bump fails these integration tests.
const (
	wantSchemaUserVersion = 12
	packGuideLimitBytes   = 8 * 1024
)

func tableHasColumn(s *store.Store, table, col string) bool {
	rows, err := s.DB().Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil && name == col {
			return true
		}
	}
	return false
}

func now() string { return time.Now().Format("2006-01-02 15:04:05") }

func js(v any) string { b, _ := json.Marshal(v); return string(b) }
