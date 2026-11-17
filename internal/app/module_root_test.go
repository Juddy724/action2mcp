package app

import (
	"path/filepath"
	"runtime"
	"testing"
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
