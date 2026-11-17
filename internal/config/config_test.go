package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadFileAndEnvironmentPrecedence(t *testing.T) {
	for _, key := range []string{"A2M_PORT", "A2M_BROWSER", "A2M_NO_SANDBOX"} {
		t.Setenv(key, "")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.json"), []byte(`{"port":17999,"browser":"fixture-chrome","browser_args":["--fixture"],"open_console":false}`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := LoadConfig(dir)
	if cfg.Port != 17999 || cfg.Browser != "fixture-chrome" || len(cfg.BrowserArgs) != 1 || cfg.OpenConsole == nil || *cfg.OpenConsole {
		t.Fatalf("file configuration: %#v", cfg)
	}
	t.Setenv("A2M_PORT", "18000")
	t.Setenv("A2M_BROWSER", "override-chrome")
	t.Setenv("A2M_NO_SANDBOX", "1")
	cfg = LoadConfig(dir)
	if cfg.Port != 18000 || cfg.Browser != "override-chrome" || !cfg.NoSandbox {
		t.Fatalf("environment override: %#v", cfg)
	}
	t.Setenv("A2M_PORT", "0")
	if got := LoadConfig(dir).Port; got != 7788 {
		t.Fatalf("zero fallback: %d", got)
	}
}

func TestDataDirectorySelection(t *testing.T) {
	t.Setenv("A2M_DATA", "relative-fixture")
	want, err := filepath.Abs("relative-fixture")
	if err != nil {
		t.Fatal(err)
	}
	if got := ResolveDataDir(); got != want {
		t.Fatalf("relative override: %q, want %q", got, want)
	}
	t.Setenv("A2M_DATA", "")
	if got := ResolveDataDir(); got != filepath.Join(exeDir(), "data") {
		t.Fatalf("executable-relative data: %q", got)
	}
}
