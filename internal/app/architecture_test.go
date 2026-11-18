package app

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestFeaturePackageDependencyDirection(t *testing.T) {
	allowed := map[string]map[string]bool{
		"config":     {},
		"credential": {},
		"vault":      {"credential": true, "ahocorasick": true},
		"recording":  {"cdp": true},
		"site":       {"credential": true, "recording": true, "domain": true},
		"mcp":        {},
		"middleware": {},
		"domain":     {},
		"mwconfig":   {"credential": true, "domain": true, "execution": true},
		"store":      {"approval": true, "domain": true, "execution": true, "mwconfig": true, "recording": true, "site": true},
		"browser":    {"cdp": true, "domain": true, "execution": true, "recording": true, "site": true},
		"login":      {"browser": true, "credential": true, "execution": true, "site": true, "vault": true},
		"approval":   {"domain": true, "vault": true},
		"result":     {"domain": true, "htmlmd": true},
		"execution":  {"credential": true, "domain": true, "vault": true, "htmlmd": true, "sqlguard": true, "recording": true, "result": true},
		"updater":    {},
	}
	for pkg, dependencies := range allowed {
		entries, err := os.ReadDir(filepath.Join(moduleRoot(t), "internal", pkg))
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(moduleRoot(t), "internal", pkg, entry.Name()), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range file.Imports {
				path, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				if imp.Name != nil && imp.Name.Name == "." {
					t.Errorf("%s/%s: dot import hides boundary", pkg, entry.Name())
				}
				if strings.HasPrefix(path, "action2mcp/") {
					dependency := strings.TrimPrefix(path, "action2mcp/internal/")
					if !dependencies[dependency] {
						t.Errorf("%s/%s: forbidden application dependency %s", pkg, entry.Name(), path)
					}
				}
			}
		}
	}
}

// App is the composition root: lifecycle, CLI and service wiring only. Feature
// behaviour belongs to the packages listed in TestFeaturePackageDependencyDirection.
func TestAppIsCompositionOnly(t *testing.T) {
	allowed := map[string]bool{"app.go": true, "cli.go": true, "compose.go": true, "browser_adapter.go": true,
		"execution_adapter.go": true, "login_adapter.go": true, "proc_unix.go": true, "proc_windows.go": true}
	entries, err := os.ReadDir(filepath.Join(moduleRoot(t), "internal", "app"))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go") && !allowed[name] {
			t.Errorf("internal/app/%s: feature code must live in its own package", name)
		}
	}
}
