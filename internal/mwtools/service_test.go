package mwtools

import (
	"action2mcp/internal/execution"
	"action2mcp/internal/invoke"
	"action2mcp/internal/middleware"
	"action2mcp/internal/store"
	"action2mcp/internal/vault"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"testing"
)

type testFixture struct {
	store *store.Store
	vault *vault.Vault
}

// testService wires the real repository, vault and drivers. Login, engine and
// approvals are deliberately absent: native/catalog paths must not need them.
func testService(t *testing.T) (*Service, testFixture) {
	t.Helper()
	st, err := store.OpenStore(filepath.Join(t.TempDir(), "a2m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB().Close() })
	v, err := vault.OpenVault(st.DB(), filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	s := New(Options{Repository: st, Secrets: v, Drivers: &middleware.Drivers{},
		Cookies:   func(string) ([]execution.Cookie, string) { return nil, "" },
		Login:     func() Login { t.Fatal("login runtime used"); return nil },
		Engine:    func() *execution.Engine { t.Fatal("execution engine used"); return nil },
		Approvals: func() *invoke.Gateway { t.Fatal("approval gateway used"); return nil }})
	return s, testFixture{st, v}
}

func privateTestValue(t *testing.T) string {
	t.Helper()
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal("cannot create test value")
	}
	return hex.EncodeToString(b[:])
}

func TestCallUnexposedMiddlewareIsAuditedWithoutCollaborators(t *testing.T) {
	s, fx := testService(t)
	secret := privateTestValue(t)
	if err := fx.vault.Upsert("leak", "secret", secret, "", ""); err != nil {
		t.Fatal(err)
	}
	text, isErr := s.Call(t.Context(), "client-"+secret, "db_query", map[string]any{"middleware": "missing"})
	if !isErr || text == "" {
		t.Fatalf("unknown middleware call = %q %v", text, isErr)
	}
	entries := fx.store.ListAudit("missing", 10)
	if len(entries) != 1 || entries[0].Allowed || entries[0].Tool != "db_query" || entries[0].Client == "client-"+secret {
		t.Fatalf("denial audit = %+v", entries)
	}
	if def, ok := IsTool("ws_sql_query"); !ok || def.Type != "websocket" {
		t.Fatal("SQL console tool missing from catalog")
	}
	if len(s.ToolList()) != 0 {
		t.Fatal("no exposed middleware must yield no tools")
	}
}
