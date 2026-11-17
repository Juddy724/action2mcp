package console

import (
	"action2mcp/internal/analysis"
	"action2mcp/internal/catalog"
	"action2mcp/internal/execution"
	"action2mcp/internal/invoke"
	"action2mcp/internal/mcp"
	"action2mcp/internal/mcpserver"
	"action2mcp/internal/mwtools"
	"action2mcp/internal/store"
	"action2mcp/internal/transfer"
	"action2mcp/internal/vault"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// The console is wired only through Options; read-only catalog routes must not
// reach any runtime collaborator, and the loopback guard applies to every route.
func TestConsoleRoutesUseOnlyInjectedPorts(t *testing.T) {
	st, err := store.OpenStore(filepath.Join(t.TempDir(), "a2m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.DB().Close() })
	v, err := vault.OpenVault(st.DB(), filepath.Join(t.TempDir(), "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SaveTool(&execution.Tool{Name: "listed_tool", Method: "GET", URL: "http://127.0.0.1:9/x"}); err != nil {
		t.Fatal(err)
	}
	fail := func(name string) { t.Fatalf("%s collaborator used by a read-only route", name) }
	s := New(Options{Port: 1, Store: st, Vault: v, Sessions: &mcp.Manager{}, Quit: make(chan struct{}),
		Status: func() any { fail("status"); return nil }, Shutdown: func() { fail("shutdown") }, Exit: func() { fail("exit") },
		Browser:      func() Browser { fail("browser"); return nil },
		Login:        func() Login { fail("login"); return nil },
		Engine:       func() *execution.Engine { fail("engine"); return nil },
		Analysis:     func() *analysis.Service { fail("analysis"); return nil },
		Middlewares:  func() *mwtools.Service { fail("middleware"); return nil },
		Approvals:    func() *invoke.Gateway { fail("approvals"); return nil },
		Transfer:     func() *transfer.Service { fail("transfer"); return nil },
		Tools:        func() *catalog.Service { fail("catalog"); return nil },
		MCPServer:    func() *mcpserver.Server { return mcpserver.New(mcpserver.Options{}) }, // resolved at route registration
		ToolsChanged: func() { fail("tools changed") }, DropDriver: func(int64) { fail("drivers") }})
	h := s.Handler()
	req := httptest.NewRequest("GET", "/api/tools", nil)
	req.Host = "127.0.0.1"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "listed_tool") {
		t.Fatalf("GET /api/tools = %d %s", w.Code, w.Body.String())
	}
	remote := httptest.NewRequest("GET", "/api/tools", nil)
	remote.Host = "evil.example"
	w = httptest.NewRecorder()
	h.ServeHTTP(w, remote)
	if w.Code != 403 {
		t.Fatalf("non-loopback host = %d", w.Code)
	}
}
