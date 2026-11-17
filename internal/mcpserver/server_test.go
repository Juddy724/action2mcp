package mcpserver

import (
	"action2mcp/internal/analysis"
	"action2mcp/internal/execution"
	"action2mcp/internal/invoke"
	"action2mcp/internal/mcp"
	"action2mcp/internal/mwconfig"
	"action2mcp/internal/mwtools"
	"action2mcp/internal/store"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

type emptyRepository struct{ mode string }

func (emptyRepository) ExposedMiddleware() ([]*mwconfig.Middleware, map[int64][]string) {
	return nil, nil
}
func (emptyRepository) ExposedTools() ([]*execution.Tool, error)        { return nil, nil }
func (r emptyRepository) GetSetting(key, def string) string             { return r.mode }
func (emptyRepository) GetTool(int64) (*execution.Tool, error)          { return nil, nil }
func (emptyRepository) ListMiddleware() ([]*mwconfig.Middleware, error) { return nil, nil }
func (emptyRepository) ListPacks() ([]*store.Pack, error)               { return nil, nil }

// Framing, sessions and errors must work without touching any collaborator.
func TestServeHTTPFramingWithoutCollaborators(t *testing.T) {
	fail := func(name string) { t.Fatalf("%s collaborator used", name) }
	s := New(Options{Version: "test", Repository: emptyRepository{mode: mcp.ModeFlat}, Sessions: &mcp.Manager{},
		Engine:      func() *execution.Engine { fail("engine"); return nil },
		Analysis:    func() *analysis.Service { fail("analysis"); return nil },
		Middlewares: func() *mwtools.Service { fail("middleware"); return nil },
		Approvals:   func() *invoke.Gateway { fail("approval"); return nil }})
	post := func(body string) (*httptest.ResponseRecorder, map[string]any) {
		w := httptest.NewRecorder()
		s.ServeHTTP(w, httptest.NewRequest("POST", "/mcp", strings.NewReader(body)))
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return w, out
	}
	if w, out := post("{"); w.Code != 400 || out["error"].(map[string]any)["code"] != float64(-32700) {
		t.Fatalf("parse error = %d %v", w.Code, out)
	}
	if _, out := post(`{"jsonrpc":"2.0","id":1,"method":"nope"}`); out["error"].(map[string]any)["code"] != float64(-32601) {
		t.Fatalf("unknown method = %v", out)
	}
	if w, _ := post(`{"jsonrpc":"2.0","method":"notifications/initialized"}`); w.Code != 202 {
		t.Fatalf("notification status = %d", w.Code)
	}
	if _, out := post(`{"jsonrpc":"2.0","id":2,"method":"ping"}`); out["result"] == nil {
		t.Fatalf("ping = %v", out)
	}
	if s.Mode() != mcp.ModeFlat || New(Options{Repository: emptyRepository{mode: "bogus"}}).Mode() != mcp.ModeTiered {
		t.Fatal("mode setting must fail closed to tiered")
	}
}

// Moved from App TestToolAnnotationsAndWritePrefix (unsaved WebSocket tools).
func TestToolOpKindWebSocketOverrides(t *testing.T) {
	wsRead := &execution.Tool{Name: "ann_ws_sql", Method: "WS", Config: execution.ToolConfig{SQLGuard: &execution.SQLGuardConfig{Enabled: true}}}
	wsWrite := &execution.Tool{Name: "ann_ws", Method: "WS"}
	if write, wsAnn := toolOpKind(wsRead); write || wsAnn["readOnlyHint"] != true || wsAnn["idempotentHint"] != true {
		t.Fatalf("sql guard WS: write=%v ann=%v", write, wsAnn)
	}
	if write, wsAnn := toolOpKind(wsWrite); !write || wsAnn["destructiveHint"] != false || wsAnn["idempotentHint"] != false || wsAnn["readOnlyHint"] != false {
		t.Fatalf("plain WS: write=%v ann=%v", write, wsAnn)
	}
	forced := &execution.Tool{Name: "ann_ws_force", Method: "WS", Config: execution.ToolConfig{SQLGuard: &execution.SQLGuardConfig{Enabled: true}, OpKind: execution.OpKindWrite}}
	if write, _ := toolOpKind(forced); !write {
		t.Fatal("op_kind=write should override sql guard")
	}
}
