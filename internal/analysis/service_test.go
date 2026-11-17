package analysis

import (
	"action2mcp/internal/execution"
	"action2mcp/internal/store"
	"action2mcp/internal/vault"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func decodeRec(t *testing.T, text string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("invalid JSON: %v: %s", err, text)
	}
	return out
}

// testService wires the real repository and vault; collaborators that would reach
// MCP/console/login are recorded instead of being reachable through an App.
func testService(t *testing.T) (*Service, *store.Store) {
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
	return New(Options{Repository: st, Vault: v,
		InputSchema:  func(*execution.Tool) map[string]any { return map[string]any{} },
		ValidateTool: func(*execution.Tool) error { return nil }, ToolsChanged: func() {}, ResetLoginFailures: func() {}}), st
}

// Moved from App TestReview051Finding01FailClosedStructured (direct sanitizer part).
func TestSanitizeDepthFailsClosed(t *testing.T) {
	a, _ := testService(t)
	deep := "depth-FAKE-token-xyz"
	for i := 0; i < 8; i++ {
		deep = string(execution.CompactJSON(map[string]any{"wrap": deep}))
	}
	if got := a.sanitizeString(deep, false, 0, nil); strings.Contains(got, "depth-FAKE-token-xyz") || !strings.Contains(got, structuredOmitted) {
		t.Fatalf("depth did not fail closed: %s", got)
	}
}

// Moved from App TestRecSecurityHeadersEscapesAndShortValues (direct replacement part).
func TestReplaceLiteralsEscapedAndShortTokens(t *testing.T) {
	if replaceLiterals(`echo=a\"b and a"b`, []string{`a"b`}) != "echo=****** and ******" {
		t.Fatal("JSON escaped form was not scrubbed")
	}
	if got := replaceLiterals("7 17 7.0", []string{"7"}); got != "****** 17 ******.0" {
		t.Fatalf("short token mask: %q", got)
	}
}

// Moved from App TestRecParamSourcesAndPackResolution (numeric pack resolution part).
func TestLookupTargetPackNumericID(t *testing.T) {
	a, st := testService(t)
	ops := &store.Pack{Name: "Ops", Enabled: true}
	if err := st.SavePack(ops); err != nil {
		t.Fatal(err)
	}
	if p, _, msg := a.lookupTargetPack(fmt.Sprint(ops.ID), false); msg != "" || p.ID != ops.ID {
		t.Fatalf("numeric pack match: %v %s", p, msg)
	}
	if p, _, msg := a.lookupTargetPack(fmt.Sprint(store.RecordingPackID), false); p != nil || !strings.Contains(msg, "不能把工具保存到内置包") {
		t.Fatalf("built-in pack accepted as save target: %v %s", p, msg)
	}
	if p, _, msg := a.lookupTargetPack("9999", true); p != nil || !strings.Contains(msg, "不会用来新建流程包") {
		t.Fatalf("numeric reference created or matched a pack: %v %s", p, msg)
	}
}
