package app

import (
	sitecfg "action2mcp/internal/site"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestCancelLoginRequiresConsoleOrigin(t *testing.T) {
	a, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Shutdown()
	a.cfg.Port = 19001
	s := &sitecfg.Site{Origin: "https://app.example.com", Method: sitecfg.MethodManual}
	if err := a.store.SaveSite(s); err != nil {
		t.Fatal(err)
	}
	handler := a.Handler()
	good := fmt.Sprintf("http://127.0.0.1:%d", a.cfg.Port)
	w := approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/sites/%d/cancel", s.ID), "", "application/json", map[string]any{})
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing origin: %d", w.Code)
	}
	w = approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/sites/%d/cancel", s.ID), "http://evil.example", "application/json", map[string]any{})
	if w.Code != http.StatusForbidden {
		t.Fatalf("evil origin: %d", w.Code)
	}
	w = approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/sites/%d/cancel", s.ID), good, "application/json", map[string]any{})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("no pending login should be 400, got %d", w.Code)
	}
	var out map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	msg, _ := out["error"].(string)
	if !strings.Contains(msg, "没有等待") {
		t.Fatalf("error=%q", msg)
	}
}
