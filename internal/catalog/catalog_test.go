package catalog

import (
	"action2mcp/internal/execution"
	"action2mcp/internal/site"
	"strings"
	"testing"
)

type memoryRepository struct {
	saved []*execution.Tool
	sites []string
}

func (m *memoryRepository) SaveTool(t *execution.Tool) error {
	m.saved = append(m.saved, t)
	return nil
}
func (m *memoryRepository) EnsureSite(raw string) *site.Site {
	m.sites = append(m.sites, raw)
	return nil
}

type fakeSecrets map[string]string

func (f fakeSecrets) ToRefs(s string) string {
	for name, value := range f {
		s = strings.ReplaceAll(s, value, "{{secret."+name+"}}")
	}
	return s
}
func (f fakeSecrets) Lookup(name string) (string, bool) { v, ok := f[name]; return v, ok }

func TestPersistRefsValidatesAndBroadcasts(t *testing.T) {
	repo := &memoryRepository{}
	changed, marked := 0, 0
	c := New(Options{Repository: repo, Secrets: fakeSecrets{"tok": "plain-token-123"},
		MarkSecretParams: func(*execution.Tool) { marked++ }, ToolsChanged: func() { changed++ }})
	tool := &execution.Tool{Name: "lookup", Method: "GET", URL: "http://127.0.0.1:9/x?t=plain-token-123", Headers: map[string]string{}}
	if err := c.Persist(tool); err != nil {
		t.Fatal(err)
	}
	if len(repo.saved) != 1 || strings.Contains(tool.URL, "plain-token-123") || !tool.AllowDisableGuard || marked != 1 || changed != 1 || len(repo.sites) != 1 {
		t.Fatalf("persist = %+v saved=%d marked=%d changed=%d sites=%v", tool, len(repo.saved), marked, changed, repo.sites)
	}
	for _, reserved := range []string{"list_packs", "rec_list_recordings"} {
		if err := c.Validate(&execution.Tool{Name: reserved, Method: "GET", URL: "http://127.0.0.1:9/"}); err == nil {
			t.Fatalf("reserved name %s accepted", reserved)
		}
	}
	missing := &execution.Tool{Name: "ref", Method: "GET", URL: "http://127.0.0.1:9/{{secret.absent}}", Headers: map[string]string{}}
	if err := c.Persist(missing); err == nil || len(repo.saved) != 1 || changed != 1 {
		t.Fatal("missing vault reference must fail before any write or broadcast")
	}
}
