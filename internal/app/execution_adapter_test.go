package app

import (
	"action2mcp/internal/domain"
	"testing"
)

// Expected wire data comes from the public renderer, not the frozen prepared object.
// Owner tests independently inspect the frozen representation without exposing it.
func renderForTest(t *testing.T, tool *Tool, args map[string]any) domain.RequestPreview {
	t.Helper()
	m, u, h, b, err := tool.Render(args)
	if err != nil {
		t.Fatal(err)
	}
	return domain.RequestPreview{Method: m, URL: u, Headers: h, Body: b}
}
