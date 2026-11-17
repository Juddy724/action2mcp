package execution

import (
	"action2mcp/internal/domain"
	"action2mcp/internal/vault"
	"testing"
)

func TestApprovalPublicMaskTokenIsLiteral(t *testing.T) {
	a := New(Options{})
	for _, body := range []string{`{"data":{{label}}}`, `{"data":"{{label}}"}`, "label={{label}}"} {
		tool := &Tool{Method: "POST", URL: "https://example.com/api?label={{label}}", Body: body, Params: []domain.Param{{Name: "label", Type: "string"}}}
		p, err := a.Prepare(tool, map[string]any{"label": vault.Mask})
		if err != nil || p.Preview.Body != p.request.Body || p.Preview.URL != p.request.URL || a.ApprovalArgs(tool, map[string]any{"label": vault.Mask}, nil)["label"] != vault.Mask {
			t.Fatal("public mask literal changed during preview rendering")
		}
	}
}
