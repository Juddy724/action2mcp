package transfer

import (
	"action2mcp/internal/domain"
	"action2mcp/internal/execution"
	"action2mcp/internal/store"
	"action2mcp/internal/vault"
	"path/filepath"
	"strings"
	"testing"
)

func testService(t *testing.T) (*Service, *store.Store, *vault.Vault, *[]int64) {
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
	dropped := &[]int64{}
	return New(Options{Repository: st, Secrets: v, MarkSecretParams: func(*execution.Tool) {},
		DropDriver: func(id int64) { *dropped = append(*dropped, id) }}), st, v, dropped
}

func TestRoundTripNeverCarriesSecretValues(t *testing.T) {
	src, st, v, _ := testService(t)
	secret := "transfer-secret-value-7f3a"
	if err := v.Upsert("api_token", "secret", secret, "", ""); err != nil {
		t.Fatal(err)
	}
	tool := &execution.Tool{Name: "lookup", Method: "GET", URL: "http://127.0.0.1:9/x?t=" + secret, Approval: "always",
		Params: []domain.Param{{Name: "q", Type: "string"}}}
	if err := st.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	if err := st.SavePack(&store.Pack{Name: "p", Enabled: true, ToolIDs: []int64{tool.ID}}); err != nil {
		t.Fatal(err)
	}
	data, err := src.Export()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) || !strings.Contains(string(data), "{{secret.api_token}}") {
		t.Fatalf("export leaked or lost the secret reference: %s", data)
	}
	dst, other, ov, _ := testService(t)
	res, err := dst.Import(data)
	if err != nil || res.ToolsAdded != 1 || res.PacksAdded != 1 {
		t.Fatalf("import = %+v %v", res, err)
	}
	if got, ok := ov.Lookup("api_token"); !ok || got != "" {
		t.Fatalf("import must create an empty placeholder, got %q %v", got, ok)
	}
	imported, err := other.GetToolByName("lookup")
	if err != nil || imported.Approval != "always" || !strings.Contains(imported.URL, "{{secret.api_token}}") {
		t.Fatalf("imported tool = %+v %v", imported, err)
	}
}
