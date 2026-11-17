package app

import (
	"action2mcp/internal/mcp"
	"action2mcp/internal/store"
	"action2mcp/internal/vault"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPackGuide(t *testing.T) {
	const secret = "Guide-S3cret!pw"
	const marker = "先调用 echo_login，把返回的 id 填到下一步。"
	app, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	if err := app.vault.Upsert("svc_password", "secret", secret, "", ""); err != nil {
		t.Fatal(err)
	}
	tool := &Tool{Name: "echo_login", Title: "回显", Method: "GET", URL: "https://example.com/echo"}
	if err := app.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	guide := marker + " 密文 " + secret + " 不能出现。引用 {{secret.svc_password}} 保持原样。"
	p := &store.Pack{Name: "回显包", Description: "回显", Scenarios: "需要回显时", Guide: guide, Enabled: true, ToolIDs: []int64{tool.ID}}
	if err := app.store.SavePack(p); err != nil {
		t.Fatal(err)
	}
	if err := app.store.SavePack(&store.Pack{Name: "空说明", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := app.store.SavePack(&store.Pack{Name: "关闭的包", Guide: "隐藏说明MARKER", Enabled: false}); err != nil {
		t.Fatal(err)
	}
	if err := app.store.SavePack(&store.Pack{Name: "刚好", Guide: strings.Repeat("a", packGuideLimitBytes), Enabled: true}); err != nil {
		t.Fatal(err)
	}
	if err := app.store.SavePack(&store.Pack{Name: "太大", Guide: strings.Repeat("a", packGuideLimitBytes+1)}); err == nil {
		t.Fatal("oversize guide accepted")
	}

	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	c := &mcpTestClient{t: t, url: srv.URL + "/mcp"}
	_, init := c.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "guide-test"}})
	instr := init["result"].(map[string]any)["instructions"].(string)
	if strings.Contains(instr, marker) || strings.Contains(instr, secret) {
		t.Fatalf("tiered instructions leaked the guide: %s", instr)
	}

	listed, _ := c.tool("list_packs", map[string]any{})
	if strings.Contains(listed, marker) || strings.Contains(listed, secret) || strings.Contains(listed, `"guide"`) {
		t.Fatalf("list_packs included the guide: %s", listed)
	}
	loaded, isErr := c.tool("load_pack", map[string]any{"pack": "回显包"})
	if isErr || !strings.Contains(loaded, marker) || !strings.Contains(loaded, "{{secret.svc_password}}") || !strings.Contains(loaded, "先按 guide") || strings.Contains(loaded, secret) {
		t.Fatalf("load_pack guide: %s", loaded)
	}
	again, _ := c.tool("load_pack", map[string]any{"pack": "回显包"})
	if !strings.Contains(again, marker) {
		t.Fatal("guide missing on repeated load")
	}
	empty, isErr := c.tool("load_pack", map[string]any{"pack": "空说明"})
	if isErr || !strings.Contains(empty, `"guide":""`) || strings.Contains(empty, "先按 guide") {
		t.Fatalf("empty guide: %s", empty)
	}

	app.store.SetSetting("mcp_mode", mcp.ModeFlat)
	flat := &mcpTestClient{t: t, url: srv.URL + "/mcp"}
	_, finit := flat.call("initialize", map[string]any{"protocolVersion": "2025-06-18"})
	finstr := finit["result"].(map[string]any)["instructions"].(string)
	if !strings.Contains(finstr, marker) || !strings.Contains(finstr, "{{secret.svc_password}}") || !strings.Contains(finstr, "回显包") || strings.Contains(finstr, secret) || strings.Contains(finstr, "隐藏说明MARKER") {
		t.Fatalf("flat instructions: %s", finstr)
	}

	exp, err := app.transfer().Export()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(exp), secret) || !strings.Contains(string(exp), "{{secret.svc_password}}") || !strings.Contains(string(exp), `"guide"`) {
		t.Fatalf("export guide: %s", exp)
	}

	old, err := app.store.ListPacks()
	if err != nil {
		t.Fatal(err)
	}
	var stored string
	for _, x := range old {
		if x.Name == "回显包" {
			stored = x.Guide
		}
	}
	if !strings.Contains(stored, secret) {
		t.Fatal("stored guide was scrubbed in place")
	}
	keep, err := app.transfer().Import([]byte(`{"format":"action2mcp","packs":[{"name":"回显包","description":"imported","enabled":true,"tools":["echo_login"]}]}`))
	if err != nil || keep.PacksUpdated != 1 {
		t.Fatalf("import missing guide: %+v %v", keep, err)
	}
	if g := packGuide(t, app, "回显包"); g != stored {
		t.Fatalf("missing guide field cleared it: %q", g)
	}
	if _, err := app.transfer().Import(exp); err != nil {
		t.Fatal(err)
	}
	if g := packGuide(t, app, "回显包"); strings.Contains(g, secret) || !strings.Contains(g, vault.Mask) || !strings.Contains(g, "{{secret.svc_password}}") {
		t.Fatalf("round trip guide: %q", g)
	}
	if _, err := app.transfer().Import([]byte(`{"format":"action2mcp","packs":[{"name":"回显包","description":"imported","enabled":true,"guide":"","tools":["echo_login"]}]}`)); err != nil {
		t.Fatal(err)
	}
	if g := packGuide(t, app, "回显包"); g != "" {
		t.Fatalf("explicit empty guide did not clear: %q", g)
	}
	if _, err := app.transfer().Import([]byte(`{"format":"action2mcp","packs":[{"name":"回显包","enabled":true,"guide":"新说明","tools":["echo_login"]}]}`)); err != nil {
		t.Fatal(err)
	}
	if g := packGuide(t, app, "回显包"); g != "新说明" {
		t.Fatalf("guide = %q", g)
	}
	huge, _ := json.Marshal(map[string]any{"format": "action2mcp", "packs": []map[string]any{{
		"name": "回显包", "enabled": true, "guide": strings.Repeat("b", packGuideLimitBytes+1), "tools": []string{"echo_login"},
	}}})
	if _, err := app.transfer().Import(huge); err == nil {
		t.Fatal("oversize import accepted")
	}
	if g := packGuide(t, app, "回显包"); g != "新说明" {
		t.Fatalf("oversize import changed guide: %q", g)
	}
}

func packGuide(t *testing.T, app *App, name string) string {
	t.Helper()
	packs, err := app.store.ListPacks()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range packs {
		if p.Name == name {
			return p.Guide
		}
	}
	t.Fatalf("pack %s missing", name)
	return ""
}
