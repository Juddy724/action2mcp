package app

import (
	"action2mcp/internal/domain"
	"action2mcp/internal/execution"
	"action2mcp/internal/mcp"
	"action2mcp/internal/store"
	"action2mcp/internal/vault"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func wrapApprovalJSONDepth(inner string, depth int) string {
	return strings.Repeat("[", depth) + inner + strings.Repeat("]", depth)
}

func assertNoSecretLeak(t *testing.T, where, text, secret string) {
	t.Helper()
	if secret == "" || secret == vault.Mask {
		t.Fatal("invalid secret fixture")
	}
	if strings.Contains(text, secret) {
		t.Fatalf("%s leaked the secret", where)
	}
	jb, _ := json.Marshal(secret)
	for _, variant := range []string{
		url.QueryEscape(secret),
		url.PathEscape(secret),
		html.EscapeString(secret),
		string(jb[1 : len(jb)-1]),
		base64.StdEncoding.EncodeToString([]byte(secret)),
		base64.RawStdEncoding.EncodeToString([]byte(secret)),
		base64.URLEncoding.EncodeToString([]byte(secret)),
		base64.RawURLEncoding.EncodeToString([]byte(secret)),
		base64.RawStdEncoding.EncodeToString([]byte(secret)) + ",",
	} {
		if variant != "" && variant != secret && strings.Contains(text, variant) {
			t.Fatalf("%s leaked an encoded secret", where)
		}
	}
}

func TestMCPSecretParamDefaultsHidden(t *testing.T) {
	const (
		flagSecret    = "SchemaFlagSecret-R7/x"
		keySecret     = "SchemaKeySecret-R7/y"
		posSecret     = "SchemaPosSecret-R7/z"
		publicDefault = "visible-public-default"
	)
	app, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	tool := &Tool{
		Name:        "schema_secret",
		Title:       "Schema",
		Description: "flag uses " + flagSecret + " in the tool text",
		Method:      "POST",
		URL:         "https://example.com/echo",
		Headers:     map[string]string{"Content-Type": "application/json"},
		Body:        `{"token":{{token}},"password":{{password}},"authorization":{{label}},"note":{{note}}}`,
		Params: []domain.Param{
			{Name: "token", Type: "string", Secret: true, Default: flagSecret, Description: "token default " + flagSecret},
			{Name: "password", Type: "string", Default: keySecret},
			{Name: "label", Type: "string", Default: posSecret},
			{Name: "note", Type: "string", Default: publicDefault},
		},
	}
	if err := app.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	if err := app.store.SavePack(&store.Pack{Name: "脱敏包", Description: "desc " + flagSecret, Scenarios: "scene " + keySecret, Enabled: true, ToolIDs: []int64{tool.ID}}); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	forbid := func(where, text string) {
		t.Helper()
		for _, secret := range []string{flagSecret, keySecret, posSecret} {
			assertNoSecretLeak(t, where, text, secret)
		}
	}

	c := &mcpTestClient{t: t, url: srv.URL + "/mcp"}
	_, init := c.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "schema-test"}})
	forbid("tiered initialize", string(execution.CompactJSON(init)))
	listedPacks, _ := c.tool("list_packs", map[string]any{})
	forbid("list_packs", listedPacks)
	loaded, isErr := c.tool("load_pack", map[string]any{"pack": "脱敏包"})
	if isErr {
		t.Fatalf("load_pack failed: %s", loaded)
	}
	forbid("load_pack", loaded)
	if !strings.Contains(loaded, publicDefault) {
		t.Fatal("load_pack hid a public parameter default")
	}
	_, listed := c.call("tools/list", map[string]any{})
	forbid("tiered tools/list", string(execution.CompactJSON(listed)))

	if err := app.store.SetSetting("mcp_mode", mcp.ModeFlat); err != nil {
		t.Fatal(err)
	}
	flat := &mcpTestClient{t: t, url: srv.URL + "/mcp"}
	_, finit := flat.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "schema-flat"}})
	forbid("flat initialize", string(execution.CompactJSON(finit)))
	_, flist := flat.call("tools/list", map[string]any{})
	body := string(execution.CompactJSON(flist))
	forbid("flat tools/list", body)
	if !strings.Contains(body, publicDefault) {
		t.Fatal("tools/list hid a public parameter default")
	}
}

func TestMCPLimitedTemplateSecretsScrubbed(t *testing.T) {
	secret := "LimitSecretValue-R7/deep"
	body := wrapApprovalJSONDepth(`{"password":"`+secret+`"}`, vault.MaxDecodeDepth+1)

	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		if strings.Contains(string(data), secret) {
			w.WriteHeader(http.StatusBadGateway)
			io.WriteString(w, "echo "+secret)
			return
		}
		io.WriteString(w, "ok")
	}))
	a := approvalTestApp(t)
	tool, _ := saveApprovalTool(t, a, upstream, "off")
	tool.Body = body
	tool.Params = nil
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	prepared, err := a.executor().Prepare(tool, map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if a.executor().ScrubPrepared(secret, prepared, false) != vault.Mask {
		t.Fatal("prepared secretValues omitted the limited literal")
	}
	res, err := a.executor().Send(prepared)
	if err != nil {
		t.Fatal(err)
	}
	assertNoSecretLeak(t, "Send body", res.Body, secret)
	assertNoSecretLeak(t, "scrubbed error", a.executor().ScrubPrepared("upstream echoed "+secret, prepared, false), secret)

	reply := getApprovalReply(t, startApprovalCall(a, context.Background(), map[string]any{}))
	assertNoSecretLeak(t, "MCP call result", reply.text, secret)

	a.httpClient = &http.Client{Transport: approvalRoundTripper(func(r *http.Request) (*http.Response, error) {
		data, _ := io.ReadAll(r.Body)
		return nil, fmt.Errorf("upstream: %s", data)
	})}
	tool.Approval = "always"
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	call := startApprovalCall(a, ctx, map[string]any{})
	pending := pendingApprovals(t, a, 1)[0]
	approveRecord(t, a, pending)
	errReply := getApprovalReply(t, call)
	assertNoSecretLeak(t, "MCP error result", errReply.text, secret)
	rows, err := a.approvals().List("all", 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		assertNoSecretLeak(t, "approvals.result", row.Result, secret)
		assertNoSecretLeak(t, "approval preview", string(execution.CompactJSON(row.Preview)), secret)
	}
}

func TestVaultScrubEncodingAndPackGuide(t *testing.T) {
	const secret = "a/bc"
	app, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	if err := app.vault.Upsert("svc_token", "secret", secret, "", ""); err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawStdEncoding.EncodeToString([]byte(secret)) + ","
	if !strings.Contains(encoded, "YS9iYw") {
		t.Fatalf("fixture encoding changed: %q", encoded)
	}
	if strings.Contains(app.vault.Scrub("guide "+encoded+" end"), "YS9iYw") {
		t.Fatal("Vault.Scrub leaked an unpadded base64 secret")
	}
	assertNoSecretLeak(t, "Vault.Scrub", app.vault.Scrub("guide "+encoded+" "+secret), secret)

	tool := &Tool{Name: "guide_echo", Title: "回显", Method: "GET", URL: "https://example.com/echo"}
	if err := app.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	guide := "先调用 guide_echo。密文 " + encoded + " 不能出现。引用 {{secret.svc_token}} 保持原样。"
	if err := app.store.SavePack(&store.Pack{Name: "回显包", Description: "回显", Enabled: true, Guide: guide, ToolIDs: []int64{tool.ID}}); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(app.Handler())
	defer srv.Close()
	c := &mcpTestClient{t: t, url: srv.URL + "/mcp"}
	_, init := c.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "guide-enc"}})
	assertNoSecretLeak(t, "tiered initialize", string(execution.CompactJSON(init)), secret)
	loaded, isErr := c.tool("load_pack", map[string]any{"pack": "回显包"})
	if isErr || !strings.Contains(loaded, "{{secret.svc_token}}") {
		t.Fatalf("load_pack: %s", loaded)
	}
	assertNoSecretLeak(t, "load_pack guide", loaded, secret)

	if err := app.store.SetSetting("mcp_mode", mcp.ModeFlat); err != nil {
		t.Fatal(err)
	}
	flat := &mcpTestClient{t: t, url: srv.URL + "/mcp"}
	_, finit := flat.call("initialize", map[string]any{"protocolVersion": "2025-06-18"})
	instr := finit["result"].(map[string]any)["instructions"].(string)
	if !strings.Contains(instr, "{{secret.svc_token}}") {
		t.Fatal("flat initialize dropped the secret reference")
	}
	assertNoSecretLeak(t, "flat initialize", string(execution.CompactJSON(finit)), secret)
}
