package app

import (
	"action2mcp/internal/execution"

	"action2mcp/internal/mwconfig"
	"action2mcp/internal/store"
	"action2mcp/internal/vault"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// assertNoConfigTokens fails if a harvested secret appears, or if a
// configuration identifier appears as its own token (not as digits inside a
// longer id such as a customer_id).
func assertNoConfigTokens(t *testing.T, blob, token string, ids ...string) {
	t.Helper()
	if token != "" && strings.Contains(blob, token) {
		t.Fatalf("leaked token in %q", truncate(blob, 240))
	}
	for _, id := range ids {
		if id == "" {
			continue
		}
		if vault.ScrubConfigTokens(blob, []string{id}) != blob {
			t.Fatalf("leaked id token %q in %q", id, truncate(blob, 240))
		}
	}
}

func TestSQLConsoleResultNotOverScrubbed(t *testing.T) {
	const (
		dsID       = "901"
		envID      = "707"
		envType    = "PROD"
		spaceCode  = "spc_alpha"
		customerID = "1190177654321" // contains "901"
		requestID  = "aabbccddeeff00112233445566778899"
		createdAt  = "2026-01-15 10:30:00"
		sqlText    = "SELECT * FROM demo_task WHERE customer_id=1190177654321 AND request_id='aabbccddeeff00112233445566778899' LIMIT 10"
	)
	longCookie := "sess_" + privateTestValue(t)
	longToken := "" // set from fake.token

	fake := newCountingWS(1)
	fake.businessCols = []any{
		map[string]any{"field": "C_1", "title": "id"},
		map[string]any{"field": "C_2", "title": "customer_id"},
		map[string]any{"field": "C_3", "title": "request_id"},
		map[string]any{"field": "C_4", "title": "created_at"},
		map[string]any{"field": "C_5", "title": "note"},
		map[string]any{"field": "C_6", "title": "retry_times"},
		map[string]any{"field": "C_7", "title": "env_label"},
	}
	// note embeds the harvested token so we can assert it IS still masked,
	// and also "LIMIT 10" which a 1-char cookie used to corrupt.
	s := fake.start(t)
	a := approvalTestApp(t)
	if err := a.vault.Upsert("short_pin", "secret", "123", "", ""); err != nil {
		t.Fatal(err)
	}
	longToken = fake.token
	fake.businessRows = []any{map[string]any{
		"C_1": "1001", "C_2": "28000446123474", "C_3": requestID, "C_4": "1700000129021",
		"C_5": "echo raw LIMIT 10",
		"C_6": 10, "C_7": envType,
	}}

	m := sqlConsoleTestMW("sqlconsole", fake.wsURL(s.URL), mwconfig.MWDatasource{
		Alias: "orders", DSID: json.Number(dsID), EnvID: json.Number(envID),
		EnvType: envType, Description: "订单测试库",
	})
	bindCookieHeader(m)
	if err := a.loginRuntime().HarvestRequestHeader("", s.URL, "sso-epctoken", fake.token); err != nil {
		t.Fatal(err)
	}
	if err := a.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}
	if err := a.store.SavePack(&store.Pack{Name: "sql包", Enabled: true, MiddlewareIDs: []int64{m.ID}}); err != nil {
		t.Fatal(err)
	}
	got, err := a.store.GetMiddleware(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	a.store.ReplaceCookies([]Cookie{
		jarSID(s.URL, longCookie),
		{Name: "tips", Value: "0", Domain: jarSID(s.URL, longCookie).Domain, Path: "/", Session: true},
	})

	// MCP schema, description and enum must list the alias and no identifiers.
	var found map[string]any
	for _, item := range a.middlewares().ToolList() {
		if item["name"] == mwconfig.WSSQLQueryTool {
			found = item
			break
		}
	}
	if found == nil {
		t.Fatal("ws_sql_query not listed")
	}
	schemaBlob, _ := json.Marshal(found)
	assertNoConfigTokens(t, string(schemaBlob), longToken, dsID, envID, envType, spaceCode)
	if strings.Contains(string(schemaBlob), longCookie) {
		t.Fatal("schema leaked cookie")
	}
	if !strings.Contains(string(schemaBlob), "orders") {
		t.Fatal("schema should list alias")
	}

	done := make(chan approvalReply, 1)
	go func() {
		v, invErr := invokeTool(a, context.Background(), mwconfig.WSSQLQueryTool, map[string]any{
			"middleware": got.Name, "database": "orders", "sql": sqlText,
		})
		done <- unpackApprovalReply(v, invErr)
	}()
	rec := pendingApprovals(t, a, 1)[0]
	pendingBlob := approvalVisibleBlob(rec)
	assertNoConfigTokens(t, pendingBlob, longToken, dsID, envID, envType, spaceCode)
	if strings.Contains(pendingBlob, longCookie) {
		t.Fatal("preview leaked cookie")
	}
	if rec.Preview.URL != "" && (strings.Contains(rec.Preview.URL, "ws://") || strings.Contains(rec.Preview.URL, "wss://")) {
		t.Fatalf("preview URL leaked address: %s", rec.Preview.URL)
	}
	if !strings.Contains(rec.Preview.URL, "orders") {
		t.Fatalf("preview should show alias, got %q", rec.Preview.URL)
	}
	shownSQL := rec.ArgsDisplay["sql"] + rec.Preview.Body
	if !strings.Contains(shownSQL, "LIMIT 10") {
		t.Fatalf("approval SQL lost LIMIT 10 (over-scrub?): args=%q body=%q", rec.ArgsDisplay["sql"], rec.Preview.Body)
	}
	if strings.Contains(shownSQL, vault.Mask) && strings.Contains(shownSQL, "LIMIT 1"+vault.Mask) {
		t.Fatalf("LIMIT 10 was corrupted by short-value scrub: %q", shownSQL)
	}

	approveRecord(t, a, rec)
	reply := getApprovalReply(t, done)
	if reply.isError {
		t.Fatalf("approved call failed: %s", reply.text)
	}

	// Successful DB query output must come through completely intact (no masking),
	// even when values contain a short Vault secret ("123"), 3-char ds_id, "PROD", "0", or "LIMIT 10".
	for _, want := range []string{"28000446123474", requestID, "1700000129021", "echo raw LIMIT 10", envType, "1001"} {
		if !strings.Contains(reply.text, want) {
			t.Fatalf("result missing %q: %s", want, truncate(reply.text, 400))
		}
	}
	if strings.Contains(reply.text, vault.Mask) {
		t.Fatalf("successful SQL query result should not be masked: %s", truncate(reply.text, 400))
	}

	history, err := a.approvals().List("all", 10)
	if err != nil || len(history) == 0 {
		t.Fatalf("history: %v %d", err, len(history))
	}
	histBlob, _ := json.Marshal(history[0])
	assertNoConfigTokens(t, history[0].Preview.URL+history[0].Preview.Body+history[0].Title, longToken, dsID, envID, spaceCode)
	if strings.Contains(string(histBlob), longToken) || strings.Contains(string(histBlob), longCookie) {
		t.Fatal("history leaked a long secret")
	}
	if strings.Contains(history[0].Preview.URL, dsID) || strings.Contains(history[0].Preview.URL, envID) {
		t.Fatalf("preview leaked ids: %s", history[0].Preview.URL)
	}
	if !strings.Contains(history[0].ArgsDisplay["sql"], "LIMIT 10") && (history[0].FinalArgsDisplay == nil || !strings.Contains(history[0].FinalArgsDisplay["sql"], "LIMIT 10")) {
		t.Fatalf("approval-record SQL lost LIMIT 10: args=%v final=%v", history[0].ArgsDisplay, history[0].FinalArgsDisplay)
	}
	if strings.Contains(history[0].Result, "LIMIT 1"+vault.Mask) || strings.Contains(history[0].ArgsDisplay["sql"], "LIMIT 1"+vault.Mask) {
		t.Fatalf("approval record corrupted LIMIT 10: result=%q args=%v", history[0].Result, history[0].ArgsDisplay)
	}
	if !strings.Contains(history[0].Result, "28000446123474") && !strings.Contains(history[0].Result, approvalResultTruncMark) {
		t.Fatalf("approval result preview lost customer_id: %q", history[0].Result)
	}

	full, _, err := a.approvals().Result(history[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(full, longToken) || strings.Contains(full, longCookie) || strings.Contains(full, dsID+" ") {
		t.Fatalf("stored full result leaked credentials: %q", truncate(full, 240))
	}
	if !strings.Contains(full, "28000446123474") || !strings.Contains(full, "1700000129021") {
		t.Fatalf("stored full result lost unmasked query fields: %q", truncate(full, 240))
	}
	for _, want := range []string{"28000446123474", requestID, "1700000129021", "LIMIT 10", envType} {
		if !strings.Contains(full, want) {
			t.Fatalf("full result missing %q", want)
		}
	}
	_ = customerID
	_ = createdAt

	audit, _ := json.Marshal(a.store.ListAudit(got.Name, 10))
	assertNoConfigTokens(t, string(audit), longToken, envID, spaceCode)
	if strings.Contains(string(audit), longCookie) {
		t.Fatal("audit leaked cookie")
	}
	// Action includes the user SQL, which may contain the same digits as ds_id
	// inside a customer_id; that is not a program-injected identifier.
}

func TestSQLConsoleErrorMasksConfigTokens(t *testing.T) {
	const dsID = "901"
	fake := newCountingWS(1)
	fake.failBusiness = "remote rejected dsId=901 envType=PROD space=spc_alpha token-will-be-set"
	s := fake.start(t)
	a := approvalTestApp(t)
	fake.failBusiness = "remote rejected dsId=901 envType=PROD space=spc_alpha token=" + fake.token

	m := saveSQLConsole(t, a, fake, s.URL, mwconfig.MWDatasource{
		Alias: "orders", DSID: json.Number(dsID), EnvID: json.Number("707"),
		EnvType: "PROD", Description: "订单测试库",
	})

	done := make(chan approvalReply, 1)
	go func() {
		v, invErr := invokeTool(a, context.Background(), mwconfig.WSSQLQueryTool, map[string]any{
			"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t WHERE id=1 LIMIT 1",
		})
		done <- unpackApprovalReply(v, invErr)
	}()
	rec := pendingApprovals(t, a, 1)[0]
	blob := approvalVisibleBlob(rec)
	port := strings.TrimPrefix(s.URL, "http://127.0.0.1:")
	if strings.Contains(blob, port) || strings.Contains(blob, s.URL) || strings.Contains(blob, "707") || strings.Contains(blob, dsID) {
		t.Fatalf("leak port=%s url=%s previewURL=%q headers=%v body=%q title=%q args=%v params=%s blob=%s", port, s.URL, rec.Preview.URL, rec.Preview.Headers, rec.Preview.Body, rec.Title, rec.ArgsDisplay, truncate(string(execution.CompactJSON(rec.Params)), 300), truncate(blob, 800))
	}
	assertHiddenFromAI(t, blob, fake.token, dsID, "707", "PROD", "spc_alpha")
	approveRecord(t, a, rec)
	reply := getApprovalReply(t, done)
	if !reply.isError {
		t.Fatalf("expected execution error, got %q", reply.text)
	}
	assertHiddenFromAI(t, reply.text, fake.token, dsID, "707", "PROD", "spc_alpha")
	if !strings.Contains(reply.text, vault.Mask) {
		t.Fatalf("error should mask config tokens: %q", reply.text)
	}

	history, err := a.approvals().List("all", 10)
	if err != nil || len(history) == 0 {
		t.Fatal("expected approval record")
	}
	assertHiddenFromAI(t, history[0].Result, fake.token, dsID, "707", "PROD", "spc_alpha")
	full, _, err := a.approvals().Result(history[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	assertHiddenFromAI(t, full, fake.token, dsID, "707", "PROD", "spc_alpha")
}
