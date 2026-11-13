package main

import (
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
		if scrubConfigTokens(blob, []string{id}) != blob {
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
	longToken = fake.token
	fake.businessRows = []any{map[string]any{
		"C_1": "1001", "C_2": customerID, "C_3": requestID, "C_4": createdAt,
		"C_5": "echo " + longToken + " LIMIT 10",
		"C_6": 10, "C_7": envType,
	}}

	m := sqlConsoleTestMW("sqlconsole", fake.wsURL(s.URL), MWDatasource{
		Alias: "orders", DSID: json.Number(dsID), EnvID: json.Number(envID),
		EnvType: envType, Description: "订单测试库",
	})
	bindCookieHeader(m)
	if err := a.HarvestRequestHeader("", s.URL, "sso-epctoken", fake.token); err != nil {
		t.Fatal(err)
	}
	if err := a.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}
	if err := a.store.SavePack(&Pack{Name: "sql包", Enabled: true, MiddlewareIDs: []int64{m.ID}}); err != nil {
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
	for _, item := range a.mwToolList() {
		if item["name"] == wsSQLQueryTool {
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
		v, invErr := a.invokeTool(context.Background(), &mcpCtx{}, wsSQLQueryTool, map[string]any{
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
	if strings.Contains(shownSQL, secretMask) && strings.Contains(shownSQL, "LIMIT 1"+secretMask) {
		t.Fatalf("LIMIT 10 was corrupted by short-value scrub: %q", shownSQL)
	}

	approveRecord(t, a, rec)
	reply := getApprovalReply(t, done)
	if reply.isError {
		t.Fatalf("approved call failed: %s", reply.text)
	}

	// Successful row data must come through intact, including values that
	// happen to contain the 3-char ds_id, "PROD", "0", and "LIMIT 10".
	for _, want := range []string{customerID, requestID, createdAt, "LIMIT 10", envType, `"retry_times"`, "1001"} {
		if !strings.Contains(reply.text, want) && want == `"retry_times"` {
			// column name is "retry_times" as title; compact result uses "name"
			if !strings.Contains(reply.text, "retry_times") && !strings.Contains(reply.text, "10") {
				t.Fatalf("result missing retry_times/10: %s", truncate(reply.text, 400))
			}
			continue
		}
		if !strings.Contains(reply.text, want) {
			t.Fatalf("result missing %q: %s", want, truncate(reply.text, 400))
		}
	}
	if strings.Contains(reply.text, longToken) {
		t.Fatal("long harvested token leaked in result")
	}
	if strings.Contains(reply.text, longCookie) {
		t.Fatal("long cookie leaked in result")
	}
	if !strings.Contains(reply.text, secretMask) {
		t.Fatal("expected the long token inside the note column to be masked")
	}
	if !strings.Contains(reply.text, "echo "+secretMask+" LIMIT 10") && !strings.Contains(reply.text, secretMask) {
		t.Fatalf("token mask should sit next to intact LIMIT 10: %s", truncate(reply.text, 400))
	}

	history, err := a.ListApprovals("all", 10)
	if err != nil || len(history) == 0 {
		t.Fatalf("history: %v %d", err, len(history))
	}
	histBlob, _ := json.Marshal(history[0])
	assertNoConfigTokens(t, history[0].Preview.URL+history[0].Preview.Body+history[0].Title, longToken, dsID, envID, spaceCode)
	if strings.Contains(string(histBlob), longToken) || strings.Contains(string(histBlob), longCookie) {
		t.Fatal("history leaked a long secret")
	}
	// envType "PROD" may appear in the successful result summary — that is
	// intentional (not a credential). It must not appear in preview/args as an id.
	if strings.Contains(history[0].Preview.URL, dsID) || strings.Contains(history[0].Preview.URL, envID) {
		t.Fatalf("preview leaked ids: %s", history[0].Preview.URL)
	}
	if !strings.Contains(history[0].ArgsDisplay["sql"], "LIMIT 10") && (history[0].FinalArgsDisplay == nil || !strings.Contains(history[0].FinalArgsDisplay["sql"], "LIMIT 10")) {
		t.Fatalf("approval-record SQL lost LIMIT 10: args=%v final=%v", history[0].ArgsDisplay, history[0].FinalArgsDisplay)
	}
	if strings.Contains(history[0].Result, "LIMIT 1"+secretMask) || strings.Contains(history[0].ArgsDisplay["sql"], "LIMIT 1"+secretMask) {
		t.Fatalf("approval record corrupted LIMIT 10: result=%q args=%v", history[0].Result, history[0].ArgsDisplay)
	}
	if !strings.Contains(history[0].Result, customerID) && !strings.Contains(history[0].Result, approvalResultTruncMark) {
		// 1-row result is well under 2KB, so the preview should include the id.
		t.Fatalf("approval result preview lost customer_id: %q", history[0].Result)
	}

	full, _, err := a.GetApprovalResult(history[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(full, longToken) || strings.Contains(full, longCookie) || strings.Contains(full, dsID+" ") {
		t.Fatalf("full result leaked a secret")
	}
	for _, want := range []string{customerID, requestID, createdAt, "LIMIT 10", envType} {
		if !strings.Contains(full, want) {
			t.Fatalf("full result missing %q", want)
		}
	}

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

	m := saveSQLConsole(t, a, fake, s.URL, MWDatasource{
		Alias: "orders", DSID: json.Number(dsID), EnvID: json.Number("707"),
		EnvType: "PROD", Description: "订单测试库",
	})

	done := make(chan approvalReply, 1)
	go func() {
		v, invErr := a.invokeTool(context.Background(), &mcpCtx{}, wsSQLQueryTool, map[string]any{
			"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t WHERE id=1 LIMIT 1",
		})
		done <- unpackApprovalReply(v, invErr)
	}()
	rec := pendingApprovals(t, a, 1)[0]
	blob := approvalVisibleBlob(rec)
	port := strings.TrimPrefix(s.URL, "http://127.0.0.1:")
	if strings.Contains(blob, port) || strings.Contains(blob, s.URL) || strings.Contains(blob, "707") || strings.Contains(blob, dsID) {
		t.Fatalf("leak port=%s url=%s previewURL=%q headers=%v body=%q title=%q args=%v params=%s blob=%s", port, s.URL, rec.Preview.URL, rec.Preview.Headers, rec.Preview.Body, rec.Title, rec.ArgsDisplay, truncate(string(compactJSON(rec.Params)), 300), truncate(blob, 800))
	}
	assertHiddenFromAI(t, blob, fake.token, dsID, "707", "PROD", "spc_alpha")
	approveRecord(t, a, rec)
	reply := getApprovalReply(t, done)
	if !reply.isError {
		t.Fatalf("expected execution error, got %q", reply.text)
	}
	assertHiddenFromAI(t, reply.text, fake.token, dsID, "707", "PROD", "spc_alpha")
	if !strings.Contains(reply.text, secretMask) {
		t.Fatalf("error should mask config tokens: %q", reply.text)
	}

	history, err := a.ListApprovals("all", 10)
	if err != nil || len(history) == 0 {
		t.Fatal("expected approval record")
	}
	assertHiddenFromAI(t, history[0].Result, fake.token, dsID, "707", "PROD", "spc_alpha")
	full, _, err := a.GetApprovalResult(history[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	assertHiddenFromAI(t, full, fake.token, dsID, "707", "PROD", "spc_alpha")
}
