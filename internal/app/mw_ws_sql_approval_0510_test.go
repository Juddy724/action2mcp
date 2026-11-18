package app

import (
	"action2mcp/internal/mwconfig"
	"action2mcp/internal/store"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func setSQLConsoleApproval(t *testing.T, a *App, m *mwconfig.Middleware, mode string) *mwconfig.Middleware {
	t.Helper()
	m.Config.Approval = mode
	if err := a.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}
	got, err := a.store.GetMiddleware(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Config.SQLConsoleApproval() != mode && mode != "" {
		want := mode
		if mode == "" {
			want = "always"
		}
		t.Fatalf("saved approval=%q, want %q", got.Config.Approval, want)
	}
	return got
}

func TestSQLConsoleApprovalDefaultsAlways(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL)
	if m.Config.SQLConsoleApproval() != "always" {
		t.Fatalf("new middleware approval=%q, want always", m.Config.Approval)
	}
	raw, err := middlewareRawConfig(a.store, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed["approval"] != "always" {
		t.Fatalf("stored approval=%v", parsed["approval"])
	}

	done := make(chan approvalReply, 1)
	go func() {
		v, err := invokeTool(a, context.Background(), mwconfig.WSSQLQueryTool, map[string]any{
			"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t WHERE id=1 LIMIT 1",
		})
		done <- unpackApprovalReply(v, err)
	}()
	rec := pendingApprovals(t, a, 1)[0]
	fake.mu.Lock()
	if fake.conns != 0 {
		fake.mu.Unlock()
		t.Fatal("default always dialed before approval")
	}
	fake.mu.Unlock()
	approveRecord(t, a, rec)
	reply := getApprovalReply(t, done)
	if reply.isError {
		t.Fatalf("approved call failed: %s", reply.text)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.business != 1 {
		t.Fatalf("business=%d after approve", fake.business)
	}
}

func TestSQLConsoleApprovalOffRunsWithoutCard(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := setSQLConsoleApproval(t, a, saveSQLConsole(t, a, fake, s.URL), "off")

	text, isErr := a.middlewares().Call(context.Background(), "tester", mwconfig.WSSQLQueryTool, map[string]any{
		"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t WHERE id=1 LIMIT 1",
	})
	if isErr {
		t.Fatalf("off call failed: %s", text)
	}
	pending, err := a.store.Approvals.List("all", 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 0 {
		t.Fatalf("off created approval records: %+v", pending)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.business != 1 || fake.explain != 1 {
		t.Fatalf("off should run guard+query, explain=%d business=%d", fake.explain, fake.business)
	}
	rows := a.store.ListAudit(m.Name, 10)
	if len(rows) == 0 {
		t.Fatal("expected audit row")
	}
	found := false
	for _, r := range rows {
		if r.Allowed && strings.Contains(r.Result, "未审批，直接执行") {
			found = true
		}
		assertHiddenFromAI(t, r.Result+r.Action, fake.token, "90001", "spc_alpha", "70007")
	}
	if !found {
		b, _ := json.Marshal(rows)
		t.Fatalf("audit did not record running without approval: %s", b)
	}
}

func TestSQLConsoleApprovalOffStillEnforcesGuard(t *testing.T) {
	cases := []struct {
		name, sql, want string
	}{
		{"no-limit", "SELECT id FROM t", "LIMIT"},
		{"non-select", "DELETE FROM t WHERE id=1", "SELECT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newCountingWS(2)
			s := fake.start(t)
			a := approvalTestApp(t)
			m := setSQLConsoleApproval(t, a, saveSQLConsole(t, a, fake, s.URL), "off")
			text, isErr := a.middlewares().Call(context.Background(), "tester", mwconfig.WSSQLQueryTool, map[string]any{
				"middleware": m.Name, "database": "orders", "sql": tc.sql,
			})
			if !isErr || !strings.Contains(text, tc.want) {
				t.Fatalf("expected %s reject, isErr=%v text=%s", tc.want, isErr, text)
			}
			pending, _ := a.store.Approvals.List("all", 20)
			if len(pending) != 0 {
				t.Fatalf("guard reject should not create an approval: %+v", pending)
			}
			fake.mu.Lock()
			defer fake.mu.Unlock()
			if fake.conns != 0 || fake.business != 0 || fake.explain != 0 {
				t.Fatalf("guard reject still sent frames: conns=%d biz=%d explain=%d msgs=%v", fake.conns, fake.business, fake.explain, fake.all)
			}
		})
	}
}

func TestMigrateV10SQLConsoleApprovalStaysAlways(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v10.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	sqlConsole := `{"url":"ws://127.0.0.1:9/ws","ws_mode":"sql_console","ws_messages":["execute {\"data\":{\"sql\":\"{{sql}}\"}}"],"datasources":[{"alias":"orders","ds_id":90001,"env_id":70007,"env_type":"TEST","description":"订单库"}],"max_rows":200,"timeout_sec":15,"perms":{"select":true}}`
	terminal := `{"url":"ws://127.0.0.1:9/term","ws_mode":"terminal","ws_messages":["{\"type\":\"TERMINAL_COMMAND\",\"text\":\"{{command}}\"}"],"command_allow":["ls"],"timeout_sec":30,"perms":{"log":true}}`
	mysql := `{"host":"127.0.0.1","port":3306,"database":"shop","perms":{"select":true}}`
	_, err = db.Exec(`CREATE TABLE middleware(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, type TEXT, config TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);
INSERT INTO middleware(name,type,config,created_at,updated_at) VALUES
('demo_sql','websocket',?, '', ''),
('pod_term','websocket',?, '', ''),
('shop_db','mysql',?, '', '');
PRAGMA user_version=10;`, sqlConsole, terminal, mysql)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		st, err := store.OpenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		var ver int
		if err := st.DB().QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil || ver != wantSchemaUserVersion {
			t.Fatalf("version=%d err=%v want %d", ver, err, wantSchemaUserVersion)
		}
		sqlMW, err := st.GetMiddlewareByName("demo_sql")
		if err != nil {
			t.Fatal(err)
		}
		if sqlMW.Config.SQLConsoleApproval() != "always" {
			t.Fatalf("existing sql_console approval=%q", sqlMW.Config.Approval)
		}
		raw, err := middlewareRawConfig(st, sqlMW.ID)
		if err != nil {
			t.Fatal(err)
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			t.Fatal(err)
		}
		if parsed["approval"] != "always" {
			t.Fatalf("stored sql_console approval=%v raw=%s", parsed["approval"], raw)
		}

		term, err := st.GetMiddlewareByName("pod_term")
		if err != nil {
			t.Fatal(err)
		}
		if term.Config.Approval != "" {
			t.Fatalf("terminal middleware should have no approval, got %q", term.Config.Approval)
		}
		termRaw, err := middlewareRawConfig(st, term.ID)
		if err != nil {
			t.Fatal(err)
		}
		var termParsed map[string]any
		if err := json.Unmarshal([]byte(termRaw), &termParsed); err != nil {
			t.Fatal(err)
		}
		if _, ok := termParsed["approval"]; ok && termParsed["approval"] != "" {
			t.Fatalf("terminal stored approval unexpectedly: %s", termRaw)
		}

		shop, err := st.GetMiddlewareByName("shop_db")
		if err != nil {
			t.Fatal(err)
		}
		if shop.Config.Approval != "" {
			t.Fatalf("mysql middleware should have no approval, got %q", shop.Config.Approval)
		}
		st.DB().Close()
	}
}

func TestMigrateV10PreservesHandSetOff(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v10off.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := `{"url":"ws://127.0.0.1:9/ws","ws_mode":"sql_console","approval":"off","ws_messages":["execute {\"data\":{\"sql\":\"{{sql}}\"}}"],"datasources":[{"alias":"orders","ds_id":90001,"env_id":70007,"env_type":"TEST","description":"订单库"}],"max_rows":200,"timeout_sec":15,"perms":{"select":true}}`
	_, err = db.Exec(`CREATE TABLE middleware(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, type TEXT, config TEXT, created_at TEXT, updated_at TEXT);
INSERT INTO middleware(name,type,config,created_at,updated_at) VALUES('demo_sql','websocket',?, '', '');
PRAGMA user_version=10;`, cfg)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.DB().Close()
	mw, err := st.GetMiddlewareByName("demo_sql")
	if err != nil {
		t.Fatal(err)
	}
	if mw.Config.SQLConsoleApproval() != "off" {
		t.Fatalf("hand-set off was overwritten: %q", mw.Config.Approval)
	}
}

func TestSQLConsoleApprovalMCPCannotChangeOrSee(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL)
	// Put a header binding so we can confirm a later legal save does not require re-entering it.
	m.Config.WSHeaders = map[string]string{"X-Token": "{{header.sso-epctoken}}"}
	m = setSQLConsoleApproval(t, a, m, "always")

	for _, item := range a.middlewares().ToolList() {
		blob, _ := json.Marshal(item)
		text := string(blob)
		if strings.Contains(text, `"approval"`) || strings.Contains(text, "审批模式") ||
			strings.Contains(text, "每次审批") || strings.Contains(text, "每次执行都要审批") ||
			strings.Contains(text, "每次调用都要在控制台审批") || strings.Contains(text, `"off"`) && item["name"] == mwconfig.WSSQLQueryTool {
			if item["name"] == mwconfig.WSSQLQueryTool {
				t.Fatalf("AI-facing tool schema leaked approval setting: %s", truncate(text, 400))
			}
		}
		if item["name"] == mwconfig.WSSQLQueryTool && (strings.Contains(text, "审批") || strings.Contains(strings.ToLower(text), "approval")) {
			t.Fatalf("AI-facing description mentions approval: %s", truncate(text, 400))
		}
	}

	// invokeTool extra argument must not change the stored mode or skip approval.
	done := make(chan approvalReply, 1)
	go func() {
		v, err := invokeTool(a, context.Background(), mwconfig.WSSQLQueryTool, map[string]any{
			"middleware": m.Name, "database": "orders",
			"sql": "SELECT id FROM t WHERE id=1 LIMIT 1", "approval": "off",
		})
		done <- unpackApprovalReply(v, err)
	}()
	rec := pendingApprovals(t, a, 1)[0]
	_ = rec
	got, _ := a.store.GetMiddleware(m.ID)
	if got.Config.SQLConsoleApproval() != "always" {
		t.Fatalf("MCP args changed stored approval to %q", got.Config.Approval)
	}
	fake.mu.Lock()
	if fake.conns != 0 {
		fake.mu.Unlock()
		t.Fatal("approval=off argument skipped the approval card")
	}
	fake.mu.Unlock()
	// cancel by rejecting so the goroutine finishes
	if err := a.approvals().Decide(rec.ID, rec.Nonce, "reject", nil, "test cleanup", rec.PreviewHash); err != nil {
		t.Fatal(err)
	}
	_ = getApprovalReply(t, done)

	// HTTP PUT from a foreign Origin must be rejected and leave the setting alone.
	body := map[string]any{
		"name": m.Name, "type": "websocket",
		"config": map[string]any{
			"ws_mode": "sql_console", "approval": "off",
			"url": m.Config.URL, "ws_messages": m.Config.WSMessages,
			"datasources": m.Config.Datasources, "sql_defaults": m.Config.SQLDefaults,
			"max_rows": m.Config.MaxRows, "timeout_sec": m.Config.TimeoutSec,
			"perms": m.Config.Perms,
		},
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPut, "http://127.0.0.1/api/middleware/"+strconv.FormatInt(m.ID, 10), bytes.NewReader(b))
	req.Header.Set("Origin", "https://evil.example.com")
	req.Header.Set("Content-Type", "application/json")
	req.Host = "127.0.0.1"
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("foreign origin status=%d body=%s", w.Code, w.Body.Bytes())
	}
	got, _ = a.store.GetMiddleware(m.ID)
	if got.Config.SQLConsoleApproval() != "always" {
		t.Fatalf("foreign origin changed approval to %q", got.Config.Approval)
	}

	// Console Origin can change it, and must keep existing header bindings
	// without the caller re-sending secrets.
	body["config"].(map[string]any)["ws_headers"] = got.Config.WSHeaders
	b, _ = json.Marshal(body)
	req = httptest.NewRequest(http.MethodPut, "http://127.0.0.1/api/middleware/"+strconv.FormatInt(m.ID, 10), bytes.NewReader(b))
	req.Header.Set("Origin", "http://127.0.0.1")
	req.Header.Set("Content-Type", "application/json")
	req.Host = "127.0.0.1"
	w = httptest.NewRecorder()
	a.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("console save status=%d body=%s", w.Code, w.Body.Bytes())
	}
	got, _ = a.store.GetMiddleware(m.ID)
	if got.Config.SQLConsoleApproval() != "off" {
		t.Fatalf("console did not save off, got %q", got.Config.Approval)
	}
	if got.Config.WSHeaders["X-Token"] != "{{header.sso-epctoken}}" {
		t.Fatalf("save dropped header binding: %+v", got.Config.WSHeaders)
	}

	// After switching to off, a call runs immediately and still hides IDs.
	text, isErr := a.middlewares().Call(context.Background(), "tester", mwconfig.WSSQLQueryTool, map[string]any{
		"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t WHERE id=1 LIMIT 1",
	})
	if isErr {
		t.Fatalf("off after console save failed: %s", text)
	}
	assertHiddenFromAI(t, text, fake.token, "90001", "spc_alpha", "70007")
	pending, _ := a.store.Approvals.List("pending", 20)
	if len(pending) != 0 {
		t.Fatalf("off still created a pending card: %+v", pending)
	}
}

func TestSQLConsoleApprovalUnknownFailsClosed(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL)
	m.Config.Approval = "sometimes"
	if err := a.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}
	got, _ := a.store.GetMiddleware(m.ID)
	if got.Config.SQLConsoleApproval() != "always" {
		t.Fatalf("unknown value should fail closed to always, got %q", got.Config.Approval)
	}
}

func TestTerminalMiddlewareIgnoresApproval(t *testing.T) {
	a := approvalTestApp(t)
	m := &mwconfig.Middleware{Name: "pod_term", Type: "websocket", Config: mwconfig.MWConfig{
		WSMode:       mwconfig.WSModeTerminal,
		URL:          "ws://127.0.0.1:9/term",
		WSMessages:   []string{`{"type":"TERMINAL_COMMAND","text":"{{command}}"}`},
		CommandAllow: []string{"ls"},
		TimeoutSec:   30,
		Perms:        map[string]bool{"log": true},
		Approval:     "off",
	}}
	if err := a.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}
	got, err := a.store.GetMiddleware(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Config.Approval != "" {
		t.Fatalf("terminal stored approval=%q", got.Config.Approval)
	}
	raw, _ := middlewareRawConfig(a.store, m.ID)
	if strings.Contains(raw, `"approval"`) {
		t.Fatalf("terminal raw config has approval: %s", raw)
	}
}
