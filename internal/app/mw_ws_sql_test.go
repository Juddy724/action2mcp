package app

import (
	"action2mcp/internal/approval"
	"action2mcp/internal/execution"

	"action2mcp/internal/mwconfig"
	"action2mcp/internal/store"
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func withRowEnv(sources []mwconfig.MWDatasource) []mwconfig.MWDatasource {
	out := make([]mwconfig.MWDatasource, len(sources))
	copy(out, sources)
	for i := range out {
		if mwconfig.IsEmptyJSONValue(out[i].EnvID) {
			out[i].EnvID = json.Number("70007")
		}
		if strings.TrimSpace(out[i].EnvType) == "" {
			out[i].EnvType = "TEST"
		}
	}
	return out
}

func sqlConsoleTestMW(name, url string, sources ...mwconfig.MWDatasource) *mwconfig.Middleware {
	if len(sources) == 0 {
		sources = []mwconfig.MWDatasource{{Alias: "orders", DSID: json.Number("90001"), Description: "订单测试库"}}
	}
	sources = withRowEnv(sources)
	return &mwconfig.Middleware{Name: name, Type: "websocket", Config: mwconfig.MWConfig{
		WSMode:      mwconfig.WSModeSQLConsole,
		URL:         url,
		WSMessages:  []string{`execute {"data":{"sql":"{{sql}}","spaceCode":"{{ds.space_code}}","dsId":"{{ds.ds_id}}","envId":"{{ds.env_id}}","envType":"{{ds.env_type}}","dbType":"{{ds.db_type}}"},"token":"{{header.sso-epctoken}}"}`},
		SQLPath:     "data.sql",
		SQLDefaults: mwconfig.MWSQLDefaults{SpaceCode: "spc_alpha", DBType: "mysql"},
		Datasources: sources,
		MaxRows:     200,
		TimeoutSec:  15,
		Perms:       map[string]bool{"select": true},
		WSCollect:   &WSCollectConfig{ResultCmd: "execResult", CloseCmds: []string{"close"}, SuccessPath: "data.success", DonePath: "data.done", MessagePath: "data.message", TimeoutMS: 5000, MaxBytes: 65536},
		WSAuth:      &WSAuthConfig{RetryRelogin: true},
	}}
}

func saveSQLConsole(t *testing.T, a *App, fake *countingWS, httpURL string, sources ...mwconfig.MWDatasource) *mwconfig.Middleware {
	t.Helper()
	if err := a.loginRuntime().HarvestRequestHeader("", httpURL, "sso-epctoken", fake.token); err != nil {
		t.Fatal(err)
	}
	m := sqlConsoleTestMW("sqlconsole", fake.wsURL(httpURL), sources...)
	if err := a.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}
	pack := &store.Pack{Name: "sql包", Enabled: true, MiddlewareIDs: []int64{m.ID}}
	if err := a.store.SavePack(pack); err != nil {
		t.Fatal(err)
	}
	got, err := a.store.GetMiddleware(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func assertHiddenFromAI(t *testing.T, blob, token string, ids ...string) {
	t.Helper()
	if token != "" && strings.Contains(blob, token) {
		t.Fatalf("leaked token in %q", truncate(blob, 200))
	}
	for _, id := range ids {
		if id != "" && strings.Contains(blob, id) {
			t.Fatalf("leaked id %q in %q", id, truncate(blob, 200))
		}
	}
}

// approvalVisibleBlob is the approval record without its preview digest.
// The digest is random hex, so a short numeric id such as 901 or 707 appears
// inside it by chance even though that digest is not configuration text.
func approvalVisibleBlob(rec approval.Record) string {
	rec.PreviewHash = ""
	b, _ := json.Marshal(rec)
	return string(b)
}

func TestSQLConsoleHappyPath(t *testing.T) {
	fake := newCountingWS(2)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL)
	tool, err := m.SQLConsoleTool(firstDatasource(t, m))
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.executor().Execute(tool, map[string]any{"sql": "SELECT id FROM t WHERE id=1 LIMIT 10", "database": "orders"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != execution.OutcomeSuccess {
		t.Fatalf("outcome=%s err=%s body=%s", res.Outcome, res.Error, res.Body)
	}
	assertHiddenFromAI(t, res.Body, fake.token, "90001", "spc_alpha", "70007")
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.explain != 1 || fake.business != 1 || fake.conns != 2 {
		t.Fatalf("explain=%d business=%d conns=%d", fake.explain, fake.business, fake.conns)
	}
	joined := strings.Join(fake.all, "\n")
	if !strings.Contains(joined, `"dsId":90001`) && !strings.Contains(joined, `"dsId":"90001"`) {
		t.Fatalf("datasource id not sent: %v", fake.all)
	}
}

func TestSQLConsoleGuardRejectsSendsNothing(t *testing.T) {
	fake := newCountingWS(2)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL)
	text, isErr := a.middlewares().Call(context.Background(), "tester", mwconfig.WSSQLQueryTool, map[string]any{"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t"})
	if !isErr || !strings.Contains(text, "LIMIT") {
		t.Fatalf("expected LIMIT reject, got err=%v text=%s", isErr, text)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.conns != 0 || fake.business != 0 {
		t.Fatalf("guard reject still dialed: conns=%d biz=%d", fake.conns, fake.business)
	}
}

func TestSQLConsoleNoIndexRejects(t *testing.T) {
	fake := newCountingWS(2)
	fake.typeALL = true
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL)
	tool, err := m.SQLConsoleTool(firstDatasource(t, m))
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.executor().Execute(tool, map[string]any{"sql": "SELECT id FROM t WHERE id=1 LIMIT 10", "database": "orders"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != execution.OutcomeGuardRejected {
		t.Fatalf("outcome=%s err=%s", res.Outcome, res.Error)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.business != 0 {
		t.Fatalf("business=%d", fake.business)
	}
}

func TestSQLConsoleTokenAbsentFailClosed(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := sqlConsoleTestMW("sqlconsole", fake.wsURL(s.URL))
	if err := a.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}
	if err := a.store.SavePack(&store.Pack{Name: "sql包", Enabled: true, MiddlewareIDs: []int64{m.ID}}); err != nil {
		t.Fatal(err)
	}
	got, _ := a.store.GetMiddleware(m.ID)
	tool, err := got.SQLConsoleTool(firstDatasource(t, got))
	if err != nil {
		t.Fatal(err)
	}
	text, isErr := a.middlewares().Call(context.Background(), "tester", mwconfig.WSSQLQueryTool, map[string]any{"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t WHERE id=1 LIMIT 1"})
	if !isErr || (!strings.Contains(text, "请求头") && !strings.Contains(text, "登录")) {
		t.Fatalf("AI path should fail closed before approval, got isErr=%v text=%q", isErr, text)
	}
	assertHiddenFromAI(t, text, fake.token, "90001", "spc_alpha", "70007")
	pending, _ := a.store.Approvals.List("pending", 20)
	if len(pending) != 0 {
		t.Fatalf("missing token should not create an approval card: %+v", pending)
	}
	res, err := a.executor().Execute(tool, map[string]any{"sql": "SELECT id FROM t WHERE id=1 LIMIT 1", "database": "orders"})
	msg := ""
	if err != nil {
		msg = err.Error()
	} else if res != nil {
		msg = res.Error + res.Body + res.Outcome
	}
	if !strings.Contains(msg, "请求头") && !strings.Contains(msg, "auth") && (res == nil || res.Outcome != execution.OutcomeAuthFailed) {
		t.Fatalf("expected fail-closed missing header, got err=%v res=%+v", err, res)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.business != 0 {
		t.Fatalf("sent business without token: %v", fake.all)
	}
}

func TestSQLConsoleUnknownAlias(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL, mwconfig.MWDatasource{Alias: "orders", DSID: json.Number("90001"), Description: "订单库"}, mwconfig.MWDatasource{Alias: "tasks", DSID: json.Number("90002"), Description: "任务库"})
	text, isErr := a.middlewares().Call(context.Background(), "tester", mwconfig.WSSQLQueryTool, map[string]any{"middleware": m.Name, "database": "missing", "sql": "SELECT id FROM t LIMIT 1"})
	if !isErr || !strings.Contains(text, "missing") || !strings.Contains(text, "orders") || !strings.Contains(text, "tasks") {
		t.Fatalf("unknown alias error should list allowed names: %s", text)
	}
	assertHiddenFromAI(t, text, fake.token, "90001", "90002", "70007")
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.conns != 0 {
		t.Fatal("unknown alias should not dial")
	}
}

func TestSQLConsoleMultiDatasourceRouting(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL,
		mwconfig.MWDatasource{Alias: "orders", DSID: json.Number("90001"), Description: "订单测试库"},
		mwconfig.MWDatasource{Alias: "tasks", DSID: json.Number("90002"), Description: "任务库"},
	)
	tool, err := m.SQLConsoleTool(mustDS(t, m, "tasks"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.executor().Execute(tool, map[string]any{"sql": "SELECT id FROM t WHERE id=1 LIMIT 1", "database": "tasks"}); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	joined := strings.Join(fake.all, "\n")
	fake.mu.Unlock()
	if !strings.Contains(joined, `"dsId":90002`) && !strings.Contains(joined, `"dsId":"90002"`) {
		t.Fatalf("expected tasks dsId=90002, got %s", joined)
	}
	if strings.Contains(joined, `"dsId":90001`) || strings.Contains(joined, `"dsId":"90001"`) {
		t.Fatalf("sent the other datasource id: %s", joined)
	}
}

func mustDS(t *testing.T, m *mwconfig.Middleware, alias string) mwconfig.MWDatasource {
	t.Helper()
	ds, err := m.LookupDatasource(alias)
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

func TestSQLConsoleSchemaListsAliasesNotIDs(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL,
		mwconfig.MWDatasource{Alias: "orders", DSID: json.Number("90001"), Description: "订单测试库"},
		mwconfig.MWDatasource{Alias: "tasks", DSID: json.Number("90002"), Description: "任务库"},
	)
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
	desc := found["description"].(string)
	if !strings.Contains(desc, "orders：订单测试库") || !strings.Contains(desc, "tasks：任务库") {
		t.Fatalf("description should list aliases with AI descriptions: %s", desc)
	}
	blob, _ := json.Marshal(found)
	text := string(blob) + fake.wsURL(s.URL)
	assertHiddenFromAI(t, string(blob), fake.token, "90001", "90002", "spc_alpha", "70007", m.Config.URL)
	schema := found["inputSchema"].(map[string]any)
	props := schema["properties"].(map[string]any)
	db := props["database"].(map[string]any)
	enum, _ := db["enum"].([]string)
	if len(enum) == 0 {
		// json decode through any may be []any
		if raw, ok := db["enum"].([]any); ok {
			for _, v := range raw {
				enum = append(enum, fmtSprint(v))
			}
		}
	}
	joined := strings.Join(enum, ",")
	if !strings.Contains(joined, "orders") || !strings.Contains(joined, "tasks") {
		t.Fatalf("database enum=%v", db["enum"])
	}
	_ = text
}

func fmtSprint(v any) string {
	b, _ := json.Marshal(v)
	return strings.Trim(string(b), `"`)
}

func TestSQLConsoleApprovalPreviewHidesIDs(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL, mwconfig.MWDatasource{Alias: "orders", DSID: json.Number("90001"), Description: "订单测试库"})
	done := make(chan approvalReply, 1)
	go func() {
		v, err := invokeTool(a, context.Background(), mwconfig.WSSQLQueryTool, map[string]any{"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t WHERE id=1 LIMIT 1"})
		done <- unpackApprovalReply(v, err)
	}()
	rec := pendingApprovals(t, a, 1)[0]
	assertHiddenFromAI(t, approvalVisibleBlob(rec), fake.token, "90001", "spc_alpha", "70007", strings.TrimPrefix(fake.wsURL(s.URL), "ws://"))
	if rec.Preview.URL != "" && (strings.Contains(rec.Preview.URL, "ws://") || strings.Contains(rec.Preview.URL, "wss://")) {
		t.Fatalf("preview URL leaked address: %s", rec.Preview.URL)
	}
	shown := rec.Preview.URL + rec.Title + rec.ArgsDisplay["database"] + rec.ArgsDisplay["sql"] + rec.Preview.Body
	if !strings.Contains(shown, "orders") {
		t.Fatalf("preview should show alias: url=%s title=%s args=%v", rec.Preview.URL, rec.Title, rec.ArgsDisplay)
	}
	if rec.Preview.Body != "" && rec.Preview.Body != "SELECT id FROM t WHERE id=1 LIMIT 1" && !strings.Contains(rec.Preview.Body, "SELECT id FROM t") {
		t.Fatalf("preview body should be SQL, got %q", rec.Preview.Body)
	}
	fake.mu.Lock()
	if fake.conns != 0 {
		fake.mu.Unlock()
		t.Fatal("dialed before approval")
	}
	fake.mu.Unlock()
	approveRecord(t, a, rec)
	reply := getApprovalReply(t, done)
	if reply.isError {
		t.Fatalf("approved call failed: %s", reply.text)
	}
	assertHiddenFromAI(t, reply.text, fake.token, "90001", "spc_alpha", "70007")
}

func TestSQLConsoleTestConnectionNeverRunsSQL(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL)
	msg, err := a.middlewares().Test(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "未执行 SQL") && !strings.Contains(msg, "握手") && !strings.Contains(msg, "连接成功") {
		t.Fatalf("unexpected test message: %s", msg)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.business != 0 || fake.explain != 0 || len(fake.messages) != 0 {
		t.Fatalf("test connection sent SQL: explain=%d biz=%d msgs=%v", fake.explain, fake.business, fake.messages)
	}
}

func TestSQLConsoleAuditHasNoIDs(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL)
	_, _ = a.middlewares().Call(context.Background(), "tester", mwconfig.WSSQLQueryTool, map[string]any{"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t"})
	rows := a.store.ListAudit(m.Name, 10)
	if len(rows) == 0 {
		t.Fatal("expected audit row")
	}
	b, _ := json.Marshal(rows)
	assertHiddenFromAI(t, string(b), fake.token, "90001", "spc_alpha", "70007")
}

func TestMigrateWSToolToSQLMiddleware(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v7.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE tools(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, title TEXT, description TEXT, method TEXT, url TEXT, headers TEXT, body TEXT, params TEXT, cred_headers TEXT, source_request_id INTEGER, created_at TEXT, updated_at TEXT, approval TEXT NOT NULL DEFAULT 'off', rev INTEGER NOT NULL DEFAULT 1, config TEXT NOT NULL DEFAULT '{}');
CREATE TABLE packs(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, description TEXT, enabled INTEGER, created_at TEXT);
CREATE TABLE pack_tools(pack_id INTEGER REFERENCES packs(id) ON DELETE CASCADE, tool_id INTEGER REFERENCES tools(id) ON DELETE CASCADE, PRIMARY KEY(pack_id, tool_id));
CREATE TABLE middleware(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, type TEXT, config TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE pack_middleware(pack_id INTEGER REFERENCES packs(id) ON DELETE CASCADE, mw_id INTEGER REFERENCES middleware(id) ON DELETE CASCADE, PRIMARY KEY(pack_id, mw_id));
CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);
INSERT INTO tools(name,title,description,method,url,headers,body,params,config,approval) VALUES('demo_sql_query','SQL','','WS','ws://127.0.0.1:9/ws','{"sso-epctoken":"{{header.sso-epctoken}}"}','','[{"name":"sql","type":"string","required":true}]','{"messages":["execute {\"data\":{\"sql\":\"{{sql}}\",\"spaceCode\":\"spc_alpha\",\"dsId\":90001,\"envId\":70007,\"envType\":\"TEST\",\"dbType\":\"mysql\"}}"],"sql_guard":{"enabled":true,"param":"sql","path":"data.sql","max_rows":200}}','always');
INSERT INTO packs(name,description,enabled,created_at) VALUES('排查', '', 1, '');
INSERT INTO pack_tools(pack_id,tool_id) VALUES(1,1);
PRAGMA user_version=7;`)
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
			t.Fatalf("version=%d err=%v", ver, err)
		}
		if _, err := st.GetToolByName("demo_sql_query"); err == nil {
			t.Fatal("old tool should have been removed")
		}
		mw, err := st.GetMiddlewareByName("demo_sql")
		if err != nil {
			t.Fatal(err)
		}
		if !mw.Config.IsSQLConsole() {
			t.Fatalf("mode=%s", mw.Config.EffectiveWSMode())
		}
		if mw.Config.SQLConsoleApproval() != "always" {
			t.Fatalf("migrated approval=%q, want always", mw.Config.Approval)
		}
		if len(mw.Config.Datasources) != 1 || mw.Config.Datasources[0].Alias != "default" {
			t.Fatalf("datasources=%+v", mw.Config.Datasources)
		}
		ds := mw.Config.Datasources[0]
		if fmtSprint(ds.DSID) != "90001" {
			t.Fatalf("dsid=%v", ds.DSID)
		}
		if fmtSprint(ds.EnvID) != "70007" {
			t.Fatalf("row envId=%v", ds.EnvID)
		}
		if ds.EnvType != "TEST" {
			t.Fatalf("row envType=%q", ds.EnvType)
		}
		if mw.Config.SQLDefaults.SpaceCode != "spc_alpha" || mw.Config.SQLDefaults.DBType != "mysql" {
			t.Fatalf("defaults=%+v", mw.Config.SQLDefaults)
		}
		if mwconfig.SQLConsoleEnvNeedsPromote(mw.Config) { // owner predicate covers the private legacy keys
			t.Fatalf("legacy default env keys should have been dropped: %+v", mw.Config.SQLDefaults)
		}
		raw, err := middlewareRawConfig(st, mw.ID)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(raw, `"env_id"`) && strings.Contains(raw, `"sql_defaults"`) {
			// env_id must live under datasources, not sql_defaults
			var parsed map[string]any
			if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
				t.Fatal(err)
			}
			if defs, _ := parsed["sql_defaults"].(map[string]any); defs != nil {
				if _, ok := defs["env_id"]; ok {
					t.Fatalf("sql_defaults still has env_id: %s", raw)
				}
				if _, ok := defs["env_type"]; ok {
					t.Fatalf("sql_defaults still has env_type: %s", raw)
				}
			}
		}
		packs, _ := st.ListPacks()
		if len(packs) != 1 || len(packs[0].ToolIDs) != 0 || len(packs[0].MiddlewareIDs) != 1 || packs[0].MiddlewareIDs[0] != mw.ID {
			t.Fatalf("pack membership not moved: %+v", packs)
		}
		st.DB().Close()
	}
}

func middlewareRawConfig(st *store.Store, id int64) (string, error) {
	var raw string
	err := st.DB().QueryRow(`SELECT config FROM middleware WHERE id=?`, id).Scan(&raw)
	return raw, err
}

func TestSQLConsolePerRowEnvRouting(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL,
		mwconfig.MWDatasource{Alias: "orders", DSID: json.Number("90001"), EnvID: json.Number("71001"), EnvType: "TEST", Description: "订单测试库"},
		mwconfig.MWDatasource{Alias: "tasks", DSID: json.Number("90002"), EnvID: json.Number("72002"), EnvType: "PROD", Description: "任务库"},
	)
	tool, err := m.SQLConsoleTool(mustDS(t, m, "tasks"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.executor().Execute(tool, map[string]any{"sql": "SELECT id FROM t WHERE id=1 LIMIT 1", "database": "tasks"}); err != nil {
		t.Fatal(err)
	}
	fake.mu.Lock()
	joined := strings.Join(fake.all, "\n")
	fake.mu.Unlock()
	if !strings.Contains(joined, `"dsId":90002`) && !strings.Contains(joined, `"dsId":"90002"`) {
		t.Fatalf("expected tasks dsId=90002, got %s", joined)
	}
	if !strings.Contains(joined, `"envId":72002`) && !strings.Contains(joined, `"envId":"72002"`) {
		t.Fatalf("expected tasks envId=72002, got %s", joined)
	}
	if !strings.Contains(joined, `"envType":"PROD"`) {
		t.Fatalf("expected tasks envType=PROD, got %s", joined)
	}
	if strings.Contains(joined, `"dsId":90001`) || strings.Contains(joined, `"dsId":"90001"`) || strings.Contains(joined, `"envId":71001`) || strings.Contains(joined, `"envId":"71001"`) || strings.Contains(joined, `"envType":"TEST"`) {
		t.Fatalf("sent the other datasource env: %s", joined)
	}
}

func TestSQLConsoleValidateDatasourceUniqueness(t *testing.T) {
	dup := sqlConsoleTestMW("sqlconsole", "ws://127.0.0.1:9/ws",
		mwconfig.MWDatasource{Alias: "orders", DSID: json.Number("90001"), EnvID: json.Number("8"), EnvType: "PROD"},
		mwconfig.MWDatasource{Alias: "tasks", DSID: json.Number("90001"), EnvID: json.Number("8"), EnvType: "prod"},
	)
	err := dup.Normalize()
	if err == nil || !strings.Contains(err.Error(), "完全相同") {
		t.Fatalf("expected unique triple error, got %v", err)
	}
	if strings.Contains(err.Error(), "90001") || strings.Contains(err.Error(), "8") {
		t.Fatalf("uniqueness error leaked ids: %v", err)
	}

	alias := sqlConsoleTestMW("sqlconsole", "ws://127.0.0.1:9/ws",
		mwconfig.MWDatasource{Alias: "Orders", DSID: json.Number("1"), EnvID: json.Number("8"), EnvType: "PROD"},
		mwconfig.MWDatasource{Alias: "orders", DSID: json.Number("2"), EnvID: json.Number("9"), EnvType: "TEST"},
	)
	if err := alias.Normalize(); err == nil || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("expected alias unique error, got %v", err)
	}

	missing := sqlConsoleTestMW("sqlconsole", "ws://127.0.0.1:9/ws",
		mwconfig.MWDatasource{Alias: "orders", DSID: json.Number("90001"), EnvType: "PROD"},
	)
	missing.Config.Datasources[0].EnvID = nil
	if err := missing.Normalize(); err == nil || !strings.Contains(err.Error(), "envId") {
		t.Fatalf("expected missing envId error, got %v", err)
	}

	// Same dsId + envId but different envType is allowed.
	ok := sqlConsoleTestMW("sqlconsole", "ws://127.0.0.1:9/ws",
		mwconfig.MWDatasource{Alias: "orders_test", DSID: json.Number("90001"), EnvID: json.Number("8"), EnvType: "TEST"},
		mwconfig.MWDatasource{Alias: "orders_prod", DSID: json.Number("90001"), EnvID: json.Number("8"), EnvType: "PROD"},
	)
	if err := ok.Normalize(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLConsoleEnvTypeDefaultsToPROD(t *testing.T) {
	m := sqlConsoleTestMW("sqlconsole", "ws://127.0.0.1:9/ws",
		mwconfig.MWDatasource{Alias: "orders", DSID: json.Number("90001"), EnvID: json.Number("70007")},
	)
	m.Config.Datasources[0].EnvType = ""
	if err := m.Normalize(); err != nil {
		t.Fatal(err)
	}
	if m.Config.Datasources[0].EnvType != "PROD" {
		t.Fatalf("envType=%q", m.Config.Datasources[0].EnvType)
	}
	vals := m.Config.Datasources[0].FieldValues(&m.Config)
	if fmtSprint(vals["env_type"]) != "PROD" {
		t.Fatalf("fieldValues env_type=%v", vals["env_type"])
	}
}

func TestMigrateV8SQLConsoleEnvToRows(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v8env.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := `{"url":"ws://127.0.0.1:9/ws","ws_mode":"sql_console","ws_messages":["execute {\"data\":{\"sql\":\"{{sql}}\",\"spaceCode\":\"{{ds.space_code}}\",\"dsId\":\"{{ds.ds_id}}\",\"envId\":\"{{ds.env_id}}\",\"envType\":\"{{ds.env_type}}\",\"dbType\":\"{{ds.db_type}}\"}}"],"sql_path":"data.sql","sql_defaults":{"space_code":"spc_alpha","env_id":70007,"env_type":"TEST","db_type":"mysql"},"datasources":[{"alias":"default","ds_id":90001}],"max_rows":200,"timeout_sec":15,"perms":{"select":true}}`
	_, err = db.Exec(`CREATE TABLE tools(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, title TEXT, description TEXT, method TEXT, url TEXT, headers TEXT, body TEXT, params TEXT, cred_headers TEXT, source_request_id INTEGER, created_at TEXT, updated_at TEXT, approval TEXT NOT NULL DEFAULT 'off', rev INTEGER NOT NULL DEFAULT 1, config TEXT NOT NULL DEFAULT '{}');
CREATE TABLE packs(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, description TEXT, enabled INTEGER, created_at TEXT);
CREATE TABLE pack_tools(pack_id INTEGER REFERENCES packs(id) ON DELETE CASCADE, tool_id INTEGER REFERENCES tools(id) ON DELETE CASCADE, PRIMARY KEY(pack_id, tool_id));
CREATE TABLE middleware(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, type TEXT, config TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE pack_middleware(pack_id INTEGER REFERENCES packs(id) ON DELETE CASCADE, mw_id INTEGER REFERENCES middleware(id) ON DELETE CASCADE, PRIMARY KEY(pack_id, mw_id));
CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);
INSERT INTO middleware(name,type,config,created_at,updated_at) VALUES('demo_sql','websocket',?, '', '');
PRAGMA user_version=8;`, cfg)
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
			t.Fatalf("version=%d err=%v", ver, err)
		}
		mw, err := st.GetMiddlewareByName("demo_sql")
		if err != nil {
			t.Fatal(err)
		}
		if len(mw.Config.Datasources) != 1 || mw.Config.Datasources[0].Alias != "default" {
			t.Fatalf("datasources=%+v", mw.Config.Datasources)
		}
		if mw.Config.SQLConsoleApproval() != "always" {
			t.Fatalf("v8 upgrade approval=%q, want always", mw.Config.Approval)
		}
		ds := mw.Config.Datasources[0]
		if fmtSprint(ds.DSID) != "90001" || fmtSprint(ds.EnvID) != "70007" || ds.EnvType != "TEST" {
			t.Fatalf("row not promoted: %+v", ds)
		}
		if mwconfig.SQLConsoleEnvNeedsPromote(mw.Config) { // owner predicate covers the private legacy keys
			t.Fatalf("legacy keys still present: %+v", mw.Config.SQLDefaults)
		}
		raw, err := middlewareRawConfig(st, mw.ID)
		if err != nil {
			t.Fatal(err)
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			t.Fatal(err)
		}
		if defs, _ := parsed["sql_defaults"].(map[string]any); defs != nil {
			if _, ok := defs["env_id"]; ok {
				t.Fatalf("stored sql_defaults still has env_id: %s", raw)
			}
			if _, ok := defs["env_type"]; ok {
				t.Fatalf("stored sql_defaults still has env_type: %s", raw)
			}
		}
		st.DB().Close()
	}
}

func TestSQLConsoleSavePromotesLegacyDefaults(t *testing.T) {
	a := approvalTestApp(t)
	raw := `{"url":"ws://127.0.0.1:9/ws","ws_mode":"sql_console","ws_messages":["execute {\"data\":{\"sql\":\"{{sql}}\"}}"],"sql_defaults":{"space_code":"spc_alpha","env_id":70007,"env_type":"TEST","db_type":"mysql"},"datasources":[{"alias":"default","ds_id":90001}],"max_rows":200,"timeout_sec":15,"perms":{"select":true}}`
	c, err := mwconfig.DecodeMWConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !mwconfig.SQLConsoleEnvNeedsPromote(c) { // private capture is asserted by the mwconfig owner test
		t.Fatalf("expected to capture legacy defaults, got %+v", c.SQLDefaults)
	}
	m := &mwconfig.Middleware{Name: "legacy_sql", Type: "websocket", Config: c}
	if err := a.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}
	got, err := a.store.GetMiddleware(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	ds := got.Config.Datasources[0]
	if fmtSprint(ds.EnvID) != "70007" || ds.EnvType != "TEST" {
		t.Fatalf("saved row missing env: %+v", ds)
	}
	rawSaved, err := middlewareRawConfig(a.store, m.ID)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal([]byte(rawSaved), &parsed); err != nil {
		t.Fatal(err)
	}
	if defs, _ := parsed["sql_defaults"].(map[string]any); defs != nil {
		if _, ok := defs["env_id"]; ok {
			t.Fatalf("saved sql_defaults still has env_id: %s", rawSaved)
		}
		if _, ok := defs["env_type"]; ok {
			t.Fatalf("saved sql_defaults still has env_type: %s", rawSaved)
		}
	}
}

// firstDatasource is the first enabled datasource, resolved through the public alias lookup.
func firstDatasource(t *testing.T, m *mwconfig.Middleware) mwconfig.MWDatasource {
	t.Helper()
	aliases := m.DatasourceAliases()
	if len(aliases) == 0 {
		t.Fatal("no enabled datasource")
	}
	ds, err := m.LookupDatasource(aliases[0])
	if err != nil {
		t.Fatal(err)
	}
	return ds
}

func TestSQLConsoleDescribePermission(t *testing.T) {
	fake := newCountingWS(1)
	fake.businessCols = []any{
		map[string]any{"field": "C_1", "title": "Field"},
		map[string]any{"field": "C_2", "title": "Type"},
	}
	fake.businessRows = []any{
		map[string]any{"C_1": "customer_id", "C_2": "bigint"},
	}
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL, mwconfig.MWDatasource{Alias: "orders", DSID: json.Number("90001"), Description: "订单库"})

	// By default describe and list_tables permissions are disabled.
	v, err := invokeTool(a, context.Background(), mwconfig.WSSQLQueryTool, map[string]any{
		"middleware": m.Name, "database": "orders", "sql": "DESCRIBE order_dispatch_task",
	})
	rep := unpackApprovalReply(v, err)
	if !rep.isError || !strings.Contains(rep.text, "查表结构") {
		t.Fatalf("expected describe permission denial, got isError=%v text=%q", rep.isError, rep.text)
	}
	if fake.explain != 0 || fake.business != 0 {
		t.Fatalf("denied describe should not send WS frames: explain=%d business=%d", fake.explain, fake.business)
	}
	v, err = invokeTool(a, context.Background(), mwconfig.WSSQLQueryTool, map[string]any{
		"middleware": m.Name, "database": "orders", "sql": "SHOW TABLES",
	})
	rep = unpackApprovalReply(v, err)
	if !rep.isError || !strings.Contains(rep.text, "查表列表") {
		t.Fatalf("expected SHOW TABLES permission denial, got isError=%v text=%q", rep.isError, rep.text)
	}

	// Enable describe permission ONLY: DESCRIBE succeeds, while SHOW TABLES remains denied.
	m.Config.Perms["describe"] = true
	m.Config.Approval = "off"
	if err := a.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}
	v, err = invokeTool(a, context.Background(), mwconfig.WSSQLQueryTool, map[string]any{
		"middleware": m.Name, "database": "orders", "sql": "SHOW TABLES",
	})
	rep = unpackApprovalReply(v, err)
	if !rep.isError || !strings.Contains(rep.text, "查表列表") {
		t.Fatalf("SHOW TABLES should be denied when only describe is enabled: isError=%v text=%q", rep.isError, rep.text)
	}

	// Enable list_tables permission as well.
	m.Config.Perms["list_tables"] = true
	if err := a.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}

	// Only ws_sql_query should be exposed (no separate ws_sql_list_tables tool), and its description mentions DESCRIBE & SHOW TABLES.
	var listedDesc string
	for _, item := range a.middlewares().ToolList() {
		if item["name"] == "ws_sql_list_tables" {
			t.Fatal("ws_sql_list_tables should not be exposed as a separate tool")
		}
		if item["name"] == mwconfig.WSSQLQueryTool {
			listedDesc, _ = item["description"].(string)
		}
	}
	if !strings.Contains(listedDesc, "DESCRIBE") || !strings.Contains(listedDesc, "SHOW COLUMNS") || !strings.Contains(listedDesc, "SHOW TABLES") {
		t.Fatalf("expected tool description to mention DESCRIBE/SHOW COLUMNS/SHOW TABLES, got: %s", listedDesc)
	}

	// Valid schema inspection and table-listing statements must succeed and skip EXPLAIN preflight.
	for _, stmt := range []string{
		"SHOW TABLES",
		"SHOW TABLES LIKE '%task%'",
		"DESCRIBE order_dispatch_task",
		"SHOW FULL COLUMNS FROM order_dispatch_task",
		"SHOW INDEX FROM order_dispatch_task",
		"SHOW CREATE TABLE order_dispatch_task",
	} {
		fake.mu.Lock()
		prevBiz := fake.business
		fake.mu.Unlock()
		v, err := invokeTool(a, context.Background(), mwconfig.WSSQLQueryTool, map[string]any{
			"middleware": m.Name, "database": "orders", "sql": stmt,
		})
		rep := unpackApprovalReply(v, err)
		if rep.isError || !strings.Contains(rep.text, "customer_id") {
			t.Fatalf("%q failed: isError=%v text=%q", stmt, rep.isError, rep.text)
		}
		fake.mu.Lock()
		gotExplain := fake.explain
		gotBiz := fake.business
		fake.mu.Unlock()
		if gotExplain != 0 || gotBiz != prevBiz+1 {
			t.Fatalf("%q expected no EXPLAIN and 1 business query, got explain=%d business=%d", stmt, gotExplain, gotBiz)
		}
	}

	// Non-schema SHOW commands remain blocked even with describe and list_tables enabled.
	v, err = invokeTool(a, context.Background(), mwconfig.WSSQLQueryTool, map[string]any{
		"middleware": m.Name, "database": "orders", "sql": "SHOW VARIABLES",
	})
	rep = unpackApprovalReply(v, err)
	if !rep.isError {
		t.Fatalf("SHOW VARIABLES should remain rejected, got: %q", rep.text)
	}
}
