package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func withRowEnv(sources []MWDatasource) []MWDatasource {
	out := make([]MWDatasource, len(sources))
	copy(out, sources)
	for i := range out {
		if isEmptyJSONValue(out[i].EnvID) {
			out[i].EnvID = json.Number("70007")
		}
		if strings.TrimSpace(out[i].EnvType) == "" {
			out[i].EnvType = "TEST"
		}
	}
	return out
}

func sqlConsoleTestMW(name, url string, sources ...MWDatasource) *Middleware {
	if len(sources) == 0 {
		sources = []MWDatasource{{Alias: "orders", DSID: json.Number("90001"), Description: "订单测试库"}}
	}
	sources = withRowEnv(sources)
	return &Middleware{Name: name, Type: "websocket", Config: MWConfig{
		WSMode:      wsModeSQLConsole,
		URL:         url,
		WSMessages:  []string{`execute {"data":{"sql":"{{sql}}","spaceCode":"{{ds.space_code}}","dsId":"{{ds.ds_id}}","envId":"{{ds.env_id}}","envType":"{{ds.env_type}}","dbType":"{{ds.db_type}}"},"token":"{{header.sso-epctoken}}"}`},
		SQLPath:     "data.sql",
		SQLDefaults: MWSQLDefaults{SpaceCode: "spc_alpha", DBType: "mysql"},
		Datasources: sources,
		MaxRows:     200,
		TimeoutSec:  15,
		Perms:       map[string]bool{"select": true},
		WSCollect:   &WSCollectConfig{ResultCmd: "execResult", CloseCmds: []string{"close"}, SuccessPath: "data.success", DonePath: "data.done", MessagePath: "data.message", TimeoutMS: 5000, MaxBytes: 65536},
		WSAuth:      &WSAuthConfig{RetryRelogin: true},
	}}
}

func saveSQLConsole(t *testing.T, a *App, fake *countingWS, httpURL string, sources ...MWDatasource) *Middleware {
	t.Helper()
	if err := a.HarvestRequestHeader("", httpURL, "sso-epctoken", fake.token); err != nil {
		t.Fatal(err)
	}
	m := sqlConsoleTestMW("sqlconsole", fake.wsURL(httpURL), sources...)
	if err := a.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}
	pack := &Pack{Name: "sql包", Enabled: true, MiddlewareIDs: []int64{m.ID}}
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
func approvalVisibleBlob(rec ApprovalRecord) string {
	rec.PreviewHash = ""
	b, _ := json.Marshal(rec)
	return string(b)
}

func TestSQLConsoleHappyPath(t *testing.T) {
	fake := newCountingWS(2)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL)
	tool, err := m.sqlConsoleTool(m.enabledDatasources()[0])
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Execute(tool, map[string]any{"sql": "SELECT id FROM t WHERE id=1 LIMIT 10", "database": "orders"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != outcomeSuccess {
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
	text, isErr := a.callMWTool(context.Background(), "tester", wsSQLQueryTool, map[string]any{"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t"})
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
	tool, err := m.sqlConsoleTool(m.enabledDatasources()[0])
	if err != nil {
		t.Fatal(err)
	}
	res, err := a.Execute(tool, map[string]any{"sql": "SELECT id FROM t WHERE id=1 LIMIT 10", "database": "orders"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != outcomeGuardRejected {
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
	if err := a.store.SavePack(&Pack{Name: "sql包", Enabled: true, MiddlewareIDs: []int64{m.ID}}); err != nil {
		t.Fatal(err)
	}
	got, _ := a.store.GetMiddleware(m.ID)
	tool, err := got.sqlConsoleTool(got.enabledDatasources()[0])
	if err != nil {
		t.Fatal(err)
	}
	text, isErr := a.callMWTool(context.Background(), "tester", wsSQLQueryTool, map[string]any{"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t WHERE id=1 LIMIT 1"})
	if !isErr || (!strings.Contains(text, "请求头") && !strings.Contains(text, "登录")) {
		t.Fatalf("AI path should fail closed before approval, got isErr=%v text=%q", isErr, text)
	}
	assertHiddenFromAI(t, text, fake.token, "90001", "spc_alpha", "70007")
	pending, _ := a.store.listApprovals("pending", 20)
	if len(pending) != 0 {
		t.Fatalf("missing token should not create an approval card: %+v", pending)
	}
	res, err := a.Execute(tool, map[string]any{"sql": "SELECT id FROM t WHERE id=1 LIMIT 1", "database": "orders"})
	msg := ""
	if err != nil {
		msg = err.Error()
	} else if res != nil {
		msg = res.Error + res.Body + res.Outcome
	}
	if !strings.Contains(msg, "请求头") && !strings.Contains(msg, "auth") && (res == nil || res.Outcome != outcomeAuthFailed) {
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
	m := saveSQLConsole(t, a, fake, s.URL, MWDatasource{Alias: "orders", DSID: json.Number("90001"), Description: "订单库"}, MWDatasource{Alias: "tasks", DSID: json.Number("90002"), Description: "任务库"})
	text, isErr := a.callMWTool(context.Background(), "tester", wsSQLQueryTool, map[string]any{"middleware": m.Name, "database": "missing", "sql": "SELECT id FROM t LIMIT 1"})
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
		MWDatasource{Alias: "orders", DSID: json.Number("90001"), Description: "订单测试库"},
		MWDatasource{Alias: "tasks", DSID: json.Number("90002"), Description: "任务库"},
	)
	tool, err := m.sqlConsoleTool(mustDS(t, m, "tasks"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Execute(tool, map[string]any{"sql": "SELECT id FROM t WHERE id=1 LIMIT 1", "database": "tasks"}); err != nil {
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

func mustDS(t *testing.T, m *Middleware, alias string) MWDatasource {
	t.Helper()
	ds, err := m.lookupDatasource(alias)
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
		MWDatasource{Alias: "orders", DSID: json.Number("90001"), Description: "订单测试库"},
		MWDatasource{Alias: "tasks", DSID: json.Number("90002"), Description: "任务库"},
	)
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
	m := saveSQLConsole(t, a, fake, s.URL, MWDatasource{Alias: "orders", DSID: json.Number("90001"), Description: "订单测试库"})
	done := make(chan approvalReply, 1)
	go func() {
		v, err := a.invokeTool(context.Background(), &mcpCtx{}, wsSQLQueryTool, map[string]any{"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t WHERE id=1 LIMIT 1"})
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
	msg, err := a.TestMiddleware(context.Background(), m)
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
	_, _ = a.callMWTool(context.Background(), "tester", wsSQLQueryTool, map[string]any{"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t"})
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
		st, err := OpenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		var ver int
		if err := st.db.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil || ver != schemaUserVersion {
			t.Fatalf("version=%d err=%v", ver, err)
		}
		if _, err := st.GetToolByName("demo_sql_query"); err == nil {
			t.Fatal("old tool should have been removed")
		}
		mw, err := st.GetMiddlewareByName("demo_sql")
		if err != nil {
			t.Fatal(err)
		}
		if !mw.Config.isSQLConsole() {
			t.Fatalf("mode=%s", mw.Config.wsMode())
		}
		if mw.Config.sqlConsoleApproval() != "always" {
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
		if !isEmptyJSONValue(mw.Config.SQLDefaults.legacyEnvID) || mw.Config.SQLDefaults.legacyEnvType != "" {
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
		st.db.Close()
	}
}

func TestSQLConsoleNameFromTool(t *testing.T) {
	if sqlConsoleNameFromTool("demo_sql_query") != "demo_sql" {
		t.Fatal(sqlConsoleNameFromTool("demo_sql_query"))
	}
	if sqlConsoleNameFromTool("other") != "other" {
		t.Fatal(sqlConsoleNameFromTool("other"))
	}
}

func middlewareRawConfig(st *Store, id int64) (string, error) {
	var raw string
	err := st.db.QueryRow(`SELECT config FROM middleware WHERE id=?`, id).Scan(&raw)
	return raw, err
}

func TestSQLConsolePerRowEnvRouting(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsole(t, a, fake, s.URL,
		MWDatasource{Alias: "orders", DSID: json.Number("90001"), EnvID: json.Number("71001"), EnvType: "TEST", Description: "订单测试库"},
		MWDatasource{Alias: "tasks", DSID: json.Number("90002"), EnvID: json.Number("72002"), EnvType: "PROD", Description: "任务库"},
	)
	tool, err := m.sqlConsoleTool(mustDS(t, m, "tasks"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Execute(tool, map[string]any{"sql": "SELECT id FROM t WHERE id=1 LIMIT 1", "database": "tasks"}); err != nil {
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
		MWDatasource{Alias: "orders", DSID: json.Number("90001"), EnvID: json.Number("8"), EnvType: "PROD"},
		MWDatasource{Alias: "tasks", DSID: json.Number("90001"), EnvID: json.Number("8"), EnvType: "prod"},
	)
	err := dup.normalize()
	if err == nil || !strings.Contains(err.Error(), "完全相同") {
		t.Fatalf("expected unique triple error, got %v", err)
	}
	if strings.Contains(err.Error(), "90001") || strings.Contains(err.Error(), "8") {
		t.Fatalf("uniqueness error leaked ids: %v", err)
	}

	alias := sqlConsoleTestMW("sqlconsole", "ws://127.0.0.1:9/ws",
		MWDatasource{Alias: "Orders", DSID: json.Number("1"), EnvID: json.Number("8"), EnvType: "PROD"},
		MWDatasource{Alias: "orders", DSID: json.Number("2"), EnvID: json.Number("9"), EnvType: "TEST"},
	)
	if err := alias.normalize(); err == nil || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("expected alias unique error, got %v", err)
	}

	missing := sqlConsoleTestMW("sqlconsole", "ws://127.0.0.1:9/ws",
		MWDatasource{Alias: "orders", DSID: json.Number("90001"), EnvType: "PROD"},
	)
	missing.Config.Datasources[0].EnvID = nil
	if err := missing.normalize(); err == nil || !strings.Contains(err.Error(), "envId") {
		t.Fatalf("expected missing envId error, got %v", err)
	}

	// Same dsId + envId but different envType is allowed.
	ok := sqlConsoleTestMW("sqlconsole", "ws://127.0.0.1:9/ws",
		MWDatasource{Alias: "orders_test", DSID: json.Number("90001"), EnvID: json.Number("8"), EnvType: "TEST"},
		MWDatasource{Alias: "orders_prod", DSID: json.Number("90001"), EnvID: json.Number("8"), EnvType: "PROD"},
	)
	if err := ok.normalize(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLConsoleEnvTypeDefaultsToPROD(t *testing.T) {
	m := sqlConsoleTestMW("sqlconsole", "ws://127.0.0.1:9/ws",
		MWDatasource{Alias: "orders", DSID: json.Number("90001"), EnvID: json.Number("70007")},
	)
	m.Config.Datasources[0].EnvType = ""
	if err := m.normalize(); err != nil {
		t.Fatal(err)
	}
	if m.Config.Datasources[0].EnvType != "PROD" {
		t.Fatalf("envType=%q", m.Config.Datasources[0].EnvType)
	}
	vals := m.Config.Datasources[0].fieldValues(&m.Config)
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
		st, err := OpenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		var ver int
		if err := st.db.QueryRow(`PRAGMA user_version`).Scan(&ver); err != nil || ver != schemaUserVersion {
			t.Fatalf("version=%d err=%v", ver, err)
		}
		mw, err := st.GetMiddlewareByName("demo_sql")
		if err != nil {
			t.Fatal(err)
		}
		if len(mw.Config.Datasources) != 1 || mw.Config.Datasources[0].Alias != "default" {
			t.Fatalf("datasources=%+v", mw.Config.Datasources)
		}
		if mw.Config.sqlConsoleApproval() != "always" {
			t.Fatalf("v8 upgrade approval=%q, want always", mw.Config.Approval)
		}
		ds := mw.Config.Datasources[0]
		if fmtSprint(ds.DSID) != "90001" || fmtSprint(ds.EnvID) != "70007" || ds.EnvType != "TEST" {
			t.Fatalf("row not promoted: %+v", ds)
		}
		if !isEmptyJSONValue(mw.Config.SQLDefaults.legacyEnvID) || mw.Config.SQLDefaults.legacyEnvType != "" {
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
		st.db.Close()
	}
}

func TestSQLConsoleSavePromotesLegacyDefaults(t *testing.T) {
	a := approvalTestApp(t)
	raw := `{"url":"ws://127.0.0.1:9/ws","ws_mode":"sql_console","ws_messages":["execute {\"data\":{\"sql\":\"{{sql}}\"}}"],"sql_defaults":{"space_code":"spc_alpha","env_id":70007,"env_type":"TEST","db_type":"mysql"},"datasources":[{"alias":"default","ds_id":90001}],"max_rows":200,"timeout_sec":15,"perms":{"select":true}}`
	c, err := decodeMWConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if isEmptyJSONValue(c.SQLDefaults.legacyEnvID) || c.SQLDefaults.legacyEnvType != "TEST" {
		t.Fatalf("expected to capture legacy defaults, got %+v", c.SQLDefaults)
	}
	m := &Middleware{Name: "legacy_sql", Type: "websocket", Config: c}
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
