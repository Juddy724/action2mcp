package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func jarSID(rawURL, value string) Cookie {
	u, err := url.Parse(rawURL)
	if err != nil {
		return Cookie{Name: "sid", Value: value, Domain: "127.0.0.1", Path: "/", Session: true}
	}
	return Cookie{Name: "sid", Value: value, Domain: u.Hostname(), Path: "/", Session: true}
}

func bindCookieHeader(m *Middleware) {
	if m.Config.WSHeaders == nil {
		m.Config.WSHeaders = map[string]string{}
	}
	m.Config.WSHeaders["Cookie"] = "{{header.cookie}}"
}

func saveSQLConsoleCookie(t *testing.T, a *App, fake *countingWS, httpURL, cookieVal string, harvestToken bool) *Middleware {
	t.Helper()
	if harvestToken {
		if err := a.HarvestRequestHeader("", httpURL, "sso-epctoken", fake.token); err != nil {
			t.Fatal(err)
		}
	}
	m := sqlConsoleTestMW("sqlconsole", fake.wsURL(httpURL))
	bindCookieHeader(m)
	if err := a.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}
	if err := a.store.SavePack(&Pack{Name: "sql包", Enabled: true, MiddlewareIDs: []int64{m.ID}}); err != nil {
		t.Fatal(err)
	}
	if cookieVal != "" {
		a.store.ReplaceCookies([]Cookie{jarSID(httpURL, cookieVal)})
	} else {
		a.store.ClearCookies()
	}
	got, err := a.store.GetMiddleware(m.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Config.WSHeaders["Cookie"] != "{{header.cookie}}" {
		t.Fatalf("normalized Cookie binding=%q", got.Config.WSHeaders["Cookie"])
	}
	return got
}

func assertCookieHidden(t *testing.T, blob, cookieVal, token string) {
	t.Helper()
	if cookieVal != "" && strings.Contains(blob, cookieVal) {
		t.Fatalf("leaked cookie in %q", truncate(blob, 240))
	}
	assertHiddenFromAI(t, blob, token, "90001", "spc_alpha", "70007")
}

func assertMissingCookieMsg(t *testing.T, msg string) {
	t.Helper()
	if !strings.Contains(msg, "Cookie") || !strings.Contains(msg, "登录") {
		t.Fatalf("expected missing Cookie wording, got %q", msg)
	}
	low := strings.ToLower(msg)
	if strings.Contains(low, "请求头 cookie") || strings.Contains(low, "请求头cookie") {
		t.Fatalf("cookie jar miss should not be reported as a harvested header: %q", msg)
	}
}

func TestSQLConsoleCookieJarTestConnection(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	cookieVal := "sess_" + privateTestValue(t)
	m := saveSQLConsoleCookie(t, a, fake, s.URL, cookieVal, true)
	msg, err := a.TestMiddleware(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(msg, "握手") && !strings.Contains(msg, "连接成功") {
		t.Fatalf("unexpected test message: %s", msg)
	}
	assertCookieHidden(t, msg, cookieVal, fake.token)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.conns != 1 || fake.business != 0 || fake.explain != 0 || len(fake.messages) != 0 {
		t.Fatalf("test connection should only handshake: conns=%d biz=%d expl=%d msgs=%v", fake.conns, fake.business, fake.explain, fake.messages)
	}
	if !strings.Contains(fake.handshakeCookie, cookieVal) {
		t.Fatalf("handshake Cookie=%q, want value present", fake.handshakeCookie)
	}
}

func TestSQLConsoleCookieJarMissingCookie(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	m := saveSQLConsoleCookie(t, a, fake, s.URL, "", true)
	msg, err := a.TestMiddleware(context.Background(), m)
	if err == nil {
		t.Fatalf("expected missing cookie error, got %q", msg)
	}
	assertMissingCookieMsg(t, err.Error())
	text, isErr := a.callMWTool(context.Background(), "tester", wsSQLQueryTool, map[string]any{"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t WHERE id=1 LIMIT 1"})
	if !isErr {
		t.Fatalf("call should fail closed, got %q", text)
	}
	assertMissingCookieMsg(t, text)
	assertCookieHidden(t, text+err.Error(), "", fake.token)
	pending, _ := a.store.listApprovals("pending", 20)
	if len(pending) != 0 {
		t.Fatalf("missing cookie should not create an approval card: %+v", pending)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.conns != 0 {
		t.Fatalf("missing cookie still dialed: conns=%d", fake.conns)
	}
}

func TestSQLConsoleCookieJarMissingToken(t *testing.T) {
	fake := newCountingWS(1)
	s := fake.start(t)
	a := approvalTestApp(t)
	cookieVal := "sess_" + privateTestValue(t)
	m := saveSQLConsoleCookie(t, a, fake, s.URL, cookieVal, false)
	_, err := a.TestMiddleware(context.Background(), m)
	if err == nil || (!strings.Contains(err.Error(), "请求头") && !strings.Contains(err.Error(), "登录")) {
		t.Fatalf("expected missing token error, got %v", err)
	}
	assertCookieHidden(t, err.Error(), cookieVal, fake.token)
	text, isErr := a.callMWTool(context.Background(), "tester", wsSQLQueryTool, map[string]any{"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t WHERE id=1 LIMIT 1"})
	if !isErr || (!strings.Contains(text, "请求头") && !strings.Contains(text, "登录")) {
		t.Fatalf("expected token fail-closed, got isErr=%v text=%q", isErr, text)
	}
	assertCookieHidden(t, text, cookieVal, fake.token)
	pending, _ := a.store.listApprovals("pending", 20)
	if len(pending) != 0 {
		t.Fatalf("missing token should not create an approval card: %+v", pending)
	}
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.conns != 0 {
		t.Fatalf("missing token still dialed: conns=%d", fake.conns)
	}
}

func TestSQLConsoleCookieJarCallRedacts(t *testing.T) {
	fake := newCountingWS(2)
	s := fake.start(t)
	a := approvalTestApp(t)
	cookieVal := "sess_" + privateTestValue(t)
	m := saveSQLConsoleCookie(t, a, fake, s.URL, cookieVal, true)

	tool, err := m.sqlConsoleTool(m.enabledDatasources()[0])
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := a.Prepare(tool, map[string]any{"sql": "SELECT id FROM t WHERE id=1 LIMIT 10", "database": "orders"})
	if err != nil {
		t.Fatal(err)
	}
	redactSQLConsolePreview(prepared, m, "orders", nil)
	prev, _ := json.Marshal(prepared.Preview)
	assertCookieHidden(t, string(prev)+prepared.PreviewHash, cookieVal, fake.token)

	done := make(chan approvalReply, 1)
	go func() {
		v, invErr := a.invokeTool(context.Background(), &mcpCtx{}, wsSQLQueryTool, map[string]any{"middleware": m.Name, "database": "orders", "sql": "SELECT id FROM t WHERE id=1 LIMIT 10"})
		done <- unpackApprovalReply(v, invErr)
	}()
	rec := pendingApprovals(t, a, 1)[0]
	blob, _ := json.Marshal(rec)
	assertCookieHidden(t, string(blob), cookieVal, fake.token)
	approveRecord(t, a, rec)
	reply := getApprovalReply(t, done)
	if reply.isError {
		t.Fatalf("approved call failed: %s", reply.text)
	}
	assertCookieHidden(t, reply.text, cookieVal, fake.token)

	fake.mu.Lock()
	gotCookie := fake.handshakeCookie
	fake.mu.Unlock()
	if !strings.Contains(gotCookie, cookieVal) {
		t.Fatalf("real call did not send cookie: %q", gotCookie)
	}

	rows := a.store.ListAudit(m.Name, 10)
	if len(rows) == 0 {
		t.Fatal("expected audit row")
	}
	audit, _ := json.Marshal(rows)
	assertCookieHidden(t, string(audit), cookieVal, fake.token)
}

func TestRequiredSiteHeadersSkipsCookieJarRef(t *testing.T) {
	a := approvalTestApp(t)
	m := sqlConsoleTestMW("sqlconsole", "wss://sql.example.com/api/ws")
	bindCookieHeader(m)
	if err := a.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}
	site := a.store.EnsureSite(m.Config.URL)
	if site == nil {
		t.Fatal("expected site for wss URL")
	}
	need := a.requiredSiteHeaders(site)
	for _, n := range need {
		if strings.EqualFold(n, "cookie") {
			t.Fatalf("required headers should exclude cookie: %v", need)
		}
	}
	if len(need) != 1 || need[0] != "sso-epctoken" {
		t.Fatalf("required headers=%v", need)
	}
}

func TestWSToolHeaderCookieBinding(t *testing.T) {
	fake := newCountingWS(2)
	s := fake.start(t)
	a := approvalTestApp(t)
	cookieVal := "sess_" + privateTestValue(t)
	if err := a.HarvestRequestHeader("", s.URL, "sso-epctoken", fake.token); err != nil {
		t.Fatal(err)
	}
	a.store.ReplaceCookies([]Cookie{jarSID(s.URL, cookieVal)})
	tool := wsTestTool(fake.wsURL(s.URL), "{{header.sso-epctoken}}")
	tool.Headers = map[string]string{"Cookie": "{{header.cookie}}"}
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	prepared, err := a.Prepare(tool, map[string]any{"sql": "SELECT id FROM t WHERE id=1 LIMIT 10"})
	if err != nil {
		t.Fatal(err)
	}
	prev, _ := json.Marshal(prepared.Preview)
	assertCookieHidden(t, string(prev), cookieVal, fake.token)
	res, err := a.Send(prepared)
	if err != nil {
		t.Fatal(err)
	}
	if res.Outcome != outcomeSuccess {
		t.Fatalf("outcome=%s err=%s body=%s", res.Outcome, res.Error, res.Body)
	}
	assertCookieHidden(t, res.Body+res.Error, cookieVal, fake.token)
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if !strings.Contains(fake.handshakeCookie, cookieVal) {
		t.Fatalf("old WS path handshake Cookie=%q", fake.handshakeCookie)
	}
}

func TestResolveCookieJarWSS(t *testing.T) {
	a := approvalTestApp(t)
	cookieVal := "sess_" + privateTestValue(t)
	a.store.ReplaceCookies([]Cookie{{Name: "sid", Value: cookieVal, Domain: "sql.example.com", Path: "/", Secure: true, Session: true}})
	var secrets []string
	got, err := a.resolveCookieJar("wss://sql.example.com/api/ws/execute", &secrets)
	if err != nil {
		t.Fatal(err)
	}
	if got != "sid="+cookieVal {
		t.Fatalf("got %q", got)
	}
	joined := strings.Join(secrets, "\n")
	if !strings.Contains(joined, cookieVal) {
		t.Fatal("cookie was not registered as a secret")
	}
	if _, err := a.GetSiteHeader("wss://sql.example.com/api/ws/execute", "cookie"); err == nil {
		t.Fatal("harvested site_headers should not contain cookie")
	}
	v, err := a.resolveWSRef("HEADER.COOKIE", "wss://sql.example.com/api/ws/execute", &secrets)
	if err != nil || v != got {
		t.Fatalf("case-insensitive header.cookie: v=%q err=%v", v, err)
	}
}

func TestNormalizeCookieHeaderBinding(t *testing.T) {
	cases := map[string]string{
		"{{header.cookie}}":   "{{header.cookie}}",
		"{{HEADER.COOKIE}}":   "{{header.cookie}}",
		"{{ header.Cookie }}": "{{header.cookie}}",
		"sid=should-not-keep": "{{header.cookie}}",
		"":                    "{{header.cookie}}",
		"{{cookie.sid}}":      "{{cookie.sid}}",
		"{{secret.session}}":  "{{secret.session}}",
	}
	for in, want := range cases {
		h := map[string]string{"cookie": in, "sso-epctoken": "{{header.sso-epctoken}}"}
		normalizeCookieHeaderBinding(h)
		if _, ok := h["cookie"]; ok {
			t.Fatalf("lowercase cookie key should have been canonicalized: %v", h)
		}
		if h["Cookie"] != want {
			t.Fatalf("input %q: got %q want %q", in, h["Cookie"], want)
		}
		if h["sso-epctoken"] != "{{header.sso-epctoken}}" {
			t.Fatalf("other headers changed: %v", h)
		}
	}
}

func TestMigrateWSToolNormalizesCookieBinding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "v7-cookie.db")
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
INSERT INTO tools(name,title,description,method,url,headers,body,params,config,approval) VALUES('demo_sql_query','SQL','','WS','ws://127.0.0.1:9/ws','{"cookie":"{{HEADER.cookie}}","sso-epctoken":"{{header.sso-epctoken}}"}','','[{"name":"sql","type":"string","required":true}]','{"messages":["execute {\"data\":{\"sql\":\"{{sql}}\",\"spaceCode\":\"spc_alpha\",\"dsId\":90001,\"envId\":70007,\"envType\":\"TEST\",\"dbType\":\"mysql\"},\"token\":\"{{header.sso-epctoken}}\"}"],"sql_guard":{"enabled":true,"param":"sql","path":"data.sql","max_rows":200}}','always');
PRAGMA user_version=7;`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	st, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.db.Close()
	mw, err := st.GetMiddlewareByName("demo_sql")
	if err != nil {
		t.Fatal(err)
	}
	if mw.Config.WSHeaders["Cookie"] != "{{header.cookie}}" {
		t.Fatalf("migrated Cookie binding=%v", mw.Config.WSHeaders)
	}
	if _, ok := mw.Config.WSHeaders["cookie"]; ok {
		t.Fatalf("lowercase cookie key left behind: %v", mw.Config.WSHeaders)
	}
	if mw.Config.WSHeaders["sso-epctoken"] != "{{header.sso-epctoken}}" {
		t.Fatalf("token binding lost: %v", mw.Config.WSHeaders)
	}
}
