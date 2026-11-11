package main

import (
	"bufio"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type mcpTestClient struct {
	t   *testing.T
	url string
	sid string
	id  int
}

// call posts one request and returns (all SSE/JSON messages, the response message).
func (c *mcpTestClient) call(method string, params any) ([]map[string]any, map[string]any) {
	c.id++
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	req, _ := http.NewRequest("POST", c.url, strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.sid != "" {
		req.Header.Set("Mcp-Session-Id", c.sid)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	if s := resp.Header.Get("Mcp-Session-Id"); s != "" {
		c.sid = s
	}
	var msgs []map[string]any
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		readSSE(resp.Body, func(b []byte) {
			var m map[string]any
			json.Unmarshal(b, &m)
			msgs = append(msgs, m)
		})
	} else {
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		msgs = append(msgs, m)
	}
	for _, m := range msgs {
		if m["id"] != nil {
			return msgs, m
		}
	}
	c.t.Fatalf("no response for %s", method)
	return nil, nil
}

func (c *mcpTestClient) toolNames() []string {
	_, r := c.call("tools/list", map[string]any{})
	out := []string{}
	for _, t := range r["result"].(map[string]any)["tools"].([]any) {
		out = append(out, t.(map[string]any)["name"].(string))
	}
	return out
}

func (c *mcpTestClient) tool(name string, args any) (string, bool) {
	_, r := c.call("tools/call", map[string]any{"name": name, "arguments": args})
	if e, ok := r["error"].(map[string]any); ok {
		return e["message"].(string), true
	}
	res := r["result"].(map[string]any)
	txt := res["content"].([]any)[0].(map[string]any)["text"].(string)
	isErr, _ := res["isError"].(bool)
	return txt, isErr
}

func has(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func TestTieredDiscovery(t *testing.T) {
	const secret = "Tiered-S3cret!pw"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Write(b) // echoes the body, which contains the secret
	}))
	defer upstream.Close()

	// not t.TempDir(): a tool call may start the dedicated browser, whose
	// profile can still be written to while the test cleans up.
	dir, _ := os.MkdirTemp("", "a2m-tiered-")
	defer os.RemoveAll(dir)
	app, err := NewApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	app.vault.Upsert("svc_password", "secret", secret, upstream.URL, "")
	echo := &Tool{Approval: "off", Name: "echo_login", Title: "回显", Method: "POST", URL: upstream.URL + "/echo",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"kw":"{{kw}}","pw":"{{secret.svc_password}}"}`, Params: []Param{{Name: "kw", Type: "string", Required: true}}}
	other := &Tool{Name: "hidden_tool", Title: "隐藏", Method: "GET", URL: upstream.URL + "/h"}
	for _, x := range []*Tool{echo, other} {
		if err := app.store.SaveTool(x); err != nil {
			t.Fatal(err)
		}
	}
	db := &Middleware{Name: "订单库", Type: "mysql", Config: MWConfig{Host: "127.0.0.1", Port: 1, User: "u"}}
	if err := app.store.SaveMiddleware(db); err != nil {
		t.Fatal(err)
	}
	p1 := &Pack{Name: "回显包", Description: "回显测试", Scenarios: "需要回显时", Enabled: true, ToolIDs: []int64{echo.ID}, MiddlewareIDs: []int64{db.ID}}
	p2 := &Pack{Name: "关闭的包", Enabled: false, ToolIDs: []int64{other.ID}}
	app.store.SavePack(p1)
	app.store.SavePack(p2)

	c := &mcpTestClient{t: t, url: srv.URL + "/mcp"}
	_, init := c.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "tiered-test"}})
	caps := init["result"].(map[string]any)["capabilities"].(map[string]any)["tools"].(map[string]any)
	if caps["listChanged"] != true {
		t.Fatal("listChanged capability not declared")
	}

	// 1) only entry tools
	names := c.toolNames()
	if len(names) != 4 || !has(names, "list_packs") || has(names, "echo_login") {
		t.Fatalf("initial tools: %v", names)
	}

	// 2) list_packs shows enabled packs only
	txt, _ := c.tool("list_packs", map[string]any{})
	var lp struct {
		Packs []struct {
			ID              int64    `json:"id"`
			Name            string   `json:"name"`
			Scenarios       string   `json:"scenarios"`
			ToolCount       int      `json:"tool_count"`
			Middleware      []string `json:"middleware"`
			MiddlewareCount int      `json:"middleware_count"`
			Loaded          bool     `json:"loaded"`
		} `json:"packs"`
	}
	if err := json.Unmarshal([]byte(txt), &lp); err != nil {
		t.Fatalf("list_packs not JSON: %s", txt)
	}
	var echoOK, recOK bool
	for _, p := range lp.Packs {
		if p.Name == "回显包" && p.Scenarios == "需要回显时" && p.ToolCount == 1 && p.MiddlewareCount == 1 && !p.Loaded {
			echoOK = true
		}
		if p.Name == "录制分析" && p.ToolCount >= 6 && !p.Loaded {
			recOK = true
		}
	}
	if len(lp.Packs) != 2 || !echoOK || !recOK {
		t.Fatalf("list_packs: %s", txt)
	}

	// open the GET SSE stream
	streamMsgs := make(chan string, 10)
	req, _ := http.NewRequest("GET", c.url, nil)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Mcp-Session-Id", c.sid)
	sresp, err := http.DefaultClient.Do(req)
	if err != nil || sresp.StatusCode != 200 {
		t.Fatalf("GET stream: %v %v", err, sresp)
	}
	defer sresp.Body.Close()
	go readSSE(bufio.NewReader(sresp.Body), func(b []byte) { streamMsgs <- string(b) })
	time.Sleep(100 * time.Millisecond)

	// 3) load_pack -> list_changed on the GET stream, tools in the result and in tools/list
	txt, isErr := c.tool("load_pack", map[string]any{"pack": "回显包"})
	if isErr || !strings.Contains(txt, `"echo_login"`) || !strings.Contains(txt, "inputSchema") || !strings.Contains(txt, "db_query") {
		t.Fatalf("load_pack: %s", txt)
	}
	select {
	case m := <-streamMsgs:
		if !strings.Contains(m, "notifications/tools/list_changed") {
			t.Fatalf("unexpected stream msg %s", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no list_changed on GET stream")
	}
	names = c.toolNames()
	if !has(names, "echo_login") || !has(names, "db_query") || has(names, "hidden_tool") || !has(names, "list_packs") {
		t.Fatalf("after load: %v", names)
	}

	// 4) direct call; the secret is sent upstream but scrubbed from the result
	txt, isErr = c.tool("echo_login", map[string]any{"kw": "张三"})
	if isErr || !strings.Contains(txt, "张三") || strings.Contains(txt, secret) {
		t.Fatalf("direct call: %s", txt)
	}
	// 5) call_pack_tool fallback, also with stringified arguments
	txt, isErr = c.tool("call_pack_tool", map[string]any{"tool": "echo_login", "arguments": map[string]any{"kw": "李四"}})
	if isErr || !strings.Contains(txt, "李四") || strings.Contains(txt, secret) {
		t.Fatalf("fallback call: %s", txt)
	}
	txt, isErr = c.tool("call_pack_tool", map[string]any{"tool": "echo_login", "arguments": `{"kw":"王五"}`})
	if isErr || !strings.Contains(txt, "王五") {
		t.Fatalf("fallback stringified: %s", txt)
	}
	// 6) middleware permission denial through the fallback (DELETE is off by default) + audit
	txt, isErr = c.tool("call_pack_tool", map[string]any{"tool": "db_query", "arguments": map[string]any{"middleware": "订单库", "sql": "DELETE FROM orders WHERE id=1"}})
	if !isErr || !strings.Contains(txt, "无权限") {
		t.Fatalf("mw deny via fallback: %s", txt)
	}
	if au := app.store.ListAudit("订单库", 5); len(au) == 0 || au[0].Allowed || au[0].Client != "tiered-test" {
		t.Fatalf("audit: %+v", au)
	}
	// 7) disabled pack: invisible, not loadable, its tools not callable
	if txt, isErr = c.tool("load_pack", map[string]any{"pack": "关闭的包"}); !isErr || !strings.Contains(txt, "不存在或未开启") {
		t.Fatalf("disabled load: %s", txt)
	}
	if txt, isErr = c.tool("call_pack_tool", map[string]any{"tool": "hidden_tool"}); !isErr || !strings.Contains(txt, "load_pack") {
		t.Fatalf("disabled tool via fallback: %s", txt)
	}
	if _, isErr = c.tool("hidden_tool", map[string]any{}); !isErr {
		t.Fatal("disabled tool directly callable")
	}
	// lenient: a second session that never loaded the pack can still call an enabled pack's tool
	c2 := &mcpTestClient{t: t, url: c.url}
	c2.call("initialize", map[string]any{})
	if txt, isErr = c2.tool("echo_login", map[string]any{"kw": "x"}); isErr {
		t.Fatalf("lenient direct call: %s", txt)
	}
	if n := c2.toolNames(); len(n) != 4 {
		t.Fatalf("session state leaked into other session: %v", n)
	}
	// 8) unload
	txt, isErr = c.tool("unload_pack", map[string]any{"pack": "回显包"})
	if isErr || !strings.Contains(txt, `"was_loaded":true`) {
		t.Fatalf("unload: %s", txt)
	}
	if names = c.toolNames(); len(names) != 4 {
		t.Fatalf("after unload: %v", names)
	}
	// without a GET stream the notification is delivered inline as SSE in the POST response
	sresp.Body.Close()
	time.Sleep(100 * time.Millisecond)
	msgs, _ := c.call("tools/call", map[string]any{"name": "load_pack", "arguments": map[string]any{"pack": "1"}})
	if len(msgs) != 2 || msgs[0]["method"] != "notifications/tools/list_changed" {
		t.Fatalf("inline notification: %v", msgs)
	}
	// console disabling a loaded pack removes its tools at once
	app.store.SetPackEnabled(p1.ID, false)
	if names = c.toolNames(); len(names) != 4 {
		t.Fatalf("disabled-after-load still listed: %v", names)
	}
	// flat mode switch restores the 0.3.0 behaviour
	app.store.SetPackEnabled(p1.ID, true)
	app.store.SetSetting("mcp_mode", ModeFlat)
	if names = c.toolNames(); has(names, "list_packs") || !has(names, "echo_login") {
		t.Fatalf("flat mode: %v", names)
	}
}

// A 0.3.0 database (no packs.scenarios, no settings table) opens and keeps its data.
func TestMigrateFrom030(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "a2m.db")
	db, err := sql.Open("sqlite", p)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE tools(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, title TEXT, description TEXT, method TEXT, url TEXT, headers TEXT, body TEXT, params TEXT, cred_headers TEXT, source_request_id INTEGER, created_at TEXT, updated_at TEXT)`,
		`CREATE TABLE packs(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, description TEXT, enabled INTEGER, created_at TEXT)`,
		`CREATE TABLE pack_tools(pack_id INTEGER, tool_id INTEGER, PRIMARY KEY(pack_id, tool_id))`,
		`INSERT INTO tools(name,title,description,method,url,headers,body,params,cred_headers,created_at,updated_at) VALUES('t1','T','','GET','http://x/','{}','','[]','[]','','')`,
		`INSERT INTO packs(name,description,enabled,created_at) VALUES('老包','desc',1,'')`,
		`INSERT INTO pack_tools VALUES(1,1)`,
		`PRAGMA user_version=3`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	st, err := OpenStore(p)
	if err != nil {
		t.Fatal(err)
	}
	packs, _ := st.ListPacks()
	if len(packs) != 1 || packs[0].Name != "老包" || packs[0].Scenarios != "" || packs[0].Guide != "" || len(packs[0].ToolIDs) != 1 {
		t.Fatalf("packs after migration: %+v", packs)
	}
	packs[0].Scenarios = "查订单"
	if err := st.SavePack(packs[0]); err != nil {
		t.Fatal(err)
	}
	packs, _ = st.ListPacks()
	if packs[0].Scenarios != "查订单" {
		t.Fatal("scenarios not saved")
	}
	if st.GetSetting("mcp_mode", ModeTiered) != ModeTiered {
		t.Fatal("default mode")
	}
	st.db.Close()
	if st, err = OpenStore(p); err != nil { // idempotent
		t.Fatal(err)
	}
	st.db.Close()
}
