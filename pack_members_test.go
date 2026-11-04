package main

import (
	"bufio"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPackMembershipEndpoints(t *testing.T) {
	dir, _ := os.MkdirTemp("", "a2m-members-")
	defer os.RemoveAll(dir)
	app, err := NewApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	var tools []*Tool
	for _, n := range []string{"t_a", "t_b", "t_c"} {
		x := &Tool{Name: n, Title: n, Method: "GET", URL: "http://127.0.0.1:1/" + n}
		if err := app.store.SaveTool(x); err != nil {
			t.Fatal(err)
		}
		tools = append(tools, x)
	}
	mw := &Middleware{Name: "库", Type: "mysql", Config: MWConfig{Host: "127.0.0.1", Port: 1, User: "u"}}
	app.store.SaveMiddleware(mw)
	p := &Pack{Name: "包", Enabled: true, ToolIDs: []int64{tools[0].ID}}
	if err := app.store.SavePack(p); err != nil {
		t.Fatal(err)
	}
	api := func(method, path, body string) map[string]any {
		req, _ := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var m map[string]any
		json.NewDecoder(resp.Body).Decode(&m)
		if resp.StatusCode != 200 {
			t.Fatalf("%s %s: %d %v", method, path, resp.StatusCode, m)
		}
		return m
	}
	members := func() ([]int64, []int64) {
		l, _ := app.store.ListPacks()
		return l[0].ToolIDs, l[0].MiddlewareIDs
	}

	c := &mcpTestClient{t: t, url: srv.URL + "/mcp"}
	c.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "members", "version": "1"}})
	c.tool("load_pack", map[string]any{"pack": "包"})
	notes := make(chan string, 10)
	req, _ := http.NewRequest("GET", c.url, nil)
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Mcp-Session-Id", c.sid)
	sresp, err := http.DefaultClient.Do(req)
	if err != nil || sresp.StatusCode != 200 {
		t.Fatal("GET stream", err)
	}
	defer sresp.Body.Close()
	go readSSE(bufio.NewReader(sresp.Body), func(b []byte) { notes <- string(b) })
	time.Sleep(100 * time.Millisecond)
	expectNote := func(want bool, what string) {
		select {
		case m := <-notes:
			if !want {
				t.Fatalf("%s: unexpected notification %s", what, m)
			}
			if !strings.Contains(m, "notifications/tools/list_changed") {
				t.Fatalf("%s: %s", what, m)
			}
		case <-time.After(400 * time.Millisecond):
			if want {
				t.Fatalf("%s: no list_changed", what)
			}
		}
	}

	// add two tools (+ one already in, + one unknown id): only 2 added, existing member kept
	r := api("POST", "/api/packs/1/tools", `{"ids":[`+id64(tools[1].ID)+`,`+id64(tools[2].ID)+`,`+id64(tools[0].ID)+`,999]}`)
	if r["added"].(float64) != 2 {
		t.Fatalf("added %v", r)
	}
	expectNote(true, "add tools")
	if ti, _ := members(); len(ti) != 3 {
		t.Fatalf("members %v", ti)
	}
	if n := c.toolNames(); !has(n, "t_a") || !has(n, "t_b") || !has(n, "t_c") {
		t.Fatalf("tools/list %v", n)
	}
	// re-adding is a no-op without notification
	api("POST", "/api/packs/1/tools", `{"ids":[`+id64(tools[1].ID)+`]}`)
	expectNote(false, "noop add")

	// remove one: tool itself stays
	r = api("DELETE", "/api/packs/1/tools/"+id64(tools[1].ID), "")
	if r["removed"] != true {
		t.Fatalf("remove %v", r)
	}
	expectNote(true, "remove tool")
	if n := c.toolNames(); has(n, "t_b") || !has(n, "t_a") {
		t.Fatalf("after remove %v", n)
	}
	if all, _ := app.store.ListTools(); len(all) != 3 {
		t.Fatalf("tool deleted? %d", len(all))
	}
	txt, _ := c.tool("list_packs", map[string]any{})
	if !strings.Contains(txt, `"tool_names":["t_a","t_c"]`) {
		t.Fatalf("list_packs %s", txt)
	}
	// remove non-member: ok, no notification
	api("DELETE", "/api/packs/1/tools/"+id64(tools[1].ID), "")
	expectNote(false, "noop remove")

	// middleware add / remove
	api("POST", "/api/packs/1/middleware", `{"ids":[`+id64(mw.ID)+`]}`)
	expectNote(true, "add mw")
	if _, mi := members(); len(mi) != 1 {
		t.Fatalf("mw members %v", mi)
	}
	if n := c.toolNames(); !has(n, "db_query") {
		t.Fatalf("mw tools %v", n)
	}
	api("DELETE", "/api/packs/1/middleware/"+id64(mw.ID), "")
	expectNote(true, "remove mw")
	if n := c.toolNames(); has(n, "db_query") {
		t.Fatalf("mw tools after remove %v", n)
	}

	// flat mode reflects membership too
	app.store.SetSetting("mcp_mode", ModeFlat)
	if n := c.toolNames(); strings.Join(n, ",") != "t_a,t_c" {
		t.Fatalf("flat %v", n)
	}
	// unknown pack
	req2, _ := http.NewRequest("POST", srv.URL+"/api/packs/42/tools", strings.NewReader(`{"ids":[1]}`))
	if resp, _ := http.DefaultClient.Do(req2); resp.StatusCode != 400 {
		t.Fatalf("unknown pack status %d", resp.StatusCode)
	}
}

func id64(n int64) string { b, _ := json.Marshal(n); return string(b) }
