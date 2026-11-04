package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// End-to-end (no browser): console loads, MCP lists/calls a tool with the
// cookie attached from the local jar, disabled packs hide tools, and exports
// carry no credentials.
func TestServerMCPAndExport(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("sid")
		if err != nil || c.Value != "secret-session" {
			w.WriteHeader(401)
			io.WriteString(w, `{"msg":"login"}`)
			return
		}
		b, _ := io.ReadAll(r.Body)
		w.Write(b)
	}))
	defer upstream.Close()

	app, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	srv := httptest.NewServer(app.Handler())
	defer srv.Close()

	// console page
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	page, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(page), "Action2MCP") {
		t.Fatalf("console not served: %d", resp.StatusCode)
	}

	tool := &Tool{Name: "echo_search", Title: "查询", Method: "POST", URL: upstream.URL + "/api/search",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"kw":"{{kw}}"}`, Params: []Param{{Name: "kw", Type: "string", Required: true}},
		CredHeaders: []string{"cookie"}}
	if err := app.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	pack := &Pack{Name: "测试包", Enabled: true, ToolIDs: []int64{tool.ID}}
	if err := app.store.SavePack(pack); err != nil {
		t.Fatal(err)
	}
	app.store.ReplaceCookies([]Cookie{{Name: "sid", Value: "secret-session", Domain: "127.0.0.1", Path: "/"}})
	app.store.SetSetting("mcp_mode", ModeFlat) // this test covers the 0.3.0-style flat mode

	sid := ""
	rpc := func(body string) map[string]any {
		req, _ := http.NewRequest("POST", srv.URL+"/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if sid != "" {
			req.Header.Set("Mcp-Session-Id", sid)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if s := resp.Header.Get("Mcp-Session-Id"); s != "" {
			sid = s
		}
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	rpc(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if sid == "" {
		t.Fatal("no Mcp-Session-Id")
	}
	list := rpc(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if b, _ := json.Marshal(list); !bytes.Contains(b, []byte("echo_search")) {
		t.Fatalf("tool not listed: %s", b)
	}
	call := rpc(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo_search","arguments":{"kw":"张"}}}`)
	b, _ := json.Marshal(call)
	if !bytes.Contains(b, []byte("HTTP 200")) || !strings.Contains(string(b), "张") {
		t.Fatalf("call failed: %s", b)
	}

	app.store.SetPackEnabled(pack.ID, false)
	list = rpc(`{"jsonrpc":"2.0","id":4,"method":"tools/list"}`)
	if b, _ := json.Marshal(list); bytes.Contains(b, []byte("echo_search")) {
		t.Fatalf("disabled pack still exposes tool: %s", b)
	}

	// cross-site requests are refused
	req, _ := http.NewRequest("POST", srv.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Origin", "http://evil.example")
	if r, _ := http.DefaultClient.Do(req); r == nil || r.StatusCode != 403 {
		t.Fatal("foreign origin not rejected")
	}

	exp, err := app.Export()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(exp, []byte("secret-session")) {
		t.Fatal("export leaked cookie value")
	}
	if !bytes.Contains(exp, []byte("echo_search")) {
		t.Fatal("export missing tool")
	}
}

func TestNoiseClassification(t *testing.T) {
	cases := []struct {
		q     ReqRecord
		noise bool
	}{
		{ReqRecord{Method: "GET", URL: "https://x.com/static/app.js", ResourceType: "Script"}, true},
		{ReqRecord{Method: "OPTIONS", URL: "https://x.com/api/order"}, true},
		{ReqRecord{Method: "POST", URL: "https://x.com/api/order/create", ResourceType: "Fetch", Status: 200, RespMime: "application/json"}, false},
	}
	for _, c := range cases {
		if n, why := ClassifyNoise(&c.q); n != c.noise {
			t.Errorf("%s %s: noise=%v (%s) want %v", c.q.Method, c.q.URL, n, why, c.noise)
		}
	}
}
