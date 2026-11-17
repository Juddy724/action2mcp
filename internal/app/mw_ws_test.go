package app

import (
	"action2mcp/internal/execution"
	"action2mcp/internal/mwconfig"
	"action2mcp/internal/store"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestCookieHeaderWSS(t *testing.T) {
	cs := []Cookie{{Name: "sid", Value: "abc", Domain: "example.com", Path: "/", Secure: true, Session: true}}
	if h, _ := execution.CookieHeader(cs, "wss://example.com/ws/ssh"); h != "sid=abc" {
		t.Fatalf("wss cookie header = %q", h)
	}
	if h, _ := execution.CookieHeader(cs, "ws://example.com/ws/ssh"); h != "" {
		t.Fatalf("secure cookie leaked onto ws: %q", h)
	}
}

func TestNormalizeWebSocket(t *testing.T) {
	m := &mwconfig.Middleware{Name: "终端", Type: "websocket", Config: mwconfig.MWConfig{URL: "wss://example.com/ws?pod={{pod_name}}"}}
	if err := m.Normalize(); err != nil {
		t.Fatal(err)
	}
	if len(m.Config.WSMessages) != 2 || !strings.Contains(m.Config.WSMessages[0], "{{command}}") {
		t.Fatalf("messages: %#v", m.Config.WSMessages)
	}
	if !m.Config.Perms["log"] || m.Config.Perms["exec"] {
		t.Fatalf("perms: %#v", m.Config.Perms)
	}
	if m.Config.TimeoutSec != 30 {
		t.Fatalf("timeout %d", m.Config.TimeoutSec)
	}
	if len(m.Config.CommandAllow) == 0 {
		t.Fatal("default allowlist missing")
	}
	open := &mwconfig.Middleware{Name: "终端", Type: "websocket", Config: mwconfig.MWConfig{URL: "wss://example.com/ws", CommandAllow: []string{}}}
	if err := open.Normalize(); err != nil {
		t.Fatal(err)
	}
	if len(open.Config.CommandAllow) != 0 {
		t.Fatalf("empty allowlist filled in: %#v", open.Config.CommandAllow)
	}
	bad := &mwconfig.Middleware{Name: "终端", Type: "websocket", Config: mwconfig.MWConfig{URL: "https://example.com/ws"}}
	if err := bad.Normalize(); err == nil {
		t.Fatal("https address accepted")
	}
}

func TestCallPodReadLog(t *testing.T) {
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	var gotCmd string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Cookie") != "sid=abc" {
			http.Error(w, "no cookie", 401)
			return
		}
		if r.URL.Query().Get("pod") != "pod-a" {
			http.Error(w, "pod", 400)
			return
		}
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteMessage(websocket.BinaryMessage, []byte("pod-a # "))
		_, b, err := c.ReadMessage()
		if err != nil {
			return
		}
		gotCmd = string(b)
		_, _, _ = c.ReadMessage()
		_ = c.WriteMessage(websocket.BinaryMessage, []byte("line-1\nline-2\n"))
		_ = c.WriteMessage(websocket.BinaryMessage, []byte("pod-a # "))
	}))
	defer srv.Close()

	app, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	app.store.SaveCookies([]Cookie{{Name: "sid", Value: "abc", Domain: "127.0.0.1", Path: "/", Session: true}})
	m := &mwconfig.Middleware{Name: "终端", Type: "websocket", Config: mwconfig.MWConfig{
		URL:   "ws" + strings.TrimPrefix(srv.URL, "http") + "/term?pod={{pod_name}}",
		Perms: map[string]bool{"log": true, "exec": false},
	}}
	if err := app.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}
	p := &store.Pack{Name: "集群", Enabled: true}
	if err := app.store.SavePack(p); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.AddPackMembers(p.ID, "middleware", []int64{m.ID}); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, tool := range app.middlewares().ToolList() {
		names = append(names, tool["name"].(string))
		if tool["name"] == "pod_read_log" {
			props := tool["inputSchema"].(map[string]any)["properties"].(map[string]any)
			if _, ok := props["pod_name"]; !ok {
				t.Fatal("pod_name missing from schema")
			}
		}
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "pod_read_log") || !strings.Contains(joined, "pod_exec") {
		t.Fatalf("tools: %v", names)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	text, isErr := app.middlewares().Call(ctx, "test", "pod_read_log", map[string]any{
		"middleware": "终端", "pod_name": "pod-a", "file": "BusinessException.log", "lines": 20,
	})
	if isErr {
		t.Fatal(text)
	}
	if text != "line-1\nline-2" {
		t.Fatalf("output = %q", text)
	}
	if !strings.Contains(gotCmd, "tail -n 20 'BusinessException.log'") {
		t.Fatalf("command frame = %q", gotCmd)
	}
	msg, isErr := app.middlewares().Call(ctx, "test", "pod_exec", map[string]any{
		"middleware": "终端", "pod_name": "pod-a", "command": "ls",
	})
	if !isErr || !strings.Contains(msg, "无权限") {
		t.Fatalf("exec without perm: err=%v %q", isErr, msg)
	}
}
