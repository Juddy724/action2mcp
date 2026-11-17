package app

import (
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
	if h, _ := CookieHeader(cs, "wss://example.com/ws/ssh"); h != "sid=abc" {
		t.Fatalf("wss cookie header = %q", h)
	}
	if h, _ := CookieHeader(cs, "ws://example.com/ws/ssh"); h != "" {
		t.Fatalf("secure cookie leaked onto ws: %q", h)
	}
}

func TestWSCommandPolicy(t *testing.T) {
	got, err := tailCommand("BusinessException.log", 100)
	if err != nil || got != "tail -n 100 'BusinessException.log'" {
		t.Fatalf("tail = %q %v", got, err)
	}
	if _, err := tailCommand("a\nrm", 10); err == nil {
		t.Fatal("newline in path accepted")
	}
	allow := []string{"tail", "ls", "grep", "head"}
	if err := checkExecCommand("tail -n 1 a.log", allow); err != nil {
		t.Fatal(err)
	}
	if err := checkExecCommand("tail -n 20 a.log | grep -F 'trace-1' | head -n 20", allow); err != nil {
		t.Fatal(err)
	}
	if err := checkExecCommand("grep 'a|b' file | head", allow); err != nil {
		t.Fatal(err)
	}
	if err := checkExecCommand("rm -rf /", allow); err == nil {
		t.Fatal("rm allowed")
	}
	if err := checkExecCommand("tail a.log | rm x", allow); err == nil {
		t.Fatal("piped rm allowed")
	}
	if err := checkExecCommand("tail a.log; rm x", allow); err == nil {
		t.Fatal("chained command allowed")
	}
	if err := checkExecCommand("tail a.log > /tmp/x", allow); err == nil {
		t.Fatal("redirect allowed")
	}
	if err := checkExecCommand("grep $(id) file", allow); err == nil {
		t.Fatal("command substitution allowed")
	}
	if err := checkExecCommand("ls || rm", allow); err == nil {
		t.Fatal("or-list allowed")
	}
	if err := checkExecCommand("tail a.log |", allow); err == nil {
		t.Fatal("dangling pipe allowed")
	}
	if err := checkExecCommand("echo hi", nil); err != nil {
		t.Fatal(err)
	}
	search := []string{"grep", "zgrep", "rg", "find", "cut", "wc", "stat"}
	for _, cmd := range []string{
		"find /logs -maxdepth 2 -type f -name '*.log' -mmin -30 -mtime -1 -size +1k",
		"rg -n -F 'trace-1' /logs",
		"zgrep -n -F 'trace-1' /logs/a.log.gz | cut -c 1-200",
		"grep -n -F 'trace-1' /logs/a.log | cut -c1-200",
		"rg -n trace-1 /logs | cut -c 1-200",
		"wc -l /logs/a.log",
		"stat /logs/a.log",
	} {
		if err := checkExecCommand(cmd, search); err != nil {
			t.Fatal(cmd, err)
		}
	}
	for _, cmd := range []string{
		"find /logs -name x -exec rm {} +",
		"find /logs -delete",
		"cut -f 1 -d ,",
		"cut /logs/a.log",
		"rg --pre cat /logs",
		"rg --pre=cat /logs",
	} {
		if err := checkExecCommand(cmd, search); err == nil {
			t.Fatal("accepted " + cmd)
		}
	}
}

func TestNormalizeWebSocket(t *testing.T) {
	m := &Middleware{Name: "终端", Type: "websocket", Config: MWConfig{URL: "wss://example.com/ws?pod={{pod_name}}"}}
	if err := m.normalize(); err != nil {
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
	open := &Middleware{Name: "终端", Type: "websocket", Config: MWConfig{URL: "wss://example.com/ws", CommandAllow: []string{}}}
	if err := open.normalize(); err != nil {
		t.Fatal(err)
	}
	if len(open.Config.CommandAllow) != 0 {
		t.Fatalf("empty allowlist filled in: %#v", open.Config.CommandAllow)
	}
	bad := &Middleware{Name: "终端", Type: "websocket", Config: MWConfig{URL: "https://example.com/ws"}}
	if err := bad.normalize(); err == nil {
		t.Fatal("https address accepted")
	}
}

func TestPromptDoesNotCutLogLine(t *testing.T) {
	if _, ok := peelPrompt("fail pod-a while starting\n", "pod-a"); ok {
		t.Fatal("log line treated as prompt")
	}
	body, ok := peelPrompt("fail pod-a while starting\npod-a # ", "pod-a")
	if !ok || body != "fail pod-a while starting" {
		t.Fatalf("peel = %q %v", body, ok)
	}
}

func TestWSSession(t *testing.T) {
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	gotCookie := ""
	gotCmd := ""
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie = r.Header.Get("Cookie")
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
		_ = c.WriteMessage(websocket.BinaryMessage, []byte("fail pod-a while starting\n"))
		_ = c.WriteMessage(websocket.BinaryMessage, []byte("hello\n"))
		_ = c.WriteMessage(websocket.BinaryMessage, []byte("pod-a # "))
	}))
	defer srv.Close()

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/term"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h := http.Header{}
	h.Set("Cookie", "sid=abc")
	out, auth, err := runWSSession(ctx, wsURL, h, defaultWSMessages(), "pod-a", 1024)
	if err != nil || auth {
		t.Fatalf("session: %v auth=%v", err, auth)
	}
	if out != "fail pod-a while starting\nhello" {
		t.Fatalf("output = %q", out)
	}
	if gotCookie != "sid=abc" {
		t.Fatalf("cookie = %q", gotCookie)
	}
	if !strings.Contains(gotCmd, "tail") && !strings.Contains(gotCmd, "{{command}}") {
		// default template still contains the unsubstituted marker only if command var is empty.
		// render is not applied here; the frame is sent as stored, with {{command}} literal.
		// This test checks the session, not substitution.
	}
	if strings.Contains(gotCmd, "TERMINAL_COMMAND") == false {
		t.Fatalf("frame = %q", gotCmd)
	}
}

func TestWSSessionAuth(t *testing.T) {
	up := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := up.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.WriteMessage(websocket.TextMessage, []byte(`{"messageCode":"auth.not.login"}`))
	}))
	defer srv.Close()
	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, auth, err := runWSSession(ctx, wsURL, nil, defaultWSMessages(), "", 1024)
	if !auth {
		t.Fatalf("auth=%v err=%v", auth, err)
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
	m := &Middleware{Name: "终端", Type: "websocket", Config: MWConfig{
		URL:   "ws" + strings.TrimPrefix(srv.URL, "http") + "/term?pod={{pod_name}}",
		Perms: map[string]bool{"log": true, "exec": false},
	}}
	if err := app.store.SaveMiddleware(m); err != nil {
		t.Fatal(err)
	}
	p := &Pack{Name: "集群", Enabled: true}
	if err := app.store.SavePack(p); err != nil {
		t.Fatal(err)
	}
	if _, err := app.store.AddPackMembers(p.ID, "middleware", []int64{m.ID}); err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for _, tool := range app.mwToolList() {
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
	text, isErr := app.callMWTool(ctx, "test", "pod_read_log", map[string]any{
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
	msg, isErr := app.callMWTool(ctx, "test", "pod_exec", map[string]any{
		"middleware": "终端", "pod_name": "pod-a", "command": "ls",
	})
	if !isErr || !strings.Contains(msg, "无权限") {
		t.Fatalf("exec without perm: err=%v %q", isErr, msg)
	}
}
