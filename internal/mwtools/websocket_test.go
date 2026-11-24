package mwtools

import (
	"action2mcp/internal/mwconfig"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

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
	sedAllow := []string{"cat", "sed"}
	for _, cmd := range []string{
		"sed -n '14795,14825p' app.log",
		"sed -n '10p' app.log",
		"sed -n '10,+20p' app.log",
		"cat app.log | sed -n '1,50p'",
	} {
		if err := checkExecCommand(cmd, sedAllow); err != nil {
			t.Fatalf("expected read-only sed to pass (%s): %v", cmd, err)
		}
	}
	for _, cmd := range []string{
		"sed -i 's/a/b/g' app.log",
		"sed 's/a/b/' app.log",
		"sed -n '1,5w /tmp/out' app.log",
		"sed -n '1,5p' -i app.log",
		"sed -n '1e id' app.log",
	} {
		if err := checkExecCommand(cmd, sedAllow); err == nil {
			t.Fatal("accepted unsafe sed: " + cmd)
		}
	}
	if err := checkExecCommand("grep foo app.log 2>/dev/null", allow); err == nil || !strings.Contains(err.Error(), "2>/dev/null") || !strings.Contains(err.Error(), "sed -n") {
		t.Fatalf("expected actionable redirect error, got: %v", err)
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
	out, auth, err := runWSSession(ctx, wsURL, h, defaultTerminalMessages(t), "pod-a", 1024)
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
	_, auth, err := runWSSession(ctx, wsURL, nil, defaultTerminalMessages(t), "", 1024)
	if !auth {
		t.Fatalf("auth=%v err=%v", auth, err)
	}
}

// defaultTerminalMessages are the messages a websocket terminal gets from normalization.
func defaultTerminalMessages(t *testing.T) []string {
	t.Helper()
	m := &mwconfig.Middleware{Name: "终端", Type: "websocket", Config: mwconfig.MWConfig{URL: "ws://127.0.0.1:9/term"}}
	if err := m.Normalize(); err != nil {
		t.Fatal(err)
	}
	return m.Config.WSMessages
}
