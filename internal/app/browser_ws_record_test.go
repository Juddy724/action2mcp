package app

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"action2mcp/internal/cdp"
)

func TestRecordWebSocket(t *testing.T) {
	app, bs, id := newWSRec(t, "ws")
	defer app.Shutdown()
	payload := "line1\n→ 12:00:00.000 text\n…[已截断]\nline2"
	send := wsSend(bs)
	send("Network.webSocketCreated", map[string]any{"requestId": "1", "url": "wss://example.com/ws/ssh?pod=a"})
	send("Network.webSocketWillSendHandshakeRequest", map[string]any{
		"requestId": "1", "request": map[string]any{"headers": map[string]any{"Cookie": "sid=secret"}},
	})
	send("Network.webSocketHandshakeResponseReceived", map[string]any{
		"requestId": "1", "response": map[string]any{"status": 101, "headers": map[string]any{"Upgrade": "websocket"}},
	})
	send("Network.webSocketFrameSent", map[string]any{
		"requestId": "1", "response": map[string]any{"opcode": 1, "payloadData": payload},
	})
	send("Network.webSocketFrameReceived", map[string]any{
		"requestId": "1", "response": map[string]any{"opcode": 1, "payloadData": "hello"},
	})
	send("Network.webSocketFrameReceived", map[string]any{
		"requestId": "1", "response": map[string]any{"opcode": 2, "payloadData": "AA=="},
	})
	send("Network.webSocketFrameReceived", map[string]any{
		"requestId": "1", "response": map[string]any{"opcode": 1, "payloadData": ""},
	})
	send("Network.webSocketFrameSent", map[string]any{
		"requestId": "1", "response": map[string]any{"opcode": 9, "payloadData": "ping"},
	})
	send("Network.webSocketClosed", map[string]any{"requestId": "1"})

	full := mustOneWS(t, app, id)
	if full.URL != "wss://example.com/ws/ssh?pod=a" || full.Status != 101 || full.Noise {
		t.Fatalf("saved = %+v", full)
	}
	sent := parseWSEnv(t, full.ReqBody)
	if sent.Truncated || len(sent.Frames) != 1 || sent.Frames[0].Op != 1 || sent.Frames[0].Text != payload {
		t.Fatalf("sent = %#v", sent)
	}
	if strings.Contains(full.ReqBody, "ping") {
		t.Fatalf("ping stored in %s", full.ReqBody)
	}
	recv := parseWSEnv(t, full.RespBody)
	if recv.State != "closed" || recv.Truncated || len(recv.Frames) != 3 {
		t.Fatalf("recv = %#v", recv)
	}
	if recv.Frames[0].Text != "hello" || recv.Frames[1].Op != 2 || recv.Frames[1].Bytes != 1 || recv.Frames[2].Op != 1 || recv.Frames[2].Text != "" {
		t.Fatalf("recv frames = %#v", recv.Frames)
	}
	if full.ReqHeaders["Cookie"] != "sid=secret" {
		t.Fatalf("headers = %+v", full.ReqHeaders)
	}
}

func TestRecordWebSocketFlushOnStop(t *testing.T) {
	app, bs, id := newWSRec(t, "ws-open")
	defer app.Shutdown()
	wsSend(bs)("Network.webSocketCreated", map[string]any{"requestId": "9", "url": "wss://example.com/term"})
	got := bs.FinishRecording()
	if got == nil || got.count != 1 || got.useful != 0 {
		t.Fatalf("flush count = %+v", got)
	}
	full := mustOneWS(t, app, id)
	if full.URL != "wss://example.com/term" || full.Status != 0 || !full.Noise || full.NoiseReason != "未完成" {
		t.Fatalf("saved = %+v", full)
	}
	recv := parseWSEnv(t, full.RespBody)
	if recv.State == "open" || strings.Contains(full.RespBody, "101") {
		t.Fatalf("stop invented a handshake: %+v %s", recv, full.RespBody)
	}
}

func TestRecordWebSocketFailedHandshake(t *testing.T) {
	app, bs, id := newWSRec(t, "ws-fail")
	defer app.Shutdown()
	send := wsSend(bs)
	send("Network.webSocketCreated", map[string]any{"requestId": "1", "url": "wss://example.com/term"})
	send("Network.webSocketHandshakeResponseReceived", map[string]any{
		"requestId": "1", "response": map[string]any{"status": 403},
	})
	full := mustOneWS(t, app, id)
	if full.Status != 0 || !full.Noise || full.NoiseReason != "未完成" {
		t.Fatalf("saved = %+v", full)
	}
	recv := parseWSEnv(t, full.RespBody)
	if recv.State != "error" || recv.Error != "HTTP 403" {
		t.Fatalf("recv = %#v", recv)
	}
}

func TestRecordWebSocketIgnoresUnknown(t *testing.T) {
	app, bs, id := newWSRec(t, "ws-unknown")
	defer app.Shutdown()
	send := wsSend(bs)
	send("Network.webSocketFrameSent", map[string]any{
		"requestId": "1", "response": map[string]any{"opcode": 1, "payloadData": "before"},
	})
	send("Network.webSocketFrameError", map[string]any{"requestId": "1", "errorMessage": "late"})
	send("Network.webSocketClosed", map[string]any{"requestId": "1"})
	for i, u := range []string{"", "http://example.com/ws", "chrome://newtab", "devtools://devtools/bundled/inspector.html", "blob:https://example.com/id", "ws://", "wss://"} {
		send("Network.webSocketCreated", map[string]any{"requestId": string(rune('a' + i)), "url": u})
	}
	send("Network.webSocketCreated", map[string]any{"requestId": "2", "url": "wss://example.com/ok"})
	send("Network.webSocketFrameSent", map[string]any{
		"requestId": "2", "response": map[string]any{"opcode": 1, "payloadData": "after"},
	})
	// A frame that arrived before this socket was created is not attached later.
	send("Network.webSocketFrameReceived", map[string]any{
		"requestId": "3", "response": map[string]any{"opcode": 1, "payloadData": "orphan"},
	})
	send("Network.webSocketCreated", map[string]any{"requestId": "3", "url": "wss://example.com/late"})
	if got := bs.FinishRecording(); got == nil || got.count != 2 {
		t.Fatalf("count = %+v", got)
	}
	reqs, err := app.store.ListRequests(id)
	if err != nil || len(reqs) != 2 {
		t.Fatalf("reqs = %+v err=%v", reqs, err)
	}
	for _, q := range reqs {
		full, err := app.store.GetRequest(q.ID)
		if err != nil {
			t.Fatal(err)
		}
		sent := parseWSEnv(t, full.ReqBody)
		recv := parseWSEnv(t, full.RespBody)
		for _, f := range append(append([]wsStoredFrame{}, sent.Frames...), recv.Frames...) {
			if f.Text == "before" || f.Text == "orphan" || strings.Contains(f.Text, "unknown") {
				t.Fatalf("unexpected frame in %s: %#v", full.URL, f)
			}
		}
		if full.URL == "wss://example.com/ok" && (len(sent.Frames) != 1 || sent.Frames[0].Text != "after") {
			t.Fatalf("ok socket = %#v", sent)
		}
		if full.URL == "wss://example.com/late" && (len(sent.Frames)+len(recv.Frames) != 0) {
			t.Fatalf("late socket kept an early frame: %#v %#v", sent, recv)
		}
	}
}

func TestRecordWebSocketTruncation(t *testing.T) {
	app, bs, id := newWSRec(t, "ws-cut")
	defer app.Shutdown()
	send := wsSend(bs)
	send("Network.webSocketCreated", map[string]any{"requestId": "1", "url": "wss://example.com/term"})
	send("Network.webSocketHandshakeResponseReceived", map[string]any{
		"requestId": "1", "response": map[string]any{"status": 101},
	})
	send("Network.webSocketFrameSent", map[string]any{
		"requestId": "1", "response": map[string]any{"opcode": 1, "payloadData": "hello-你好"},
	})
	send("Network.webSocketFrameSent", map[string]any{
		"requestId": "1", "response": map[string]any{"opcode": 1, "payloadData": strings.Repeat("y", maxBody)},
	})
	send("Network.webSocketFrameSent", map[string]any{
		"requestId": "1", "response": map[string]any{"opcode": 1, "payloadData": "after-cut"},
	})
	bs.FinishRecording()
	full := mustOneWS(t, app, id)
	sent := parseWSEnv(t, full.ReqBody)
	if !sent.Truncated || len(sent.Frames) != 1 || sent.Frames[0].Text != "hello-你好" {
		t.Fatalf("sent = %#v", sent)
	}
	if strings.Contains(full.ReqBody, "yyy") || strings.Contains(full.ReqBody, "after-cut") {
		t.Fatalf("partial frame kept: %s", full.ReqBody[:120])
	}
}

func TestRecordWebSocketCoalesce(t *testing.T) {
	app, bs, id := newWSRec(t, "ws-coalesce")
	defer app.Shutdown()
	send := wsSend(bs)
	send("Network.webSocketCreated", map[string]any{"requestId": "1", "url": "wss://example.com/term"})
	send("Network.webSocketHandshakeResponseReceived", map[string]any{
		"requestId": "1", "response": map[string]any{"status": 101},
	})
	send("Network.webSocketFrameSent", map[string]any{
		"requestId": "1", "response": map[string]any{"opcode": 1, "payloadData": "a"},
	})
	send("Network.webSocketFrameSent", map[string]any{
		"requestId": "1", "response": map[string]any{"opcode": 1, "payloadData": "b"},
	})
	reqs, err := app.store.ListRequests(id)
	if err != nil || len(reqs) != 1 {
		t.Fatalf("reqs = %+v err=%v", reqs, err)
	}
	mid, err := app.store.GetRequest(reqs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(parseWSEnv(t, mid.ReqBody).Frames); n != 0 {
		t.Fatalf("frames flushed immediately: %d", n)
	}
	bs.FinishRecording()
	full := mustOneWS(t, app, id)
	sent := parseWSEnv(t, full.ReqBody)
	if len(sent.Frames) != 2 || sent.Frames[0].Text != "a" || sent.Frames[1].Text != "b" {
		t.Fatalf("sent = %#v", sent)
	}
}

func TestRecordWebSocketUsefulFlip(t *testing.T) {
	app, bs, id := newWSRec(t, "ws-flip")
	defer app.Shutdown()
	send := wsSend(bs)
	send("Network.webSocketCreated", map[string]any{"requestId": "1", "url": "wss://example.com/term"})
	send("Network.webSocketWillSendHandshakeRequest", map[string]any{
		"requestId": "1", "request": map[string]any{"headers": map[string]any{}},
	})
	if c, u := bs.RecordingStats(); c != 1 || u != 0 {
		t.Fatalf("before handshake stats = %d %d", c, u)
	}
	send("Network.webSocketHandshakeResponseReceived", map[string]any{
		"requestId": "1", "response": map[string]any{"status": 101},
	})
	if c, u := bs.RecordingStats(); c != 1 || u != 1 {
		t.Fatalf("after handshake stats = %d %d", c, u)
	}
	full := mustOneWS(t, app, id)
	if full.Status != 101 || full.Noise {
		t.Fatalf("saved = %+v", full)
	}
}

func TestRecordWebSocketPersistKeepsPending(t *testing.T) {
	app, bs, _ := newWSRec(t, "ws-db")
	defer app.Shutdown()
	send := wsSend(bs)
	send("Network.webSocketCreated", map[string]any{"requestId": "1", "url": "wss://example.com/term"})
	send("Network.webSocketHandshakeResponseReceived", map[string]any{
		"requestId": "1", "response": map[string]any{"status": 101},
	})
	if err := app.store.db.Close(); err != nil {
		t.Fatal(err)
	}
	send("Network.webSocketClosed", map[string]any{"requestId": "1"})
	bs.mu.Lock()
	pr := bs.rec.pending[key("s", "1")]
	bs.mu.Unlock()
	if pr == nil || pr.wsState != "closed" {
		t.Fatal("failed close dropped the pending socket")
	}
	bs.FinishRecording()
}

func TestWSTruncationKeepsAcceptedFrame(t *testing.T) {
	keepSent := largestWSText(t, true)
	sent := &pendingReq{}
	sent.addWSFrame(true, wsStoredFrame{Op: 1, TS: "00:00:00.000", Text: keepSent})
	sent.addWSFrame(true, wsStoredFrame{Op: 1, TS: "00:00:00.000", Text: strings.Repeat("b", maxBody)})
	fitted, cut := fitWSFrames(sent.wsSent, sent.wsSentCut, "", "")
	if !sent.wsSentCut || !cut || len(fitted) != 1 || fitted[0].Text != keepSent {
		t.Fatalf("sent lost an accepted frame: cut=%v n=%d", cut, len(fitted))
	}

	keepRecv := largestWSText(t, false)
	recv := &pendingReq{wsState: "closed", wsErr: strings.Repeat("\x01", 512)}
	recv.addWSFrame(false, wsStoredFrame{Op: 1, TS: "00:00:00.000", Text: keepRecv})
	recv.addWSFrame(false, wsStoredFrame{Op: 1, TS: "00:00:00.000", Text: strings.Repeat("b", maxBody)})
	fitted, cut = fitWSFrames(recv.wsRecv, recv.wsRecvCut, recv.wsState, recv.wsErr)
	if !recv.wsRecvCut || !cut || len(fitted) != 1 || fitted[0].Text != keepRecv {
		t.Fatalf("recv lost an accepted frame: cut=%v n=%d", cut, len(fitted))
	}
}

func largestWSText(t *testing.T, sent bool) string {
	t.Helper()
	lo, hi, best := 0, maxBody, -1
	for lo <= hi {
		mid := (lo + hi) / 2
		pr := &pendingReq{}
		pr.addWSFrame(sent, wsStoredFrame{Op: 1, TS: "00:00:00.000", Text: strings.Repeat("a", mid)})
		ok := !pr.wsSentCut && !pr.wsRecvCut && len(pr.wsSent)+len(pr.wsRecv) == 1
		if ok {
			best = mid
			lo = mid + 1
		} else {
			hi = mid - 1
		}
	}
	if best <= 0 {
		t.Fatal("no frame fit")
	}
	return strings.Repeat("a", best)
}

func TestWSBinaryLen(t *testing.T) {
	if wsBinaryLen("AA==") != 1 || wsBinaryLen("AAAA") != 3 || wsBinaryLen("AAA") != 2 || wsBinaryLen("@@@@") != 0 || wsBinaryLen("") != 0 {
		t.Fatalf("lens = %d %d %d %d", wsBinaryLen("AA=="), wsBinaryLen("AAAA"), wsBinaryLen("AAA"), wsBinaryLen("@@@@"))
	}
}

func TestRecordedWSNotExecutableTemplate(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(moduleRoot(t), "web", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	if strings.Contains(s, "m.config.ws_messages = frames") || strings.Contains(s, "wsSentText") {
		t.Fatal("recorded frames are still copied into the middleware template")
	}
	for _, want := range []string{`m.config.ws_messages = []`, `id="mw-from-rec"`, "wsTemplateReady", "{{command}}", "******"} {
		if !strings.Contains(s, want) {
			t.Fatalf("app.js missing %s", want)
		}
	}
}

func newWSRec(t *testing.T, name string) (*App, *BrowserSession, int64) {
	t.Helper()
	app, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	id, err := app.store.CreateRecording(name, "https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	bs := &BrowserSession{app: app, rec: &activeRecording{id: id, pending: map[string]*pendingReq{}}}
	return app, bs, id
}

func wsSend(bs *BrowserSession) func(string, any) {
	return func(method string, params any) {
		b, _ := json.Marshal(params)
		bs.handle(cdp.Event{Method: method, SessionID: "s", Params: b})
	}
}

func mustOneWS(t *testing.T, app *App, id int64) *ReqRecord {
	t.Helper()
	reqs, err := app.store.ListRequests(id)
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Method != "WS" {
		t.Fatalf("requests = %+v", reqs)
	}
	full, err := app.store.GetRequest(reqs[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	return full
}

func parseWSEnv(t *testing.T, body string) wsEnvelope {
	t.Helper()
	var env wsEnvelope
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("envelope: %v body=%s", err, body)
	}
	if env.V != 1 {
		t.Fatalf("v = %d", env.V)
	}
	return env
}
