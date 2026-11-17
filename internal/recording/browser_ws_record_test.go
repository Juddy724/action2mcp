package recording

import (
	"action2mcp/internal/cdp"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestRecordWebSocketPersistKeepsPending(t *testing.T) {
	repo := &captureFailRepository{}
	bs := New(repo, Hooks{})
	bs.Start(1, "ws-db")
	send := func(method string, params any) {
		b, _ := json.Marshal(params)
		bs.HandleEvent(cdp.Event{Method: method, SessionID: "s", Params: b})
	}
	send("Network.webSocketCreated", map[string]any{"requestId": "1", "url": "wss://example.com/term"})
	send("Network.webSocketHandshakeResponseReceived", map[string]any{"requestId": "1", "response": map[string]any{"status": 101}})
	repo.closed = true
	send("Network.webSocketClosed", map[string]any{"requestId": "1"})
	bs.mu.Lock()
	pr := bs.rec.pending[key("s", "1")]
	bs.mu.Unlock()
	if pr == nil || pr.wsState != "closed" {
		t.Fatal("failed close dropped the pending socket")
	}
	bs.FinishRecording()
}

type captureFailRepository struct{ closed bool }

func (r *captureFailRepository) InsertRequest(q *Request) error {
	if r.closed {
		return fmt.Errorf("fixture persistence unavailable")
	}
	q.ID = 1
	return nil
}

func (r *captureFailRepository) UpdateRequest(*Request) error {
	if r.closed {
		return fmt.Errorf("fixture persistence unavailable")
	}
	return nil
}

func TestWSTruncationKeepsAcceptedFrame(t *testing.T) {
	keepSent := largestWSText(t, true)
	sent := &pendingReq{}
	sent.addWSFrame(true, Frame{Op: 1, TS: "00:00:00.000", Text: keepSent})
	sent.addWSFrame(true, Frame{Op: 1, TS: "00:00:00.000", Text: strings.Repeat("b", MaxBody)})
	fitted, cut := fitWSFrames(sent.wsSent, sent.wsSentCut, "", "")
	if !sent.wsSentCut || !cut || len(fitted) != 1 || fitted[0].Text != keepSent {
		t.Fatalf("sent lost an accepted frame: cut=%v n=%d", cut, len(fitted))
	}

	keepRecv := largestWSText(t, false)
	recv := &pendingReq{wsState: "closed", wsErr: strings.Repeat("\x01", 512)}
	recv.addWSFrame(false, Frame{Op: 1, TS: "00:00:00.000", Text: keepRecv})
	recv.addWSFrame(false, Frame{Op: 1, TS: "00:00:00.000", Text: strings.Repeat("b", MaxBody)})
	fitted, cut = fitWSFrames(recv.wsRecv, recv.wsRecvCut, recv.wsState, recv.wsErr)
	if !recv.wsRecvCut || !cut || len(fitted) != 1 || fitted[0].Text != keepRecv {
		t.Fatalf("recv lost an accepted frame: cut=%v n=%d", cut, len(fitted))
	}
}

func largestWSText(t *testing.T, sent bool) string {
	t.Helper()
	lo, hi, best := 0, MaxBody, -1
	for lo <= hi {
		mid := (lo + hi) / 2
		pr := &pendingReq{}
		pr.addWSFrame(sent, Frame{Op: 1, TS: "00:00:00.000", Text: strings.Repeat("a", mid)})
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
