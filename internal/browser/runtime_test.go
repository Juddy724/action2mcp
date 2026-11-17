package browser

import (
	"action2mcp/internal/cdp"
	"action2mcp/internal/recording"
	sitecfg "action2mcp/internal/site"
	"context"
	"encoding/json"
	"github.com/gorilla/websocket"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type wireCall struct {
	ID      int64           `json:"id"`
	Method  string          `json:"method"`
	Session string          `json:"sessionId"`
	Params  json.RawMessage `json:"params"`
}

// Real CDP framing over a loopback-only fake peer; never starts a browser.
func protocolSession(t *testing.T, cookies []Cookie) (*Session, func() []wireCall) {
	t.Helper()
	var mu sync.Mutex
	var calls []wireCall
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()
		for {
			var req wireCall
			if c.ReadJSON(&req) != nil {
				return
			}
			mu.Lock()
			calls = append(calls, req)
			mu.Unlock()
			var result any = map[string]any{}
			switch req.Method {
			case "Target.createTarget":
				result = map[string]any{"targetId": "owned-target"}
			case "Target.attachToTarget":
				result = map[string]any{"sessionId": "owned-session"}
			case "Storage.getCookies":
				result = map[string]any{"cookies": cookies}
			}
			if c.WriteJSON(map[string]any{"id": req.ID, "result": result}) != nil {
				return
			}
		}
	}))
	t.Cleanup(server.Close)
	conn, err := cdp.Dial(context.Background(), "ws"+strings.TrimPrefix(server.URL, "http"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return &Session{conn: conn, closed: make(chan struct{})}, func() []wireCall { mu.Lock(); defer mu.Unlock(); return append([]wireCall(nil), calls...) }
}
func TestOwnedTabUsesPrivateSessionAndIgnoreSet(t *testing.T) {
	bs, calls := protocolSession(t, nil)
	tab, err := bs.OpenTab("https://app.example.test/login", true)
	if err != nil {
		t.Fatal(err)
	}
	if !bs.ignore["owned-target"] {
		t.Fatal("internal login target can leak into recording")
	}
	if err := tab.Navigate("https://app.example.test/next"); err != nil {
		t.Fatal(err)
	}
	if err := tab.Reload(); err != nil {
		t.Fatal(err)
	}
	tab.Close()
	got := calls()
	want := []string{"Target.createTarget", "Target.attachToTarget", "Runtime.runIfWaitingForDebugger", "Page.navigate", "Page.navigate", "Page.reload", "Target.closeTarget"}
	if len(got) != len(want) {
		t.Fatalf("calls: %+v", got)
	}
	for i, w := range want {
		if got[i].Method != w {
			t.Errorf("call %d = %s, want %s", i, got[i].Method, w)
		}
		if i >= 2 && i <= 5 && got[i].Session != "owned-session" {
			t.Errorf("page operation escaped its session: %+v", got[i])
		}
	}
}
func TestCookieWirePolicyPreservesHostDomainAndExpiry(t *testing.T) {
	bs, calls := protocolSession(t, nil)
	err := bs.SetCookies([]Cookie{{Name: "host", Value: "v", Domain: "app.example.test", Secure: true, Session: true}, {Name: "domain", Value: "v", Domain: ".example.test", Path: "/api", Expires: float64(time.Now().Add(time.Hour).Unix())}, {Name: "expired", Domain: "app.example.test", Expires: 1}})
	if err != nil {
		t.Fatal(err)
	}
	got := calls()
	if len(got) != 1 || got[0].Method != "Storage.setCookies" {
		t.Fatalf("calls: %+v", got)
	}
	var p struct {
		Cookies []map[string]any `json:"cookies"`
	}
	if err := json.Unmarshal(got[0].Params, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Cookies) != 2 {
		t.Fatalf("expired cookie forwarded: %+v", p)
	}
	if p.Cookies[0]["url"] != "https://app.example.test/" || p.Cookies[0]["domain"] != nil || p.Cookies[0]["expires"] != nil {
		t.Fatalf("host/session semantics: %+v", p.Cookies[0])
	}
	if p.Cookies[1]["domain"] != ".example.test" || p.Cookies[1]["url"] != nil || p.Cookies[1]["expires"] == nil {
		t.Fatalf("domain semantics: %+v", p.Cookies[1])
	}
}
func TestLaunchReadsCurrentNarrowConfiguration(t *testing.T) {
	root := t.TempDir()
	selected := filepath.Join(root, "missing-one")
	reads := 0
	m := New(Options{ProfileDir: filepath.Join(root, "profile"), Config: func() LaunchConfig { reads++; return LaunchConfig{BrowserPath: selected} }})
	for _, name := range []string{"missing-one", "missing-two"} {
		selected = filepath.Join(root, name)
		if _, err := m.Launch(true); err == nil {
			t.Fatal("missing browser accepted")
		}
	}
	if reads != 2 {
		t.Fatalf("configuration was frozen at composition: %d", reads)
	}
	if _, err := os.Stat(filepath.Join(root, "profile")); !os.IsNotExist(err) {
		t.Fatalf("failed discovery touched profile: %v", err)
	}
}
func TestManagerLeasesAndStopSnapshotsStayEncapsulated(t *testing.T) {
	bs := &Session{closed: make(chan struct{})}
	m := New(Options{})
	m.browser = bs
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			leased, err := m.AcquireBrowser()
			if err != nil || leased != bs {
				t.Errorf("unexpected lease %p %v", leased, err)
				return
			}
			m.ReleaseBrowser(leased)
		}()
	}
	wg.Wait()
	if bs.users != 0 {
		t.Fatalf("unbalanced leases: %d", bs.users)
	}
	m.browser = nil
	m.lastStop = &StopInfo{Name: "original", LoginDetection: &RecordingLoginResult{Action: "unchanged"}}
	snap := m.Snapshot()
	snap.LastStop.Name = "mutation"
	snap.LastStop.LoginDetection.Action = "mutation"
	stopped, err := m.StopRecording("command")
	if err == nil || stopped.Name != "original" || stopped.LoginDetection.Action != "unchanged" {
		t.Fatalf("snapshot escaped state: %+v %v", stopped, err)
	}
	stopped.Name = "second mutation"
	if m.Snapshot().LastStop.Name != "original" {
		t.Fatal("stop response escaped state")
	}
	if got, _ := m.StopRecording("overlay"); got != nil {
		t.Fatal("overlay must not replay prior stop")
	}
}

func TestSessionRoutesCaptureIgnoresOwnedTabsAndStopsFromOverlay(t *testing.T) {
	st := testRecordingStore(t)
	defer st.db.Close()
	id, err := st.CreateRecording("runtime seam", "https://app.example.test/")
	if err != nil {
		t.Fatal(err)
	}
	m := New(Options{Repository: st, Capture: st, DetectRecordingLogin: sitecfg.NewRecordingDetector(st).Detect})
	closed := make(chan struct{})
	close(closed)
	bs := &Session{owner: m, closed: closed, headless: true, pages: map[string]string{"page": "user-target", "internal": "owned-target"}, ignore: map[string]bool{"owned-target": true}, scripts: map[string]string{"internal": "owned-script"}}
	bs.capture = m.newCapture(bs)
	bs.capture.Start(id, "runtime seam")
	m.browser = bs
	m.recID = id
	m.recName = "runtime seam"
	send := func(session, method string, params any) {
		raw, err := json.Marshal(params)
		if err != nil {
			t.Fatal(err)
		}
		bs.handle(cdp.Event{SessionID: session, Method: method, Params: raw})
	}
	for _, session := range []string{"page", "internal"} {
		send(session, "Network.webSocketCreated", map[string]any{"requestId": "same-id", "url": "wss://app.example.test/socket"})
		send(session, "Network.webSocketFrameSent", map[string]any{"requestId": "same-id", "response": map[string]any{"opcode": 1, "payloadData": "hello"}})
	}
	send("", "Target.detachedFromTarget", map[string]any{"sessionId": "internal"})
	if _, exists := bs.pages["internal"]; exists {
		t.Fatal("detached page retained")
	}
	if _, exists := bs.scripts["internal"]; exists {
		t.Fatal("detached overlay retained")
	}
	send("page", "Runtime.bindingCalled", map[string]any{"name": "unrelated"})
	if !m.Snapshot().Recording {
		t.Fatal("unrelated binding stopped recording")
	}
	send("page", "Runtime.bindingCalled", map[string]any{"name": bindingName})
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for m.Snapshot().LastStop == nil {
		select {
		case <-deadline.C:
			t.Fatal("overlay stop did not finish")
		case <-tick.C:
		}
	}
	snap := m.Snapshot()
	if snap.Recording || snap.LastStop.Reason != "overlay" || snap.LastStop.Count != 1 {
		t.Fatalf("stop state: %+v", snap)
	}
	rows, err := st.ListRequests(id)
	if err != nil || len(rows) != 1 {
		t.Fatalf("capture ignored/flush policy: %d %v", len(rows), err)
	}
	full, err := st.GetRequest(rows[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if full.ResourceType != "WebSocket" || !strings.Contains(full.ReqBody, "hello") {
		t.Fatalf("pending capture did not flush: %+v", full)
	}
	var _ recording.Repository = st
}
