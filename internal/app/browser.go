package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"action2mcp/internal/cdp"
)

// FindBrowser locates an installed Chrome / Edge / Chromium.
func FindBrowser(override string) (string, error) {
	if override != "" {
		if _, err := os.Stat(override); err == nil {
			return override, nil
		}
		if p, err := exec.LookPath(override); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("配置的浏览器路径不存在: %s", override)
	}
	var cands []string
	switch runtime.GOOS {
	case "windows":
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData"} {
			base := os.Getenv(env)
			if base == "" {
				continue
			}
			cands = append(cands,
				filepath.Join(base, `Google\Chrome\Application\chrome.exe`),
				filepath.Join(base, `Microsoft\Edge\Application\msedge.exe`),
				filepath.Join(base, `Chromium\Application\chrome.exe`),
				filepath.Join(base, `BraveSoftware\Brave-Browser\Application\brave.exe`),
			)
		}
	case "darwin":
		home, _ := os.UserHomeDir()
		for _, base := range []string{"/Applications", filepath.Join(home, "Applications")} {
			cands = append(cands,
				filepath.Join(base, "Google Chrome.app/Contents/MacOS/Google Chrome"),
				filepath.Join(base, "Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
				filepath.Join(base, "Chromium.app/Contents/MacOS/Chromium"),
				filepath.Join(base, "Brave Browser.app/Contents/MacOS/Brave Browser"),
				filepath.Join(base, "Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary"),
			)
		}
	default:
		for _, n := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "microsoft-edge-stable", "brave-browser"} {
			if p, err := exec.LookPath(n); err == nil {
				cands = append(cands, p)
			}
		}
		cands = append(cands, "/usr/bin/google-chrome", "/snap/bin/chromium", "/opt/google/chrome/chrome")
	}
	for _, c := range cands {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c, nil
		}
	}
	return "", errors.New("没有找到 Chrome / Edge 浏览器，请先安装 Chrome，或在 data/config.json 里设置 \"browser\" 为浏览器路径")
}

// BrowserSession is one running instance of the dedicated browser profile.
type BrowserSession struct {
	app      *App
	cmd      *exec.Cmd
	conn     *cdp.Conn
	headless bool

	mu      sync.Mutex
	pages   map[string]string // sessionId -> targetId
	rec     *activeRecording
	closed  chan struct{}
	scripts map[string]string // sessionId -> script identifier for overlay
	firstPg chan string

	syncPending atomic.Bool

	ignore map[string]bool // targetIds opened by Action2MCP itself (not recorded)
	users  int             // active background users (guarded by App.mu)
}

type activeRecording struct {
	id      int64
	name    string
	seq     int
	pending map[string]*pendingReq // key sessionId|requestId
	wg      sync.WaitGroup
	count   int
	useful  int
	stopped bool
}

type pendingReq struct {
	rec      *ReqRecord
	hasPost  bool
	ws       bool
	session  string
	reqID    string
	extraHdr map[string]string

	wsSent     []wsStoredFrame
	wsRecv     []wsStoredFrame
	wsState    string
	wsErr      string
	wsSentCut  bool
	wsRecvCut  bool
	wsFlush    time.Time
	wsNoise    bool
	wsInserted bool
}

type wsStoredFrame struct {
	TS    string `json:"ts"`
	Op    int    `json:"op"`
	Text  string `json:"text,omitempty"`
	Bytes int    `json:"bytes,omitempty"`
}

type wsEnvelope struct {
	V         int             `json:"v"`
	State     string          `json:"state,omitempty"`
	Error     string          `json:"error,omitempty"`
	Truncated bool            `json:"truncated,omitempty"`
	Frames    []wsStoredFrame `json:"frames"`
}

func (a *App) profileDir() string { return filepath.Join(a.dataDir, "browser-profile") }

// LaunchBrowser starts the browser with the dedicated profile and connects via CDP.
func (a *App) LaunchBrowser(headless bool) (*BrowserSession, error) {
	bin, err := FindBrowser(a.cfg.Browser)
	if err != nil {
		return nil, err
	}
	prof := a.profileDir()
	os.MkdirAll(prof, 0o755)
	portFile := filepath.Join(prof, "DevToolsActivePort")
	os.Remove(portFile)
	// never restore old tabs from a previous run: recording should start from a clean window
	for _, d := range []string{"Sessions", "Sessions_Encrypted", "Current Session", "Current Tabs", "Last Session", "Last Tabs"} {
		os.RemoveAll(filepath.Join(prof, "Default", d))
	}
	args := []string{
		"--remote-debugging-port=0",
		"--user-data-dir=" + prof,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		"--disable-sync",
		"--password-store=basic",
		"--disable-features=Translate,OptimizationHints,MediaRouter",
		"--hide-crash-restore-bubble",
	}
	if headless {
		args = append(args, "--headless=new", "--disable-gpu")
	} else {
		args = append(args, "--new-window", "--window-size=1280,860")
	}
	if a.cfg.NoSandbox || (runtime.GOOS == "linux" && os.Geteuid() == 0) {
		args = append(args, "--no-sandbox")
	}
	args = append(args, a.cfg.BrowserArgs...)
	args = append(args, "about:blank")
	cmd := exec.Command(bin, args...)
	cmd.Stdout = nil
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("启动浏览器失败: %v", err)
	}
	exited := make(chan struct{})
	go func() { cmd.Wait(); close(exited) }()
	var wsURL string
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(portFile); err == nil {
			lines := strings.Split(strings.TrimSpace(string(b)), "\n")
			if len(lines) >= 2 {
				wsURL = "ws://127.0.0.1:" + strings.TrimSpace(lines[0]) + strings.TrimSpace(lines[1])
				break
			}
		}
		select {
		case <-exited:
			return nil, errors.New("浏览器启动后立即退出。可能是专用浏览器窗口已经打开（请先关闭它），或浏览器无法启动")
		case <-time.After(150 * time.Millisecond):
		}
	}
	if wsURL == "" {
		cmd.Process.Kill()
		return nil, errors.New("等待浏览器调试端口超时")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := cdp.Dial(ctx, wsURL)
	if err != nil {
		cmd.Process.Kill()
		return nil, fmt.Errorf("连接浏览器失败: %v", err)
	}
	bs := &BrowserSession{app: a, cmd: cmd, conn: conn, headless: headless, pages: map[string]string{}, closed: make(chan struct{}), scripts: map[string]string{}, firstPg: make(chan string, 1)}
	go bs.loop(exited)
	if !headless {
		err = conn.Call(ctx, "", "Target.setAutoAttach", map[string]any{"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}, nil)
		if err != nil {
			bs.Close()
			return nil, err
		}
	}
	a.restoreCookies(bs)
	return bs, nil
}

func (bs *BrowserSession) Closed() <-chan struct{} { return bs.closed }

func (bs *BrowserSession) loop(exited chan struct{}) {
	go func() {
		select {
		case <-exited:
			bs.conn.Close()
		case <-bs.conn.Done():
		}
	}()
	for ev := range bs.conn.Events() {
		bs.handle(ev)
	}
	// connection gone: browser closed
	bs.app.onBrowserClosed(bs)
	close(bs.closed)
}

func (bs *BrowserSession) call(session, method string, params any, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return bs.conn.Call(ctx, session, method, params, out)
}

const bindingName = "__a2mStop"

func overlayScript(name string) string {
	n, _ := json.Marshal(name)
	return `(function(){try{
if (window.top !== window) return;
window.__a2mName = ` + string(n) + `;
window.__a2mStopped = false;
if (window.__a2mOverlayInstalled) { if (window.__a2mOverlayShow) window.__a2mOverlayShow(); return; }
window.__a2mOverlayInstalled = true;
function mount(){
  if (window.__a2mStopped || document.getElementById('__a2m_overlay')) return;
  var host = document.createElement('div');
  host.id='__a2m_overlay';
  host.style.cssText='position:fixed;right:18px;bottom:18px;z-index:2147483647;';
  var root = host.attachShadow ? host.attachShadow({mode:'open'}) : host;
  root.innerHTML = '<style>.b{font:13px/1.4 -apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:#1f2328;color:#fff;border-radius:22px;padding:8px 8px 8px 14px;display:flex;align-items:center;gap:10px;box-shadow:0 6px 24px rgba(0,0,0,.28);user-select:none}.d{color:#ff4d4f;animation:p 1.2s infinite}@keyframes p{50%{opacity:.3}}button{all:unset;cursor:pointer;background:#ff4d4f;color:#fff;border-radius:16px;padding:5px 12px;font-weight:600}button:hover{background:#e03b3d}.n{max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;opacity:.85}</style>'+
   '<div class="b"><span class="d">●</span><span>录制中</span><span class="n"></span><button id="stop" title="结束录制并保存">结束录制</button></div>';
  root.querySelector('.n').textContent = window.__a2mName || '';
  root.querySelector('#stop').addEventListener('click', function(e){
    e.preventDefault(); e.stopPropagation();
    var b = root.querySelector('.b'); b.innerHTML='<span>✓ 已结束录制，正在保存…</span>'; window.__a2mStopped = true;
    try { window.` + bindingName + `('stop'); } catch(err) {}
  }, true);
  (document.body || document.documentElement).appendChild(host);
}
window.__a2mOverlayShow = mount;
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', mount); else mount();
setInterval(function(){ if (!document.getElementById('__a2m_overlay') && (document.body||document.documentElement)) mount(); }, 1500);
}catch(e){}})();`
}

func (bs *BrowserSession) setupPage(session string) {
	bs.mu.Lock()
	rec := bs.rec
	bs.mu.Unlock()
	bs.call(session, "Network.enable", map[string]any{"maxPostDataSize": 262144}, nil)
	if !bs.headless {
		bs.call(session, "Page.enable", nil, nil)
		bs.call(session, "Runtime.enable", nil, nil)
		bs.call(session, "Runtime.addBinding", map[string]any{"name": bindingName}, nil)
		if rec != nil {
			bs.installOverlay(session, rec.name)
		}
	}
	bs.call(session, "Runtime.runIfWaitingForDebugger", nil, nil)
}

func (bs *BrowserSession) installOverlay(session, name string) {
	var res struct {
		Identifier string `json:"identifier"`
	}
	if err := bs.call(session, "Page.addScriptToEvaluateOnNewDocument", map[string]any{"source": overlayScript(name)}, &res); err == nil {
		bs.mu.Lock()
		bs.scripts[session] = res.Identifier
		bs.mu.Unlock()
	}
	bs.call(session, "Runtime.evaluate", map[string]any{"expression": overlayScript(name)}, nil)
}

func (bs *BrowserSession) removeOverlays() {
	bs.mu.Lock()
	scripts := bs.scripts
	bs.scripts = map[string]string{}
	bs.mu.Unlock()
	for s, id := range scripts {
		bs.call(s, "Page.removeScriptToEvaluateOnNewDocument", map[string]any{"identifier": id}, nil)
		bs.call(s, "Runtime.evaluate", map[string]any{"expression": `(function(){var e=document.getElementById('__a2m_overlay'); if(e) e.remove(); window.__a2mStopped=true;})()`}, nil)
	}
}

func (bs *BrowserSession) handle(ev cdp.Event) {
	switch ev.Method {
	case "Target.attachedToTarget":
		var p struct {
			SessionID  string `json:"sessionId"`
			TargetInfo struct {
				TargetID string `json:"targetId"`
				Type     string `json:"type"`
			} `json:"targetInfo"`
		}
		json.Unmarshal(ev.Params, &p)
		if p.TargetInfo.Type == "page" {
			bs.mu.Lock()
			bs.pages[p.SessionID] = p.TargetInfo.TargetID
			bs.mu.Unlock()
			go func() {
				bs.setupPage(p.SessionID)
				select {
				case bs.firstPg <- p.SessionID:
				default:
				}
			}()
		} else {
			go bs.call(p.SessionID, "Runtime.runIfWaitingForDebugger", nil, nil)
		}
	case "Target.detachedFromTarget":
		var p struct {
			SessionID string `json:"sessionId"`
		}
		json.Unmarshal(ev.Params, &p)
		bs.mu.Lock()
		delete(bs.pages, p.SessionID)
		delete(bs.scripts, p.SessionID)
		n := len(bs.pages)
		bs.mu.Unlock()
		if n == 0 && !bs.headless {
			// last window closed -> treat as browser closed
			go func() {
				time.Sleep(800 * time.Millisecond)
				bs.mu.Lock()
				n := len(bs.pages)
				bs.mu.Unlock()
				if n == 0 {
					// snapshot the login state before the browser goes away (session cookies are not kept on disk reliably)
					cs, err := bs.Cookies()
					if err == nil && len(cs) > 0 {
						bs.app.store.ReplaceCookies(cs)
					}
					debugf("cookie snapshot on last window close: %d cookies err=%v", len(cs), err)
					bs.call("", "Browser.close", nil, nil)
				}
			}()
		}
	case "Runtime.bindingCalled":
		var p struct {
			Name string `json:"name"`
		}
		json.Unmarshal(ev.Params, &p)
		if p.Name == bindingName {
			go bs.app.StopRecording("overlay")
		}
	case "Network.requestWillBeSent":
		bs.onRequest(ev)
	case "Network.responseReceivedExtraInfo":
		if !bs.headless && bytes.Contains(bytes.ToLower(ev.Params), []byte("set-cookie")) {
			bs.scheduleCookieSync()
		}
	case "Network.requestWillBeSentExtraInfo":
		bs.onExtraInfo(ev)
	case "Network.responseReceived":
		bs.onResponse(ev)
	case "Network.loadingFinished":
		bs.onFinished(ev, false)
	case "Network.loadingFailed":
		bs.onFinished(ev, true)
	case "Network.webSocketCreated":
		bs.onWSCreated(ev)
	case "Network.webSocketWillSendHandshakeRequest":
		bs.onWSHandshake(ev)
	case "Network.webSocketHandshakeResponseReceived":
		bs.onWSHandshakeResponse(ev)
	case "Network.webSocketFrameSent":
		bs.onWSFrame(ev, true)
	case "Network.webSocketFrameReceived":
		bs.onWSFrame(ev, false)
	case "Network.webSocketClosed":
		bs.onWSClosed(ev)
	case "Network.webSocketFrameError":
		bs.onWSError(ev)
	}
}

// WebSocket is recorded from Network.webSocket* events, not as this HTTP upgrade request.
var recordTypes = map[string]bool{"XHR": true, "Fetch": true, "Document": true, "Ping": true, "Other": true, "EventSource": true, "Script": true, "Stylesheet": true, "Image": true, "Font": true}
var bodyTypes = map[string]bool{"XHR": true, "Fetch": true, "Document": true, "Other": true, "EventSource": true}

const maxBody = 256 * 1024

func key(s, r string) string { return s + "|" + r }

func (bs *BrowserSession) onRequest(ev cdp.Event) {
	var p struct {
		RequestID string `json:"requestId"`
		Type      string `json:"type"`
		Request   struct {
			URL             string         `json:"url"`
			Method          string         `json:"method"`
			Headers         map[string]any `json:"headers"`
			PostData        string         `json:"postData"`
			HasPostData     bool           `json:"hasPostData"`
			PostDataEntries []struct {
				Bytes string `json:"bytes"`
			} `json:"postDataEntries"`
		} `json:"request"`
		RedirectResponse *struct {
			Status int `json:"status"`
		} `json:"redirectResponse"`
	}
	json.Unmarshal(ev.Params, &p)
	hdrEarly := map[string]string{}
	for hk, hv := range p.Request.Headers {
		hdrEarly[hk] = fmt.Sprint(hv)
	}
	if p.Request.URL != "" && !strings.HasPrefix(p.Request.URL, "data:") && !strings.HasPrefix(p.Request.URL, "chrome") {
		rk := key(ev.SessionID, p.RequestID)
		bs.app.TrackHarvestHop(rk, p.Request.URL)
		for hk, hv := range hdrEarly {
			_ = bs.app.HarvestRequestHeader(rk, p.Request.URL, hk, hv)
		}
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	rec := bs.rec
	if rec == nil || rec.stopped {
		return
	}
	if bs.ignore[bs.pages[ev.SessionID]] {
		return
	}
	if strings.HasPrefix(p.Request.URL, "data:") || strings.HasPrefix(p.Request.URL, "chrome") || strings.HasPrefix(p.Request.URL, "devtools:") || strings.HasPrefix(p.Request.URL, "blob:") {
		return
	}
	if !recordTypes[p.Type] && p.Type != "" {
		return
	}
	k := key(ev.SessionID, p.RequestID)
	if old, ok := rec.pending[k]; ok && p.RedirectResponse != nil {
		// redirect: finalize previous hop
		old.rec.Status = p.RedirectResponse.Status
		bs.storeLocked(rec, old)
		delete(rec.pending, k)
	}
	body := p.Request.PostData
	if body == "" && len(p.Request.PostDataEntries) > 0 {
		var sb strings.Builder
		for _, e := range p.Request.PostDataEntries {
			if b, err := base64.StdEncoding.DecodeString(e.Bytes); err == nil {
				sb.Write(b)
			}
		}
		body = sb.String()
	}
	hdr := map[string]string{}
	for k, v := range p.Request.Headers {
		hdr[k] = fmt.Sprint(v)
	}
	rec.seq++
	pr := &pendingReq{session: ev.SessionID, reqID: p.RequestID, hasPost: p.Request.HasPostData && body == "", rec: &ReqRecord{
		RecordingID: rec.id, Seq: rec.seq, Method: p.Request.Method, URL: p.Request.URL, ResourceType: p.Type,
		ReqHeaders: hdr, ReqBody: truncate(body, maxBody), TS: time.Now().Format("15:04:05.000"),
	}}
	rec.pending[k] = pr
}

func (bs *BrowserSession) onExtraInfo(ev cdp.Event) {
	var p struct {
		RequestID string         `json:"requestId"`
		Headers   map[string]any `json:"headers"`
	}
	json.Unmarshal(ev.Params, &p)
	rk := key(ev.SessionID, p.RequestID)
	for hk, hv := range p.Headers {
		if strings.HasPrefix(hk, ":") {
			continue
		}
		_ = bs.app.HarvestRequestHeader(rk, "", hk, fmt.Sprint(hv))
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.rec == nil {
		return
	}
	if pr, ok := bs.rec.pending[rk]; ok {
		for k, v := range p.Headers {
			if strings.HasPrefix(k, ":") {
				continue
			}
			pr.rec.ReqHeaders[k] = fmt.Sprint(v)
		}
	}
}

func (bs *BrowserSession) onResponse(ev cdp.Event) {
	var p struct {
		RequestID string `json:"requestId"`
		Type      string `json:"type"`
		Response  struct {
			Status   int            `json:"status"`
			Headers  map[string]any `json:"headers"`
			MimeType string         `json:"mimeType"`
		} `json:"response"`
	}
	json.Unmarshal(ev.Params, &p)
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.rec == nil {
		return
	}
	if pr, ok := bs.rec.pending[key(ev.SessionID, p.RequestID)]; ok {
		pr.rec.Status = p.Response.Status
		pr.rec.RespMime = p.Response.MimeType
		h := map[string]string{}
		for k, v := range p.Response.Headers {
			h[k] = fmt.Sprint(v)
		}
		pr.rec.RespHeaders = h
		if p.Type != "" {
			pr.rec.ResourceType = p.Type
		}
	}
}

func (bs *BrowserSession) onFinished(ev cdp.Event, failed bool) {
	var p struct {
		RequestID string `json:"requestId"`
		ErrorText string `json:"errorText"`
	}
	json.Unmarshal(ev.Params, &p)
	bs.mu.Lock()
	rec := bs.rec
	if rec == nil {
		bs.mu.Unlock()
		return
	}
	k := key(ev.SessionID, p.RequestID)
	pr, ok := rec.pending[k]
	if !ok {
		bs.mu.Unlock()
		return
	}
	delete(rec.pending, k)
	rec.wg.Add(1)
	bs.mu.Unlock()
	go func() {
		defer rec.wg.Done()
		if failed {
			if pr.rec.RespBody == "" {
				pr.rec.RespBody = "[请求失败] " + p.ErrorText
			}
		} else {
			if pr.hasPost {
				var r struct {
					PostData string `json:"postData"`
				}
				if bs.call(pr.session, "Network.getRequestPostData", map[string]any{"requestId": pr.reqID}, &r) == nil {
					pr.rec.ReqBody = truncate(r.PostData, maxBody)
				}
			}
			if bodyTypes[pr.rec.ResourceType] && pr.rec.Method != "OPTIONS" {
				var r struct {
					Body          string `json:"body"`
					Base64Encoded bool   `json:"base64Encoded"`
				}
				if bs.call(pr.session, "Network.getResponseBody", map[string]any{"requestId": pr.reqID}, &r) == nil {
					if r.Base64Encoded {
						if b, err := base64.StdEncoding.DecodeString(r.Body); err == nil && isText(pr.rec.RespMime) {
							pr.rec.RespBody = truncate(string(b), maxBody)
						} else {
							pr.rec.RespBody = fmt.Sprintf("[二进制内容 %d 字节]", len(r.Body)*3/4)
						}
					} else {
						pr.rec.RespBody = truncate(r.Body, maxBody)
					}
				}
			}
		}
		bs.mu.Lock()
		bs.storeLocked(rec, pr)
		bs.mu.Unlock()
	}()
}

func isText(m string) bool {
	return strings.HasPrefix(m, "text/") || strings.Contains(m, "json") || strings.Contains(m, "xml") || strings.Contains(m, "javascript")
}

func (bs *BrowserSession) storeLocked(rec *activeRecording, pr *pendingReq) {
	pr.rec.Noise, pr.rec.NoiseReason = bs.app.classifyRecorded(pr.rec)
	if err := bs.app.store.InsertRequest(pr.rec); err != nil {
		log.Printf("保存请求失败: %v", err)
		return
	}
	rec.count++
	if !pr.rec.Noise {
		rec.useful++
	}
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "\n…[已截断]"
	}
	return s
}

// A WebSocket connection is one recording row. Frames stay in memory as JSON
// envelopes and are flushed on a short interval. The recording page renders them;
// saving a middleware copies the URL only, never these frames.
func (bs *BrowserSession) onWSCreated(ev cdp.Event) {
	var p struct {
		RequestID string `json:"requestId"`
		URL       string `json:"url"`
	}
	json.Unmarshal(ev.Params, &p)
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.wsPending(ev.SessionID, p.RequestID, p.URL, true)
}

func (bs *BrowserSession) onWSHandshake(ev cdp.Event) {
	var p struct {
		RequestID string `json:"requestId"`
		Request   struct {
			Headers map[string]any `json:"headers"`
		} `json:"request"`
	}
	json.Unmarshal(ev.Params, &p)
	bs.mu.Lock()
	defer bs.mu.Unlock()
	rec := bs.rec
	pr := bs.wsPending(ev.SessionID, p.RequestID, "", false)
	if pr == nil || rec == nil {
		return
	}
	for k, v := range p.Request.Headers {
		if strings.HasPrefix(k, ":") {
			continue
		}
		pr.rec.ReqHeaders[k] = fmt.Sprint(v)
	}
	rk := key(ev.SessionID, p.RequestID)
	if pr.rec.URL != "" {
		bs.app.TrackHarvestHop(rk, pr.rec.URL)
		for k, v := range pr.rec.ReqHeaders {
			_ = bs.app.HarvestRequestHeader(rk, pr.rec.URL, k, v)
		}
	}
	if err := bs.persistWSLocked(rec, pr, true); err != nil {
		log.Printf("保存 WebSocket 握手失败: %v", err)
	}
}

func (bs *BrowserSession) onWSHandshakeResponse(ev cdp.Event) {
	var p struct {
		RequestID string `json:"requestId"`
		Response  struct {
			Status  int            `json:"status"`
			Headers map[string]any `json:"headers"`
		} `json:"response"`
	}
	json.Unmarshal(ev.Params, &p)
	bs.mu.Lock()
	defer bs.mu.Unlock()
	rec := bs.rec
	pr := bs.wsPending(ev.SessionID, p.RequestID, "", false)
	if pr == nil || rec == nil {
		return
	}
	// Status is 101 only when the handshake succeeded. A missing or failed
	// handshake stays 0 so it is classified as 未完成. The HTTP code is kept
	// on the receive envelope.
	for k, v := range p.Response.Headers {
		pr.rec.RespHeaders[k] = fmt.Sprint(v)
	}
	if p.Response.Status == 101 {
		pr.rec.Status = 101
		pr.wsState = "open"
	} else if p.Response.Status != 0 {
		pr.wsState = "error"
		if pr.wsErr == "" {
			pr.wsErr = fmt.Sprintf("HTTP %d", p.Response.Status)
		}
	}
	if err := bs.persistWSLocked(rec, pr, true); err != nil {
		log.Printf("保存 WebSocket 握手失败: %v", err)
	}
}

func (bs *BrowserSession) onWSFrame(ev cdp.Event, sent bool) {
	var p struct {
		RequestID string `json:"requestId"`
		Response  struct {
			Opcode      int    `json:"opcode"`
			PayloadData string `json:"payloadData"`
		} `json:"response"`
	}
	json.Unmarshal(ev.Params, &p)
	frame, ok := wsCaptureFrame(p.Response.Opcode, p.Response.PayloadData)
	if !ok {
		return
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	rec := bs.rec
	pr := bs.wsPending(ev.SessionID, p.RequestID, "", false)
	if pr == nil || rec == nil {
		return
	}
	pr.addWSFrame(sent, frame)
	if err := bs.persistWSLocked(rec, pr, false); err != nil {
		log.Printf("保存 WebSocket 帧失败: %v", err)
	}
}

func (bs *BrowserSession) onWSClosed(ev cdp.Event) {
	var p struct {
		RequestID string `json:"requestId"`
	}
	json.Unmarshal(ev.Params, &p)
	bs.mu.Lock()
	defer bs.mu.Unlock()
	rec := bs.rec
	if rec == nil {
		return
	}
	k := key(ev.SessionID, p.RequestID)
	pr := rec.pending[k]
	if pr == nil || !pr.ws {
		return
	}
	pr.wsState = "closed"
	if err := bs.persistWSLocked(rec, pr, true); err != nil {
		log.Printf("保存 WebSocket 关闭失败: %v", err)
		return
	}
	delete(rec.pending, k)
}

func (bs *BrowserSession) onWSError(ev cdp.Event) {
	var p struct {
		RequestID    string `json:"requestId"`
		ErrorMessage string `json:"errorMessage"`
	}
	json.Unmarshal(ev.Params, &p)
	bs.mu.Lock()
	defer bs.mu.Unlock()
	rec := bs.rec
	pr := bs.wsPending(ev.SessionID, p.RequestID, "", false)
	if pr == nil || rec == nil {
		return
	}
	pr.wsState = "error"
	pr.wsErr = clipWSErr(p.ErrorMessage)
	if err := bs.persistWSLocked(rec, pr, true); err != nil {
		log.Printf("保存 WebSocket 错误失败: %v", err)
	}
}

// wsPending returns the in-progress WebSocket row. A row is created only for
// webSocketCreated with a real ws:// or wss:// URL. Caller holds bs.mu.
func (bs *BrowserSession) wsPending(session, requestID, rawURL string, create bool) *pendingReq {
	rec := bs.rec
	if rec == nil || rec.stopped || requestID == "" {
		return nil
	}
	if bs.ignore[bs.pages[session]] {
		return nil
	}
	k := key(session, requestID)
	if pr, ok := rec.pending[k]; ok {
		return pr
	}
	if !create || !validWSURL(rawURL) {
		return nil
	}
	rec.seq++
	pr := &pendingReq{ws: true, session: session, reqID: requestID, rec: &ReqRecord{
		RecordingID: rec.id, Seq: rec.seq, Method: "WS", URL: rawURL, ResourceType: "WebSocket",
		ReqHeaders: map[string]string{}, RespHeaders: map[string]string{},
		TS: time.Now().Format("15:04:05.000"),
	}}
	rec.pending[k] = pr
	return pr
}

func validWSURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "ws" || u.Scheme == "wss"
}

// persistWSLocked writes the JSON envelopes. force is set for handshake, close,
// error, and stop. Other frames flush at most once per 500ms. Caller holds bs.mu.
// On failure the pending row is left in place.
func (bs *BrowserSession) persistWSLocked(rec *activeRecording, pr *pendingReq, force bool) error {
	if rec == nil || pr == nil || pr.rec == nil {
		return nil
	}
	if !force && !pr.wsFlush.IsZero() && time.Since(pr.wsFlush) < 500*time.Millisecond {
		return nil
	}
	sent, sentCut := fitWSFrames(pr.wsSent, pr.wsSentCut, "", "")
	recv, recvCut := fitWSFrames(pr.wsRecv, pr.wsRecvCut, pr.wsState, pr.wsErr)
	pr.wsSent, pr.wsSentCut = sent, sentCut
	pr.wsRecv, pr.wsRecvCut = recv, recvCut
	sb, err := json.Marshal(wsEnv(pr.wsSent, pr.wsSentCut, "", ""))
	if err != nil {
		return err
	}
	rb, err := json.Marshal(wsEnv(pr.wsRecv, pr.wsRecvCut, pr.wsState, pr.wsErr))
	if err != nil {
		return err
	}
	pr.rec.ReqBody = string(sb)
	pr.rec.RespBody = string(rb)
	noise, why := bs.app.classifyRecorded(pr.rec)
	pr.rec.Noise, pr.rec.NoiseReason = noise, why
	if pr.rec.ID == 0 {
		if err := bs.app.store.InsertRequest(pr.rec); err != nil {
			return err
		}
		pr.wsInserted = true
		pr.wsNoise = noise
		rec.count++
		if !noise {
			rec.useful++
		}
	} else {
		if err := bs.app.store.UpdateRequest(pr.rec); err != nil {
			return err
		}
		if pr.wsNoise != noise {
			if pr.wsNoise && !noise {
				rec.useful++
			} else if !pr.wsNoise && noise && rec.useful > 0 {
				rec.useful--
			}
			pr.wsNoise = noise
		}
	}
	pr.wsFlush = time.Now()
	return nil
}

func wsEnv(frames []wsStoredFrame, cut bool, state, errMsg string) wsEnvelope {
	if frames == nil {
		frames = []wsStoredFrame{}
	}
	return wsEnvelope{V: 1, State: state, Error: errMsg, Truncated: cut, Frames: frames}
}

// fitWSFrames drops whole frames from the end until the marshalled envelope fits.
func fitWSFrames(frames []wsStoredFrame, cut bool, state, errMsg string) ([]wsStoredFrame, bool) {
	if frames == nil {
		frames = []wsStoredFrame{}
	} else {
		frames = append([]wsStoredFrame{}, frames...)
	}
	for {
		b, err := json.Marshal(wsEnv(frames, cut, state, errMsg))
		if err == nil && len(b) <= maxBody {
			return frames, cut
		}
		if len(frames) == 0 {
			return frames, true
		}
		frames = frames[:len(frames)-1]
		cut = true
	}
}

// wsMetaReserve is the largest close/error metadata a later flush can add.
// Frames are accepted only when they still fit with this reserve and with
// truncated:true, so a later flush does not have to drop an earlier frame.
func wsMetaReserve(sent bool) (state, errMsg string) {
	if sent {
		return "", ""
	}
	return "closed", strings.Repeat("\x01", 512)
}

func wsFramesFit(frames []wsStoredFrame, sent bool) bool {
	state, errMsg := wsMetaReserve(sent)
	b, err := json.Marshal(wsEnv(frames, true, state, errMsg))
	return err == nil && len(b) <= maxBody
}

func (pr *pendingReq) addWSFrame(sent bool, f wsStoredFrame) {
	if (sent && pr.wsSentCut) || (!sent && pr.wsRecvCut) {
		return
	}
	cur := pr.wsRecv
	if sent {
		cur = pr.wsSent
	}
	next := append(append([]wsStoredFrame{}, cur...), f)
	if !wsFramesFit(next, sent) {
		if sent {
			pr.wsSentCut = true
		} else {
			pr.wsRecvCut = true
		}
		return
	}
	if sent {
		pr.wsSent = next
	} else {
		pr.wsRecv = next
	}
}

func wsCaptureFrame(opcode int, data string) (wsStoredFrame, bool) {
	f := wsStoredFrame{TS: time.Now().Format("15:04:05.000"), Op: opcode}
	switch opcode {
	case 1:
		f.Text = data
		return f, true
	case 2:
		f.Bytes = wsBinaryLen(data)
		return f, true
	default:
		return wsStoredFrame{}, false
	}
}

func wsBinaryLen(data string) int {
	if data == "" {
		return 0
	}
	if b, err := base64.StdEncoding.DecodeString(data); err == nil {
		return len(b)
	}
	if b, err := base64.RawStdEncoding.DecodeString(data); err == nil {
		return len(b)
	}
	return 0
}

func clipWSErr(s string) string {
	if len(s) <= 512 {
		return s
	}
	return s[:512]
}

// StartRecordingOn marks this session as recording and opens the start URL.
func (bs *BrowserSession) StartRecordingOn(id int64, name, startURL string, fresh bool) error {
	bs.mu.Lock()
	bs.rec = &activeRecording{id: id, name: name, pending: map[string]*pendingReq{}}
	sessions := make([]string, 0, len(bs.pages))
	for s := range bs.pages {
		sessions = append(sessions, s)
	}
	bs.mu.Unlock()
	for _, s := range sessions {
		bs.installOverlay(s, name)
	}
	target := startURL
	if target == "" {
		target = "about:blank"
	}
	if fresh {
		// wait for the initial about:blank page to be attached
		select {
		case s := <-bs.firstPg:
			if startURL != "" {
				return bs.call(s, "Page.navigate", map[string]any{"url": startURL}, nil)
			}
			return nil
		case <-time.After(10 * time.Second):
		}
	}
	return bs.call("", "Target.createTarget", map[string]any{"url": target}, nil)
}

// FinishRecording stops capturing and returns the recording stats.
func (bs *BrowserSession) FinishRecording() *activeRecording {
	bs.mu.Lock()
	rec := bs.rec
	if rec == nil {
		bs.mu.Unlock()
		return nil
	}
	rec.stopped = true
	bs.mu.Unlock()
	// wait for in-flight body fetches (bounded)
	done := make(chan struct{})
	go func() { rec.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	bs.mu.Lock()
	for k, pr := range rec.pending {
		if pr.ws {
			if err := bs.persistWSLocked(rec, pr, true); err != nil {
				if err2 := bs.persistWSLocked(rec, pr, true); err2 != nil {
					log.Printf("结束录制时保存 WebSocket 失败: %v", err2)
				}
			}
		} else if pr.rec.Status != 0 {
			bs.storeLocked(rec, pr)
		}
		delete(rec.pending, k)
	}
	bs.rec = nil
	bs.mu.Unlock()
	return rec
}

func (bs *BrowserSession) RecordingStats() (int, int) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.rec == nil {
		return 0, 0
	}
	return bs.rec.count, bs.rec.useful
}

// Cookies reads all cookies from the live browser.
func (bs *BrowserSession) Cookies() ([]Cookie, error) {
	var r struct {
		Cookies []Cookie `json:"cookies"`
	}
	if err := bs.call("", "Storage.getCookies", map[string]any{}, &r); err != nil {
		return nil, err
	}
	return r.Cookies, nil
}

func (bs *BrowserSession) Close() {
	bs.call("", "Browser.close", nil, nil)
	select {
	case <-bs.closed:
	case <-time.After(5 * time.Second):
		if bs.cmd != nil && bs.cmd.Process != nil {
			bs.cmd.Process.Kill()
		}
	}
}

func (bs *BrowserSession) Alive() bool {
	select {
	case <-bs.closed:
		return false
	default:
		return true
	}
}

// scheduleCookieSync snapshots cookies shortly after the site sets new ones (e.g. right after login).
func (bs *BrowserSession) scheduleCookieSync() {
	if !bs.syncPending.CompareAndSwap(false, true) {
		return
	}
	time.AfterFunc(400*time.Millisecond, func() {
		bs.syncPending.Store(false)
		if !bs.Alive() {
			return
		}
		cs, err := bs.Cookies()
		if err == nil && len(cs) > 0 {
			bs.app.store.ReplaceCookies(cs)
		}
		debugf("cookie sync after set-cookie: %d cookies err=%v", len(cs), err)
	})
}

func debugf(f string, a ...any) {
	if os.Getenv("A2M_DEBUG") != "" {
		log.Printf("[debug] "+f, a...)
	}
}
