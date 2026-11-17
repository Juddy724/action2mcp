package browser

import (
	"action2mcp/internal/cdp"
	"action2mcp/internal/recording"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
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
type Session struct {
	owner    *Manager
	cmd      *exec.Cmd
	conn     *cdp.Conn
	headless bool

	mu      sync.Mutex
	pages   map[string]string // sessionId -> targetId
	capture *recording.Capture
	closed  chan struct{}
	scripts map[string]string // sessionId -> script identifier for overlay
	firstPg chan string

	syncPending atomic.Bool

	ignore map[string]bool // targetIds opened by Action2MCP itself (not recorded)
	users  int             // active background users (guarded by Manager.mu)
}

func (a *Manager) profileDir() string { return a.options.ProfileDir }

// LaunchBrowser starts the browser with the dedicated profile and connects via CDP.
func (a *Manager) Launch(headless bool) (*Session, error) {
	cfg := a.options.Config()
	bin, err := FindBrowser(cfg.BrowserPath)
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
	if cfg.NoSandbox || (runtime.GOOS == "linux" && os.Geteuid() == 0) {
		args = append(args, "--no-sandbox")
	}
	args = append(args, cfg.BrowserArgs...)
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
	bs := &Session{owner: a, cmd: cmd, conn: conn, headless: headless, pages: map[string]string{}, closed: make(chan struct{}), scripts: map[string]string{}, firstPg: make(chan string, 1)}
	bs.capture = a.newCapture(bs)
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

func (bs *Session) Closed() <-chan struct{} { return bs.closed }

func (bs *Session) loop(exited chan struct{}) {
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
	bs.owner.onBrowserClosed(bs)
	close(bs.closed)
}

func (bs *Session) call(session, method string, params any, out any) error {
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

func (bs *Session) setupPage(session string) {
	name, active := bs.capture.ActiveName()
	bs.call(session, "Network.enable", map[string]any{"maxPostDataSize": 262144}, nil)
	if !bs.headless {
		bs.call(session, "Page.enable", nil, nil)
		bs.call(session, "Runtime.enable", nil, nil)
		bs.call(session, "Runtime.addBinding", map[string]any{"name": bindingName}, nil)
		if active {
			bs.installOverlay(session, name)
		}
	}
	bs.call(session, "Runtime.runIfWaitingForDebugger", nil, nil)
}

func (bs *Session) installOverlay(session, name string) {
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

func (bs *Session) removeOverlays() {
	bs.mu.Lock()
	scripts := bs.scripts
	bs.scripts = map[string]string{}
	bs.mu.Unlock()
	for s, id := range scripts {
		bs.call(s, "Page.removeScriptToEvaluateOnNewDocument", map[string]any{"identifier": id}, nil)
		bs.call(s, "Runtime.evaluate", map[string]any{"expression": `(function(){var e=document.getElementById('__a2m_overlay'); if(e) e.remove(); window.__a2mStopped=true;})()`}, nil)
	}
}

func (bs *Session) handle(ev cdp.Event) {
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
						bs.owner.repo.ReplaceCookies(cs)
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
			go bs.owner.StopRecording("overlay")
		}
	case "Network.requestWillBeSent":
		bs.capture.HandleEvent(ev)
	case "Network.responseReceivedExtraInfo":
		if !bs.headless && bytes.Contains(bytes.ToLower(ev.Params), []byte("set-cookie")) {
			bs.scheduleCookieSync()
		}
	case "Network.requestWillBeSentExtraInfo":
		bs.capture.HandleEvent(ev)
	case "Network.responseReceived":
		bs.capture.HandleEvent(ev)
	case "Network.loadingFinished":
		bs.capture.HandleEvent(ev)
	case "Network.loadingFailed":
		bs.capture.HandleEvent(ev)
	case "Network.webSocketCreated":
		bs.capture.HandleEvent(ev)
	case "Network.webSocketWillSendHandshakeRequest":
		bs.capture.HandleEvent(ev)
	case "Network.webSocketHandshakeResponseReceived":
		bs.capture.HandleEvent(ev)
	case "Network.webSocketFrameSent":
		bs.capture.HandleEvent(ev)
	case "Network.webSocketFrameReceived":
		bs.capture.HandleEvent(ev)
	case "Network.webSocketClosed":
		bs.capture.HandleEvent(ev)
	case "Network.webSocketFrameError":
		bs.capture.HandleEvent(ev)
	}
}

// StartRecordingOn marks this session as recording and opens the start URL.
func (bs *Session) StartRecordingOn(id int64, name, startURL string, fresh bool) error {
	bs.capture.Start(id, name)
	bs.mu.Lock()
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

// Cookies reads all cookies from the live browser.
func (bs *Session) Cookies() ([]Cookie, error) {
	var r struct {
		Cookies []Cookie `json:"cookies"`
	}
	if err := bs.call("", "Storage.getCookies", map[string]any{}, &r); err != nil {
		return nil, err
	}
	return r.Cookies, nil
}

func (bs *Session) Close() {
	bs.call("", "Browser.close", nil, nil)
	select {
	case <-bs.closed:
	case <-time.After(5 * time.Second):
		if bs.cmd != nil && bs.cmd.Process != nil {
			bs.cmd.Process.Kill()
		}
	}
}

func (bs *Session) Alive() bool {
	select {
	case <-bs.closed:
		return false
	default:
		return true
	}
}

// scheduleCookieSync snapshots cookies shortly after the site sets new ones (e.g. right after login).
func (bs *Session) scheduleCookieSync() {
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
			bs.owner.repo.ReplaceCookies(cs)
		}
		debugf("cookie sync after set-cookie: %d cookies err=%v", len(cs), err)
	})
}

func debugf(f string, a ...any) {
	if os.Getenv("A2M_DEBUG") != "" {
		log.Printf("[debug] "+f, a...)
	}
}

// Browser lifecycle facade: capture state is owned by the recording service.
func (bs *Session) FinishRecording() *recording.Stats { return bs.capture.FinishRecording() }

func (bs *Session) RecordingStats() (int, int) { return bs.capture.RecordingStats() }

func (a *Manager) newCapture(bs *Session) *recording.Capture {
	return recording.New(a.options.Capture, recording.Hooks{
		Classify:             a.options.Classify,
		TrackHarvestHop:      a.options.TrackHarvestHop,
		HarvestRequestHeader: a.options.HarvestRequestHeader,
		Command:              bs.call,
		Ignored:              func(session string) bool { bs.mu.Lock(); defer bs.mu.Unlock(); return bs.ignore[bs.pages[session]] },
	})
}
