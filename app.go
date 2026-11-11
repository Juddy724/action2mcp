package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const Version = "0.5.3"

type Config struct {
	Port        int      `json:"port"`
	Browser     string   `json:"browser"`
	BrowserArgs []string `json:"browser_args"`
	NoSandbox   bool     `json:"no_sandbox"`
	OpenConsole *bool    `json:"open_console,omitempty"`
}

type App struct {
	dataDir    string
	cfg        Config
	store      *Store
	httpClient *http.Client

	mu       sync.Mutex
	browser  *BrowserSession
	recID    int64
	recName  string
	recStart time.Time
	lastStop *StopInfo
	quit     chan struct{}

	approvalMu         sync.Mutex
	approvals          map[int64]*pendingApproval
	approvalTimeout    time.Duration
	approvalInsertHook func() error
	approvalDecideHook func() error
	prepareNow         func() time.Time

	vault   *Vault
	smu     sync.Mutex
	sstates map[string]*siteState

	mwmu        sync.Mutex
	mwPool      sync.Map // cache key -> client (*sql.DB, redis client, mq clients)
	mwPoolKeys  map[int64]string
	mcpSessions sync.Map // Mcp-Session-Id -> *mcpSession (client name, loaded packs, SSE stream)
}

type StopInfo struct {
	RecordingID    int64                 `json:"recording_id"`
	Name           string                `json:"name"`
	Count          int                   `json:"count"`
	Useful         int                   `json:"useful"`
	Reason         string                `json:"reason"`
	At             string                `json:"at"`
	LoginDetection *RecordingLoginResult `json:"login_detection,omitempty"`
}

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	exe, _ = filepath.EvalSymlinks(exe)
	return filepath.Dir(exe)
}

func resolveDataDir() string {
	if d := os.Getenv("A2M_DATA"); d != "" {
		if abs, err := filepath.Abs(d); err == nil {
			return abs
		}
		return d
	}
	return filepath.Join(exeDir(), "data")
}

func LoadConfig(dataDir string) Config {
	cfg := Config{Port: 7788}
	p := filepath.Join(dataDir, "config.json")
	if b, err := os.ReadFile(p); err == nil {
		if err := json.Unmarshal(b, &cfg); err != nil {
			log.Printf("config.json 格式错误: %v", err)
		}
	} else {
		os.MkdirAll(dataDir, 0o755)
		b, _ := json.MarshalIndent(map[string]any{"port": 7788, "browser": "", "browser_args": []string{}, "no_sandbox": false}, "", "  ")
		os.WriteFile(p, b, 0o644)
	}
	if v := os.Getenv("A2M_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Port = n
		}
	}
	if v := os.Getenv("A2M_BROWSER"); v != "" {
		cfg.Browser = v
	}
	if os.Getenv("A2M_NO_SANDBOX") == "1" {
		cfg.NoSandbox = true
	}
	if cfg.Port == 0 {
		cfg.Port = 7788
	}
	return cfg
}

func NewApp(dataDir string) (*App, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	cfg := LoadConfig(dataDir)
	st, err := OpenStore(filepath.Join(dataDir, "a2m.db"))
	if err != nil {
		return nil, err
	}
	v, err := OpenVault(st.db, filepath.Join(dataDir, "secret.key"))
	if err != nil {
		return nil, err
	}
	a := &App{dataDir: dataDir, cfg: cfg, store: st, quit: make(chan struct{}), vault: v,
		httpClient: &http.Client{Timeout: 60 * time.Second}}
	// every site used by a tool gets a 登录配置 (default: 企业微信 / 单点登录)
	if tools, err := st.ListTools(); err == nil {
		for _, t := range tools {
			st.EnsureSite(t.URL)
		}
	}
	go a.cookieSyncLoop()
	go a.keepaliveLoop()
	return a, nil
}

func (a *App) BaseURL() string { return fmt.Sprintf("http://127.0.0.1:%d", a.cfg.Port) }

// ---------- recording ----------

func (a *App) StartRecording(name, startURL string) (int64, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "录制 " + time.Now().Format("01-02 15:04")
	}
	startURL = strings.TrimSpace(startURL)
	if startURL != "" && !strings.Contains(startURL, "://") {
		startURL = "https://" + startURL
	}
	if startURL != "" {
		if _, err := url.Parse(startURL); err != nil {
			return 0, errors.New("起始网址格式不正确")
		}
	}
	a.evictHeadless(30 * time.Second)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.recID != 0 {
		return 0, fmt.Errorf("已经有一个录制在进行中（%s），请先结束它", a.recName)
	}
	bs := a.browser
	fresh := false
	if bs != nil && (!bs.Alive() || bs.headless) {
		if bs.Alive() {
			bs.Close()
		}
		bs = nil
		a.browser = nil
	}
	if bs == nil {
		var err error
		bs, err = a.LaunchBrowser(false)
		if err != nil {
			return 0, err
		}
		a.browser = bs
		fresh = true
	}
	id, err := a.store.CreateRecording(name, startURL)
	if err != nil {
		return 0, err
	}
	if err := bs.StartRecordingOn(id, name, startURL, fresh); err != nil {
		log.Printf("打开起始页面失败: %v", err)
	}
	a.recID, a.recName, a.recStart = id, name, time.Now()
	log.Printf("开始录制 #%d %s", id, name)
	return id, nil
}

// StopRecording finishes the active recording. reason: overlay|command|console|browser-closed
func (a *App) StopRecording(reason string) (*StopInfo, error) {
	a.mu.Lock()
	if a.recID == 0 {
		a.mu.Unlock()
		if a.lastStop != nil && reason != "overlay" {
			return a.lastStop, errors.New("当前没有正在进行的录制")
		}
		return nil, errors.New("当前没有正在进行的录制")
	}
	id, name, bs := a.recID, a.recName, a.browser
	a.recID, a.recName = 0, ""
	a.mu.Unlock()
	info := &StopInfo{RecordingID: id, Name: name, Reason: reason, At: now()}
	if bs != nil {
		if rec := bs.FinishRecording(); rec != nil {
			info.Count, info.Useful = rec.count, rec.useful
		}
		if bs.Alive() {
			if cs, err := bs.Cookies(); err == nil {
				a.store.ReplaceCookies(cs)
			}
			bs.removeOverlays()
			if reason != "browser-closed" {
				go func() {
					time.Sleep(1200 * time.Millisecond) // let the overlay show "已结束"
					bs.Close()
				}()
			}
		}
	}
	a.store.FinishRecording(id)
	rec, detectErr := a.store.GetRecording(id)
	if detectErr == nil {
		info.LoginDetection, detectErr = a.detectRecordingLogin(*rec)
	}
	if detectErr != nil {
		log.Printf("录制 #%d 自动识别企业微信登录失败", id)
		info.LoginDetection = &RecordingLoginResult{Action: "error", Message: "自动识别登录失败，可在录制详情页点击「加入登录中心」重试"}
	}
	a.mu.Lock()
	a.lastStop = info
	a.mu.Unlock()
	log.Printf("结束录制 #%d %s：共 %d 个请求，其中 %d 个可能有用（%s）", id, name, info.Count, info.Useful, reason)
	return info, nil
}

func (a *App) onBrowserClosed(bs *BrowserSession) {
	a.mu.Lock()
	same := a.browser == bs
	recording := a.recID != 0
	a.mu.Unlock()
	if !same {
		return
	}
	if recording {
		a.StopRecording("browser-closed")
	}
	a.mu.Lock()
	if a.browser == bs {
		a.browser = nil
	}
	a.mu.Unlock()
}

// OpenBrowser opens the dedicated browser (for logging in) without recording.
func (a *App) OpenBrowser(u string) error {
	a.evictHeadless(30 * time.Second)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.browser != nil && a.browser.Alive() && !a.browser.headless {
		if u == "" {
			u = "about:blank"
		}
		return a.browser.call("", "Target.createTarget", map[string]any{"url": u}, nil)
	}
	if a.browser != nil && a.browser.Alive() {
		a.browser.Close()
	}
	bs, err := a.LaunchBrowser(false)
	if err != nil {
		return err
	}
	a.browser = bs
	if u != "" {
		select {
		case s := <-bs.firstPg:
			bs.call(s, "Page.navigate", map[string]any{"url": u}, nil)
		case <-time.After(10 * time.Second):
		}
	}
	return nil
}

type Status struct {
	Version        string    `json:"version"`
	PID            int       `json:"pid"`
	Recording      bool      `json:"recording"`
	RecordingID    int64     `json:"recording_id"`
	RecordingName  string    `json:"recording_name"`
	RecordingSecs  int       `json:"recording_secs"`
	Captured       int       `json:"captured"`
	Useful         int       `json:"useful"`
	BrowserRunning bool      `json:"browser_running"`
	LastStop       *StopInfo `json:"last_stop"`
	ExposedTools   int       `json:"exposed_tools"`
	ExposedMW      int       `json:"exposed_middleware"`
	TotalTools     int       `json:"total_tools"`
	EnabledPacks   int       `json:"enabled_packs"`
	MCPURL         string    `json:"mcp_url"`
	MCPMode        string    `json:"mcp_mode"`
	DataDir        string    `json:"data_dir"`
	ExePath        string    `json:"exe_path"`
	OS             string    `json:"os"`
}

func (a *App) Status() Status {
	a.mu.Lock()
	s := Status{Version: Version, PID: os.Getpid(), Recording: a.recID != 0, RecordingID: a.recID, RecordingName: a.recName, LastStop: a.lastStop,
		MCPURL: fmt.Sprintf("http://localhost:%d/mcp", a.cfg.Port), DataDir: a.dataDir, OS: runtime.GOOS}
	if exe, err := os.Executable(); err == nil {
		s.ExePath = exe
	}
	if s.Recording {
		s.RecordingSecs = int(time.Since(a.recStart).Seconds())
	}
	bs := a.browser
	a.mu.Unlock()
	if bs != nil && bs.Alive() && !bs.headless {
		s.BrowserRunning = true
		s.Captured, s.Useful = bs.RecordingStats()
	}
	ex, _ := a.store.ExposedTools()
	n := 0
	for _, t := range ex {
		if _, ok := isMWTool(t.Name); !ok {
			n++
		}
	}
	s.ExposedTools = n + len(a.mwToolList())
	s.MCPMode = a.mcpMode()
	ems, _ := a.store.ExposedMiddleware()
	s.ExposedMW = len(ems)
	all, _ := a.store.ListTools()
	s.TotalTools = len(all)
	packs, _ := a.store.ListPacks()
	for _, p := range packs {
		if p.Enabled {
			s.EnabledPacks++
		}
	}
	return s
}

// ---------- credentials ----------

func (a *App) cookieSyncLoop() {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-a.quit:
			return
		case <-t.C:
		}
		a.mu.Lock()
		bs := a.browser
		a.mu.Unlock()
		if bs != nil && bs.Alive() && !bs.headless {
			if cs, err := bs.Cookies(); err == nil {
				a.store.ReplaceCookies(cs)
			}
		}
	}
}

// CookiesFor returns the cookie set to use for a call and where it came from.
func (a *App) CookiesFor(u string) ([]Cookie, string) {
	a.mu.Lock()
	bs := a.browser
	a.mu.Unlock()
	if bs != nil && bs.Alive() {
		if cs, err := bs.Cookies(); err == nil {
			if !bs.headless {
				a.store.ReplaceCookies(cs)
				return cs, "专用浏览器（实时）"
			}
			return cs, "专用浏览器（后台）"
		}
	}
	cs := a.store.AllCookies()
	if h, _ := CookieHeader(cs, u); h != "" {
		return cs, "本地登录态快照"
	}
	// nothing cached for this site: read the persistent cookies from the profile headlessly
	hcs, err := a.readProfileCookies()
	if err != nil {
		if !errors.Is(err, errBrowserBusy) {
			log.Printf("后台读取浏览器登录态失败: %v", err)
		}
		return cs, "无"
	}
	if len(hcs) > 0 {
		a.store.SaveCookies(hcs)
		return a.store.AllCookies(), "浏览器配置（后台读取）"
	}
	return cs, "无"
}

var errBrowserBusy = errors.New("浏览器正在使用中")

// readProfileCookies returns all cookies of the dedicated profile, starting it headlessly when
// no browser is open.
func (a *App) readProfileCookies() ([]Cookie, error) {
	bs, err := a.acquireBrowser()
	if err != nil {
		return nil, err
	}
	defer a.releaseBrowser(bs)
	return bs.Cookies()
}

func (a *App) Shutdown() {
	if a.Status().Recording {
		a.StopRecording("shutdown")
	}
	a.mu.Lock()
	bs := a.browser
	a.mu.Unlock()
	if bs != nil && bs.Alive() {
		bs.Close()
	}
	select {
	case <-a.quit:
	default:
		close(a.quit)
	}
}
