package app

import (
	"action2mcp/internal/analysis"
	"action2mcp/internal/browser"
	"action2mcp/internal/catalog"
	"action2mcp/internal/config"
	"action2mcp/internal/console"
	"action2mcp/internal/flow"
	"action2mcp/internal/invoke"
	"action2mcp/internal/login"
	"action2mcp/internal/mcp"
	"action2mcp/internal/mcpserver"
	"action2mcp/internal/middleware"
	"action2mcp/internal/mwtools"
	"action2mcp/internal/store"
	"action2mcp/internal/transfer"
	"action2mcp/internal/updater"
	"action2mcp/internal/vault"

	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const Version = "0.7.0"

type App struct {
	dataDir    string
	cfg        config.Config
	store      *store.Store
	httpClient *http.Client

	browserOnce    sync.Once
	browserManager *browser.Manager
	quit           chan struct{}

	gatewayOnce        sync.Once
	gatewayService     *invoke.Gateway
	approvalTimeout    time.Duration
	approvalInsertHook func() error
	approvalDecideHook func() error
	prepareNow         func() time.Time
	wsReloginHook      func() error

	vault        *vault.Vault
	loginOnce    sync.Once
	loginService *login.Service

	analysisOnce    sync.Once
	analysisService *analysis.Service

	drivers           middleware.Drivers
	middlewareOnce    sync.Once
	middlewareService *mwtools.Service
	consoleOnce       sync.Once
	consoleService    *console.Server
	catalogOnce       sync.Once
	catalogService    *catalog.Service
	transferOnce      sync.Once
	transferService   *transfer.Service
	mcpOnce           sync.Once
	mcpService        *mcpserver.Server
	mcpSessions       mcp.Manager // Mcp-Session-Id -> *mcp.Session (client name, loaded packs, SSE stream)
	flowOnce          sync.Once
	flowService       *flow.Executor
	updaterOnce       sync.Once
	updaterService    *updater.Service
}

func NewApp(dataDir string) (*App, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, err
	}
	updater.CleanupStaleFiles("")
	cfg := config.LoadConfig(dataDir)
	st, err := store.OpenStore(filepath.Join(dataDir, "a2m.db"))
	if err != nil {
		return nil, err
	}
	v, err := vault.OpenVault(st.DB(), filepath.Join(dataDir, "secret.key"))
	if err != nil {
		return nil, err
	}
	a := &App{dataDir: dataDir, cfg: cfg, store: st, quit: make(chan struct{}), vault: v,
		httpClient: &http.Client{Timeout: 60 * time.Second}}
	// every site used by a tool or WebSocket middleware gets a 登录配置
	if tools, err := st.ListTools(); err == nil {
		for _, t := range tools {
			st.EnsureSite(t.URL)
		}
	}
	if ms, err := st.ListMiddleware(); err == nil {
		for _, m := range ms {
			if m.Type == "websocket" && strings.TrimSpace(m.Config.URL) != "" {
				st.EnsureSite(m.Config.URL)
			}
		}
	}
	go a.browserRuntime().CookieSyncLoop()
	go a.loginRuntime().KeepaliveLoop()
	go a.updaterRuntime().Loop(a.quit)
	return a, nil
}

// ---------- recording ----------

type Status struct {
	Version        string              `json:"version"`
	PID            int                 `json:"pid"`
	Recording      bool                `json:"recording"`
	RecordingID    int64               `json:"recording_id"`
	RecordingName  string              `json:"recording_name"`
	RecordingSecs  int                 `json:"recording_secs"`
	Captured       int                 `json:"captured"`
	Useful         int                 `json:"useful"`
	BrowserRunning bool                `json:"browser_running"`
	LastStop       *StopInfo           `json:"last_stop"`
	ExposedTools   int                 `json:"exposed_tools"`
	ExposedMW      int                 `json:"exposed_middleware"`
	TotalTools     int                 `json:"total_tools"`
	EnabledPacks   int                 `json:"enabled_packs"`
	MCPURL         string              `json:"mcp_url"`
	MCPMode        string              `json:"mcp_mode"`
	DataDir        string              `json:"data_dir"`
	ExePath        string              `json:"exe_path"`
	OS             string              `json:"os"`
	Update         *updater.UpdateInfo `json:"update,omitempty"`
}

func (a *App) Status() Status {
	state := a.browserRuntime().Snapshot()
	up := a.updaterRuntime().Snapshot()
	s := Status{Version: Version, PID: os.Getpid(), Recording: state.Recording, RecordingID: state.RecordingID, RecordingName: state.RecordingName, LastStop: state.LastStop, RecordingSecs: state.RecordingSecs, BrowserRunning: state.BrowserRunning, Captured: state.Captured, Useful: state.Useful, MCPURL: fmt.Sprintf("http://localhost:%d/mcp", a.cfg.Port), DataDir: a.dataDir, OS: runtime.GOOS, Update: &up}
	if exe, err := os.Executable(); err == nil {
		s.ExePath = exe
	}
	ex, _ := a.store.ExposedTools()
	n := 0
	for _, t := range ex {
		if _, ok := mwtools.IsTool(t.Name); !ok {
			n++
		}
	}
	s.ExposedTools = n + len(a.middlewares().ToolList())
	s.MCPMode = a.mcpServer().Mode()
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

func (a *App) Shutdown() {
	a.browserRuntime().Shutdown()
	select {
	case <-a.quit:
	default:
		close(a.quit)
	}
}

func debugf(f string, a ...any) {
	if os.Getenv("A2M_DEBUG") != "" {
		log.Printf("[debug] "+f, a...)
	}
}
