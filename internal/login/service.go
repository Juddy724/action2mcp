// Package login owns per-site login generations, interactive windows, cooldowns,
// cancellation and encrypted credential-header harvesting. No state lock escapes.
package login

import (
	"action2mcp/internal/browser"
	"action2mcp/internal/execution"
	sitecfg "action2mcp/internal/site"
	"action2mcp/internal/vault"
	"database/sql"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type Cookie = execution.Cookie
type Tool = execution.Tool
type LoginErr = execution.LoginErr

// Browsers owns all process/page/profile leases. Login never touches those locks.
type Browsers interface {
	AcquireBrowser() (*browser.Session, error)
	ReleaseBrowser(*browser.Session)
	OpenVisibleTab(string) (*browser.Session, *browser.Tab, error)
	ApplyCookies([]Cookie)
	CookiesFor(string) ([]Cookie, string)
	ClearOriginState(origin string, includeParentCookies bool)
}
type Repository interface {
	GetSite(int64) (*sitecfg.Site, error)
	EnsureSite(string) *sitecfg.Site
	ListSites() []*sitecfg.Site
	SaveSite(*sitecfg.Site) error
	SetSiteStatus(int64, string, string, bool)
	SetSiteError(int64, string)
	AllCookies() []Cookie
	ReplaceCookies([]Cookie)
	ListTools() ([]*execution.Tool, error)
}
type OpenLoginResult struct {
	Opened       bool   `json:"opened"`
	AlreadyValid bool   `json:"already_valid"`
	Method       string `json:"method,omitempty"`
	Message      string `json:"message,omitempty"`
}
type MiddlewareBinding struct {
	URL   string
	Names []string
}
type Options struct {
	Repository         Repository
	HeaderDB           *sql.DB
	Vault              *vault.Vault
	Browsers           Browsers
	Quit               <-chan struct{}
	ConsolePort        func() int
	HTTPClient         func() *http.Client
	MiddlewareBindings func() []MiddlewareBinding
	Probe              func(*Tool, string, string, map[string]string, string, []Cookie, string) (*execution.CallResult, error)
	OpenLogin          func(string) (LoginBrowser, Surface, error)
	Wait               time.Duration
}

// Service owns login generations, cooldown/pending/cancellation state and header
// harvesting. Its semaphore, state map, hop cache, SQL handle and locks are private.
type Service struct {
	options         Options
	repo            Repository
	db              *sql.DB
	vault           *vault.Vault
	browsers        Browsers
	smu             sync.Mutex
	sstates         map[string]*siteState
	harvest         *harvestState
	pendingLoginMax time.Duration
	openLogin       func(string) (LoginBrowser, Surface, error)
}

func New(o Options) *Service {
	return &Service{options: o, repo: o.Repository, db: o.HeaderDB, vault: o.Vault, browsers: o.Browsers, pendingLoginMax: o.Wait, openLogin: o.OpenLogin}
}

type Snapshot struct {
	Pending              bool
	PendingMsg, Cooldown string
	Relogins             int
}

func (a *Service) Snapshot(origin string) Snapshot {
	st := a.state(origin)
	a.smu.Lock()
	defer a.smu.Unlock()
	s := Snapshot{Pending: st.pending, PendingMsg: st.pendingMsg, Relogins: st.relogins}
	if !st.failUntil.IsZero() && time.Now().Before(st.failUntil) {
		s.Cooldown = st.failMsg
	}
	return s
}
func (a *Service) Generation(origin string) int64 { return a.siteGen(a.state(origin)) }
func now() string                                 { return time.Now().Format("2006-01-02 15:04:05") }
func debugf(f string, a ...any) {
	if os.Getenv("A2M_DEBUG") != "" {
		log.Printf("[debug] "+f, a...)
	}
}
func IsCSRFField(name string) bool { return csrfNameRe.MatchString(name) }
