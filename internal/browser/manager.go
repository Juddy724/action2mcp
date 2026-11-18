// Package browser owns dedicated-profile processes, page leases, CDP event routing
// and recording lifecycle. Login policy and application stores are injected ports.
package browser

import (
	"action2mcp/internal/domain"
	"action2mcp/internal/execution"
	"action2mcp/internal/recording"
	"sync"
	"time"
)

type Cookie = execution.Cookie
type RecordingLoginResult = domain.RecordingLoginResult

// Repository persists only recordings and the dedicated browser cookie jar.
type Repository interface {
	CreateRecording(string, string) (int64, error)
	FinishRecording(int64)
	GetRecording(int64) (*recording.Recording, error)
	AllCookies() []Cookie
	SaveCookies([]Cookie)
	ReplaceCookies([]Cookie)
}

// LaunchConfig is read when a new browser is launched, not when the manager is wired.
type LaunchConfig struct {
	BrowserPath string
	BrowserArgs []string
	NoSandbox   bool
}

type Options struct {
	ProfileDir           string
	Config               func() LaunchConfig
	Quit                 <-chan struct{}
	Repository           Repository
	Capture              recording.Repository
	Classify             func(*recording.Request) (bool, string)
	TrackHarvestHop      func(string, string)
	HarvestRequestHeader func(string, string, string, string) error
	DetectRecordingLogin func(recording.Recording) (*domain.RecordingLoginResult, error)
}

// Manager owns browser/profile leases and recording lifecycle. It owns neither
// application policy nor login generations, and accepts no App or exposed locks.
type Manager struct {
	options       Options
	repo          Repository
	mu            sync.Mutex
	browser       *Session
	recID         int64
	recName       string
	recStart      time.Time
	lastStop      *StopInfo
	clearMu       sync.Mutex
	pendingClears map[string]bool
}

func New(o Options) *Manager {
	return &Manager{options: o, repo: o.Repository}
}

type Snapshot struct {
	Recording        bool
	RecordingID      int64
	RecordingName    string
	RecordingSecs    int
	Captured, Useful int
	BrowserRunning   bool
	LastStop         *StopInfo
}

func (a *Manager) Snapshot() Snapshot {
	a.mu.Lock()
	s := Snapshot{Recording: a.recID != 0, RecordingID: a.recID, RecordingName: a.recName, LastStop: copyStopInfo(a.lastStop)}
	if s.Recording {
		s.RecordingSecs = int(time.Since(a.recStart).Seconds())
	}
	bs := a.browser
	a.mu.Unlock()
	if bs != nil && bs.Alive() && !bs.headless {
		s.BrowserRunning = true
		s.Captured, s.Useful = bs.RecordingStats()
	}
	return s
}
func (a *Manager) Shutdown() {
	if a.Snapshot().Recording {
		a.StopRecording("shutdown")
	}
	a.mu.Lock()
	bs := a.browser
	a.mu.Unlock()
	if bs != nil && bs.Alive() {
		bs.Close()
	}
}

// applyCookies stores cookies obtained over HTTP and pushes them into a running browser so the
// periodic browser→jar sync does not drop them.
func (a *Manager) ApplyCookies(cs []Cookie) {
	a.repo.SaveCookies(cs)
	a.mu.Lock()
	bs := a.browser
	a.mu.Unlock()
	if bs != nil && bs.Alive() {
		bs.SetCookies(cs)
	}
}

func copyStopInfo(in *StopInfo) *StopInfo {
	if in == nil {
		return nil
	}
	out := *in
	if in.LoginDetection != nil {
		v := *in.LoginDetection
		out.LoginDetection = &v
	}
	return &out
}
