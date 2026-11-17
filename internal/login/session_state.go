package login

import (
	"time"
)

// ---------- per-site runtime state (serialises re-logins) ----------

type siteState struct {
	mu         chan struct{} // 1-slot semaphore so waiters can time out
	gen        int64
	failUntil  time.Time
	failMsg    string
	pending    bool // an interactive login window is open
	pendingMsg string
	pendingAt  time.Time
	ssoHost    string // host of the SSO page shown in the pending window
	relogins   int
	cancel     chan struct{}
	loginSurf  Surface
}

func (a *Service) state(origin string) *siteState {
	a.smu.Lock()
	defer a.smu.Unlock()
	if a.sstates == nil {
		a.sstates = map[string]*siteState{}
	}
	st := a.sstates[origin]
	if st == nil {
		st = &siteState{mu: make(chan struct{}, 1)}
		a.sstates[origin] = st
	}
	return st
}
