package login

import (
	"errors"
	"sync"
	"testing"
	"time"
)

func TestExecutionSessionGenerationCollapseAndPendingGate(t *testing.T) {
	a := testLoginService(t)
	raw := "https://app.example.test/api"
	session, err := a.Begin(raw)
	if err != nil || session == nil {
		t.Fatalf("begin: %v", err)
	}
	st := a.state(session.Origin())
	a.bumpGen(st)
	// Every stale execution shares the captured generation; none may launch login.
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := session.Relogin(); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if a.Generation(session.Origin()) != 1 || a.ReloginCount(session.Origin()) != 1 {
		t.Fatal("stale execution repeated login")
	}
	a.smu.Lock()
	st.pending = true
	st.pendingMsg = "finish login"
	st.pendingAt = time.Now()
	st.failUntil = time.Now().Add(time.Hour)
	st.failMsg = "cooldown"
	a.smu.Unlock()
	if got, err := a.Begin(raw); err == nil || got != nil {
		t.Fatalf("pending login did not gate execution: %v %v", got, err)
	} else {
		var expected *LoginErr
		if !errors.As(err, &expected) {
			t.Fatalf("lost typed login error: %T", err)
		}
	}
	a.ResetSiteFailures()
	snap := a.Snapshot(session.Origin())
	if !snap.Pending || snap.Cooldown != "" || snap.Relogins != 1 {
		t.Fatalf("reset damaged pending/generation state: %+v", snap)
	}
	a.smu.Lock()
	st.pendingAt = time.Now().Add(-a.loginWait() - time.Second)
	a.smu.Unlock()
	if got, err := a.Begin(raw); err != nil || got == nil {
		t.Fatalf("expired pending state did not reopen execution: %v", err)
	}
}
func TestLoginSnapshotDoesNotExposeMutableState(t *testing.T) {
	a := testLoginService(t)
	origin := "https://app.example.test"
	st := a.state(origin)
	a.smu.Lock()
	st.pending = true
	st.pendingMsg = "original"
	st.relogins = 2
	a.smu.Unlock()
	snapshot := a.Snapshot(origin)
	snapshot.PendingMsg = "mutated"
	snapshot.Relogins = 100
	if got := a.Snapshot(origin); got.PendingMsg != "original" || got.Relogins != 2 {
		t.Fatalf("state escaped through snapshot: %+v", got)
	}
}
