package approval

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"action2mcp/internal/domain"
	"action2mcp/internal/vault"

	_ "modernc.org/sqlite"
)

func testSQLStore(t *testing.T) *SQLStore {
	t.Helper()
	db, err := sql.Open("sqlite", t.TempDir()+"/approval.db")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	_, err = db.Exec(`CREATE TABLE approvals(id INTEGER PRIMARY KEY AUTOINCREMENT,ts TEXT,tool TEXT,tool_id INTEGER,tool_rev INTEGER,client TEXT,args_display TEXT,final_args_display TEXT,status TEXT,feedback TEXT,decided_at TEXT,result TEXT,title TEXT,preview_display TEXT,params_json TEXT,result_full TEXT)`)
	if err != nil {
		t.Fatal(err)
	}
	return NewSQLStore(db)
}

type testOperation struct{ version atomic.Int64 }

func (o *testOperation) Edit(original, edits map[string]any) (map[string]any, error) {
	return EditArgs(original, edits, func(key string, _ any) bool { return key == "secret" })
}
func (o *testOperation) Preview(args map[string]any) (Preview, error) {
	b, _ := json.Marshal(struct {
		Args    map[string]any
		Version int64
	}{args, o.version.Load()})
	hash := sha256.Sum256(b)
	return Preview{Preview: domain.RequestPreview{Method: "POST", URL: "https://example.invalid/", Body: vault.Mask}, PreviewHash: hex.EncodeToString(hash[:])}, nil
}
func (o *testOperation) Confirm(args map[string]any) (*testOperation, Preview, map[string]string, error) {
	p, e := o.Preview(args)
	return o, p, map[string]string{"value": "confirmed", "secret": vault.Mask}, e
}
func (o *testOperation) Feedback(text string) string {
	return strings.ReplaceAll(text, "private-secret", vault.Mask)
}

type waitResult struct {
	decision *Decision[*testOperation]
	err      error
}

func startWait(s *Service[*testOperation], ctx context.Context, timeout time.Duration, op *testOperation, args map[string]any, executions *atomic.Int32) <-chan waitResult {
	done := make(chan waitResult, 1)
	go func() {
		decision, err := s.Wait(ctx, args, timeout, func(copy map[string]any) (*testOperation, Record, error) {
			preview, err := op.Preview(copy)
			return op, Record{TS: now(), Tool: "test", Status: "pending", ArgsDisplay: map[string]string{"value": "original", "secret": vault.Mask}, Preview: preview.Preview, PreviewHash: preview.PreviewHash}, err
		})
		if err == nil && executions != nil {
			executions.Add(1)
		}
		done <- waitResult{decision, err}
	}()
	return done
}
func receiveWait(t *testing.T, done <-chan waitResult) waitResult {
	t.Helper()
	select {
	case r := <-done:
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("approval waiter did not finish")
		return waitResult{}
	}
}
func pendingRows(t *testing.T, s *Service[*testOperation], count int) []Record {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		rows, err := s.List("pending", 1000)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == count {
			return rows
		}
		if time.Now().After(deadline) {
			t.Fatalf("pending=%d want=%d", len(rows), count)
		}
		time.Sleep(time.Millisecond)
	}
}
func requireStatus(t *testing.T, err error, status int) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Status != status {
		t.Fatalf("error=%v want status=%d", err, status)
	}
}

func TestServiceCompetingTerminalTransitions(t *testing.T) {
	store := testSQLStore(t)
	s := NewService[*testOperation](store, Options{})
	var executions atomic.Int32
	for i := 0; i < 30; i++ {
		before := executions.Load()
		ctx, cancel := context.WithCancel(context.Background())
		call := startWait(s, ctx, time.Minute, &testOperation{}, map[string]any{"value": "one"}, &executions)
		row := pendingRows(t, s, 1)[0]
		s.mu.Lock()
		p := s.pending[row.ID]
		s.mu.Unlock()
		var wg sync.WaitGroup
		for _, fn := range []func(){func() { s.Decide(row.ID, row.Nonce, "approve", nil, "", row.PreviewHash) }, func() { s.Decide(row.ID, row.Nonce, "reject", nil, "retry", "") }, func() { s.end(p, "timeout") }, cancel} {
			wg.Add(1)
			go func(fn func()) { defer wg.Done(); fn() }(fn)
		}
		wg.Wait()
		receiveWait(t, call)
		cancel()
		rows, err := s.List("all", 1)
		if err != nil || len(rows) != 1 || rows[0].Status == "pending" {
			t.Fatalf("terminal rows=%v err=%v", rows, err)
		}
		expected := int32(0)
		if rows[0].Status == "approved" {
			expected = 1
		}
		if executions.Load()-before != expected {
			t.Fatal("competing decisions granted multiple execution rights")
		}
		s.mu.Lock()
		live := len(s.pending)
		s.mu.Unlock()
		if live != 0 {
			t.Fatal("terminal transition retained a live waiter")
		}
	}
}

func TestServiceNonceFreshPreviewAndRawSnapshot(t *testing.T) {
	store := testSQLStore(t)
	s := NewService[*testOperation](store, Options{})
	op := &testOperation{}
	original := map[string]any{"value": 1, "secret": "private-secret"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	call := startWait(s, ctx, time.Minute, op, original, nil)
	row := pendingRows(t, s, 1)[0]
	original["value"] = 99
	requireStatus(t, s.Decide(row.ID, "wrong", "approve", nil, "", row.PreviewHash), 403)
	op.version.Add(1)
	preview, err := s.Preview(row.ID, row.Nonce, map[string]any{"value": "2", "secret": SecretUnchanged})
	if err != nil {
		t.Fatal(err)
	}
	requireStatus(t, s.Decide(row.ID, row.Nonce, "approve", nil, "", row.PreviewHash), 409)
	s.mu.Lock()
	snapshot := s.pending[row.ID].args
	snapshotOK := snapshot["value"] == float64(1) && snapshot["secret"] == "private-secret"
	s.mu.Unlock()
	if !snapshotOK {
		t.Fatal("preview/edit or caller mutation changed original pending args")
	}
	if err := s.Decide(row.ID, row.Nonce, "edit", map[string]any{"value": "2", "secret": SecretUnchanged}, "", preview.PreviewHash); err != nil {
		t.Fatal(err)
	}
	result := receiveWait(t, call)
	if result.err != nil || result.decision.Args["value"] != "2" || result.decision.Args["secret"] != "private-secret" {
		t.Fatalf("decision=%+v err=%v", result.decision, result.err)
	}
	encoded, err := json.Marshal(result.decision)
	if err != nil || string(encoded) != "{}" || strings.Contains(string(encoded), "private-secret") {
		t.Fatalf("completed internal handoff serialized raw args: %s %v", encoded, err)
	}
	persisted, err := store.List("all", 1)
	if err != nil {
		t.Fatal(err)
	}
	encoded, _ = json.Marshal(persisted)
	if strings.Contains(string(encoded), "private-secret") || persisted[0].Nonce != "" {
		t.Fatal("repository persisted raw secret or nonce")
	}
	requireStatus(t, s.Decide(row.ID, row.Nonce, "approve", nil, "", preview.PreviewHash), 409)
	requireStatus(t, s.Decide(999999, "none", "approve", nil, "", "hash"), 404)
}

func TestServiceDecisionWriteFailureIsFailClosed(t *testing.T) {
	store := testSQLStore(t)
	s := NewService[*testOperation](store, Options{})
	if _, err := store.db.Exec(`CREATE TRIGGER fail_approve BEFORE UPDATE OF status ON approvals WHEN NEW.status='approved' BEGIN SELECT RAISE(FAIL,'injected');END`); err != nil {
		t.Fatal(err)
	}
	var executions atomic.Int32
	call := startWait(s, context.Background(), time.Minute, &testOperation{}, nil, &executions)
	r := pendingRows(t, s, 1)[0]
	requireStatus(t, s.Decide(r.ID, r.Nonce, "approve", nil, "", r.PreviewHash), 500)
	result := receiveWait(t, call)
	if result.err == nil || !strings.Contains(result.err.Error(), "决定保存失败") || executions.Load() != 0 {
		t.Fatal("failed decision persistence granted execution")
	}
	rows, err := store.List("all", 1)
	if err != nil || rows[0].Status != "cancelled" {
		t.Fatalf("fallback cancel=%v err=%v", rows, err)
	}
}

func TestServiceTerminalWriteFailureReleasesStateAndRepairsOrphan(t *testing.T) {
	store := testSQLStore(t)
	s := NewService[*testOperation](store, Options{})
	if _, err := store.db.Exec(`CREATE TRIGGER fail_terminal BEFORE UPDATE OF status ON approvals BEGIN SELECT RAISE(FAIL,'injected');END`); err != nil {
		t.Fatal(err)
	}
	call := startWait(s, context.Background(), 30*time.Millisecond, &testOperation{}, nil, nil)
	r := pendingRows(t, s, 1)[0]
	result := receiveWait(t, call)
	if result.err == nil || !strings.Contains(result.err.Error(), "超时") {
		t.Fatal("timeout persistence error changed cancellation semantics")
	}
	s.mu.Lock()
	live := len(s.pending)
	s.mu.Unlock()
	if live != 0 {
		t.Fatal("failed terminal write retained pending slot")
	}
	var status string
	if err := store.db.QueryRow(`SELECT status FROM approvals WHERE id=?`, r.ID).Scan(&status); err != nil || status != "pending" {
		t.Fatal("failure fixture did not leave an orphan row")
	}
	if _, err := store.db.Exec(`DROP TRIGGER fail_terminal`); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	next := startWait(s, ctx, time.Minute, &testOperation{}, nil, nil)
	pendingRows(t, s, 1)
	if err := store.db.QueryRow(`SELECT status FROM approvals WHERE id=?`, r.ID).Scan(&status); err != nil || status != "cancelled" {
		t.Fatal("next call/poll did not repair orphan")
	}
	cancel()
	if receiveWait(t, next).err == nil {
		t.Fatal("cancelled next call granted execution")
	}
}

func TestServiceShutdownAndExpiredNonce(t *testing.T) {
	quit := make(chan struct{})
	s := NewService[*testOperation](testSQLStore(t), Options{Quit: quit})
	call := startWait(s, context.Background(), time.Minute, &testOperation{}, nil, nil)
	r := pendingRows(t, s, 1)[0]
	expired := NewService[*testOperation](testSQLStore(t), Options{})
	expired.pending[1] = &pending[*testOperation]{record: Record{ID: 1, Status: "pending"}, nonce: "expired", deadline: time.Now().Add(-time.Second)}
	requireStatus(t, expired.Decide(1, "expired", "approve", nil, "", r.PreviewHash), 409)

	close(quit)
	if result := receiveWait(t, call); result.err == nil || !strings.Contains(result.err.Error(), "取消") {
		t.Fatal("shutdown did not cancel waiter")
	}
}

func TestCopyArgsBoundsAndSnapshot(t *testing.T) {
	source := map[string]any{"nested": map[string]any{"number": 1}}
	clone, err := CopyArgs(source)
	if err != nil {
		t.Fatal(err)
	}
	source["nested"].(map[string]any)["number"] = 2
	if !reflect.DeepEqual(clone, map[string]any{"nested": map[string]any{"number": float64(1)}}) {
		t.Fatal("argument copy shares mutable input or changed MCP float64 semantics")
	}
	if _, err := CopyArgs(map[string]any{"large": strings.Repeat("x", vault.MaxScrubBytes)}); err == nil {
		t.Fatal("oversized approval arguments accepted")
	}
	if _, err := CopyArgs(map[string]any{"unsupported": make(chan int)}); err == nil {
		t.Fatal("unserializable arguments accepted")
	}
}
