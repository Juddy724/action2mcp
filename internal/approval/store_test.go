package approval

import (
	"action2mcp/internal/domain"
	"context"
	"testing"
	"time"
)

func TestApprovalRetentionAndOrphanPendingCleanup(t *testing.T) {
	store := testSQLStore(t)
	service := NewService[*testOperation](store, Options{})
	r := Record{TS: now(), Tool: "pending_snapshot", ArgsDisplay: map[string]string{}, Params: []domain.Param{}, Preview: domain.RequestPreview{Headers: map[string]string{}}}
	if err := store.Insert(&r); err != nil {
		t.Fatal(err)
	}
	_, err := store.db.Exec(`WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<1005)
INSERT INTO approvals(ts,tool,tool_id,tool_rev,client,args_display,final_args_display,status,feedback,decided_at,result,title,preview_display,params_json)
SELECT '', 'finished', 0, 1, '', '{}', '{}', 'rejected', '', '', '', '历史快照', '{}', '[]' FROM seq`)
	if err != nil {
		t.Fatal(err)
	}
	last := r
	if err := store.Insert(&last); err != nil {
		t.Fatal(err)
	}
	last.Status = "cancelled"
	last.DecidedAt = now()
	if err := store.Finish(&last); err != nil {
		t.Fatal(err)
	}
	var pending, finished int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM approvals WHERE status='pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM approvals WHERE status<>'pending'`).Scan(&finished); err != nil {
		t.Fatal(err)
	}
	if pending != 1 || finished != 1000 {
		t.Fatal("retention deleted pending or retained too much history")
	}
	for i := 1; i < 20; i++ {
		copy := r
		if err := store.Insert(&copy); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	call := startWait(service, ctx, time.Minute, &testOperation{}, map[string]any{"value": "one"}, nil)
	rows := pendingRows(t, service, 1)
	if rows[0].Nonce == "" {
		t.Fatal("new call did not get a decidable pending approval")
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM approvals WHERE status='pending'`).Scan(&pending); err != nil || pending != 1 {
		t.Fatal("database-only pending rows were not repaired")
	}
	cancel()
	if receiveWait(t, call).err == nil {
		t.Fatal("cancelled call executed")
	}
}
