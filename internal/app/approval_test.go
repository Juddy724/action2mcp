package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Keep HTTP encoding and redirects while exercising handlers without listening sockets.
type approvalTarget struct {
	URL     string
	handler http.Handler
}

type approvalRoundTripper func(*http.Request) (*http.Response, error)

func (f approvalRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func newApprovalTarget(handler http.Handler) *approvalTarget {
	return &approvalTarget{URL: "http://127.0.0.1:19001", handler: handler}
}

func (s *approvalTarget) Client() *http.Client {
	return &http.Client{Transport: approvalRoundTripper(func(r *http.Request) (*http.Response, error) {
		w := httptest.NewRecorder()
		s.handler.ServeHTTP(w, r)
		response := w.Result()
		response.Request = r
		return response, nil
	})}
}

func approvalTestApp(t *testing.T) *App {
	t.Helper()
	a, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a.cfg.Browser = "missing-approval-test-browser"
	a.store.ReplaceCookies([]Cookie{{Name: "test_cookie", Value: "ok", Domain: "127.0.0.1", Path: "/", Session: true}})
	t.Cleanup(a.Shutdown)
	return a
}

func privateTestValue(t *testing.T) string {
	t.Helper()
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal("cannot create test value")
	}
	return hex.EncodeToString(b[:])
}

func saveApprovalTool(t *testing.T, a *App, upstream *approvalTarget, policy string) (*Tool, *Pack) {
	t.Helper()
	a.httpClient = upstream.Client()
	tool := &Tool{Name: "approval_call", Title: "审批测试", Method: "POST", URL: upstream.URL + "/api", Approval: policy,
		Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"value":"{{value}}"}`,
		Params: []Param{{Name: "value", Type: "string", Required: true}}}
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	pack := &Pack{Name: "审批测试包", Enabled: true, ToolIDs: []int64{tool.ID}}
	if err := a.store.SavePack(pack); err != nil {
		t.Fatal(err)
	}
	return tool, pack
}

type approvalReply struct {
	text    string
	isError bool
	rpc     *rpcErr
}

func unpackApprovalReply(v any, rpc *rpcErr) approvalReply {
	if rpc != nil {
		return approvalReply{rpc: rpc}
	}
	r := v.(map[string]any)
	bad, _ := r["isError"].(bool)
	return approvalReply{text: r["content"].([]map[string]any)[0]["text"].(string), isError: bad}
}

func startApprovalCall(a *App, ctx context.Context, args map[string]any) <-chan approvalReply {
	done := make(chan approvalReply, 1)
	go func() {
		v, err := a.invokeTool(ctx, &mcpCtx{}, "approval_call", args)
		done <- unpackApprovalReply(v, err)
	}()
	return done
}

func getApprovalReply(t *testing.T, done <-chan approvalReply) approvalReply {
	t.Helper()
	select {
	case r := <-done:
		if r.rpc != nil {
			t.Fatal("unexpected RPC error")
		}
		return r
	case <-time.After(5 * time.Second):
		t.Fatal("tool call did not finish")
		return approvalReply{}
	}
}

func pendingApprovals(t *testing.T, a *App, count int) []ApprovalRecord {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		rows, err := a.ListApprovals("pending", 1000)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == count {
			return rows
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("pending approvals did not reach expected count")
	return nil
}

func requireApprovalStatus(t *testing.T, err error, status int) {
	t.Helper()
	var ae *ApprovalError
	if !errors.As(err, &ae) || ae.Status != status {
		t.Fatalf("expected approval error %d", status)
	}
}

func approveRecord(t *testing.T, a *App, r ApprovalRecord) {
	t.Helper()
	if err := a.DecideApproval(r.ID, r.Nonce, "approve", nil, "", r.PreviewHash); err != nil {
		t.Fatal(err)
	}
}

func TestApprovalOffAndConcurrentApprove(t *testing.T) {
	var hits atomic.Int32
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); io.WriteString(w, "ok") }))
	a := approvalTestApp(t)
	tool, _ := saveApprovalTool(t, a, upstream, "off")
	if r := getApprovalReply(t, startApprovalCall(a, context.Background(), map[string]any{"value": "one"})); r.isError {
		t.Fatal("off call failed")
	}
	if _, err := a.Execute(tool, map[string]any{"value": "two"}); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 2 {
		t.Fatal("off calls did not execute immediately")
	}
	rows, err := a.ListApprovals("all", 100)
	if err != nil || len(rows) != 0 {
		t.Fatal("off created approvals")
	}
	tool.Approval = "always"
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	calls := []<-chan approvalReply{}
	for i := 0; i < 3; i++ {
		calls = append(calls, startApprovalCall(a, context.Background(), map[string]any{"value": "next"}))
	}
	rows = pendingApprovals(t, a, 3)
	if hits.Load() != 2 {
		t.Fatal("request sent before approval")
	}
	for _, r := range rows {
		approveRecord(t, a, r)
	}
	for _, call := range calls {
		if getApprovalReply(t, call).isError {
			t.Fatal("approved call failed")
		}
	}
	if hits.Load() != 5 {
		t.Fatal("approved calls did not execute exactly once")
	}
	for _, r := range rows {
		requireApprovalStatus(t, a.DecideApproval(r.ID, r.Nonce, "approve", nil, "", r.PreviewHash), 409)
	}
}

func TestApprovalRejectAndRetry(t *testing.T) {
	var hits atomic.Int32
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	a := approvalTestApp(t)
	saveApprovalTool(t, a, upstream, "always")
	call := startApprovalCall(a, context.Background(), map[string]any{"value": "one"})
	r := pendingApprovals(t, a, 1)[0]
	requireApprovalStatus(t, a.DecideApproval(r.ID, "wrong", "approve", nil, "", r.PreviewHash), 403)
	requireApprovalStatus(t, a.DecideApproval(r.ID, r.Nonce, "reject", nil, " \t ", ""), 400)
	requireApprovalStatus(t, a.DecideApproval(r.ID, r.Nonce, "approve", nil, "", ""), 400)
	requireApprovalStatus(t, a.DecideApproval(r.ID, r.Nonce, "approve", nil, "", "stale"), 409)
	requireApprovalStatus(t, a.DecideApproval(r.ID, r.Nonce, "unknown", nil, "", ""), 400)
	pendingApprovals(t, a, 1)
	feedback := "请把范围缩小 <img src=x>"
	if err := a.DecideApproval(r.ID, r.Nonce, "reject", nil, feedback, ""); err != nil {
		t.Fatal(err)
	}
	reply := getApprovalReply(t, call)
	if !reply.isError || !strings.Contains(reply.text, feedback) || !strings.Contains(reply.text, "再次调用") {
		t.Fatal("reject feedback missing")
	}
	if hits.Load() != 0 {
		t.Fatal("rejected call executed")
	}
	call = startApprovalCall(a, context.Background(), map[string]any{"value": "smaller"})
	next := pendingApprovals(t, a, 1)[0]
	if next.ID == r.ID {
		t.Fatal("retry reused old approval")
	}
	approveRecord(t, a, next)
	if getApprovalReply(t, call).isError || hits.Load() != 1 {
		t.Fatal("retry was not executed once")
	}
}

func TestApprovalEditAndSecretSnapshots(t *testing.T) {
	for _, keep := range []bool{true, false} {
		t.Run(map[bool]string{true: "keep", false: "replace"}[keep], func(t *testing.T) {
			original, replacement := privateTestValue(t), privateTestValue(t)
			received := make(chan map[string]any, 1)
			upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if json.NewDecoder(r.Body).Decode(&body) != nil {
					w.WriteHeader(400)
					return
				}
				received <- body
				w.Header().Set("X-Result", replacement)
				w.Write(compactJSON(body))
			}))
			a := approvalTestApp(t)
			tool, _ := saveApprovalTool(t, a, upstream, "always")
			tool.Body = `{"value":"{{value}}","credentials":{"value":"{{label}}"},"count":"{{count}}"}`
			tool.Params = append(tool.Params, Param{Name: "label", Type: "string", Required: true}, Param{Name: "count", Type: "number", Required: true})
			if err := a.store.SaveTool(tool); err != nil {
				t.Fatal(err)
			}
			call := startApprovalCall(a, context.Background(), map[string]any{"value": "old", "label": original, "count": 1})
			r := pendingApprovals(t, a, 1)[0]
			if r.ArgsDisplay["label"] != secretMask || !r.Params[1].Secret {
				t.Fatal("renamed secret was not masked")
			}
			_, previewErr := a.PreviewApproval(r.ID, "wrong", nil)
			requireApprovalStatus(t, previewErr, 403)
			requireApprovalStatus(t, a.DecideApproval(r.ID, r.Nonce, "edit", map[string]any{"count": nil}, "", r.PreviewHash), 400)
			pendingApprovals(t, a, 1)
			label := replacement
			if keep {
				label = ApprovalSecretUnchanged
			}
			edited := map[string]any{"value": "new", "label": label, "count": "2"}
			preview, err := a.PreviewApproval(r.ID, r.Nonce, edited)
			if err != nil {
				t.Fatal("edit preview failed")
			}
			if preview.PreviewHash == r.PreviewHash {
				t.Fatal("edit did not change hash")
			}
			if err := a.DecideApproval(r.ID, r.Nonce, "edit", edited, "", preview.PreviewHash); err != nil {
				t.Fatal("edit decision failed")
			}
			reply := getApprovalReply(t, call)
			if reply.isError || !strings.Contains(reply.text, "用户修改了参数") || !strings.Contains(reply.text, "value：new") {
				t.Fatal("edited result missing prefix")
			}
			body := <-received
			expected := replacement
			if keep {
				expected = original
			}
			if body["value"] != "new" || body["count"] != float64(2) || body["credentials"].(map[string]any)["value"] != expected {
				t.Fatal("edited request or secret not forwarded correctly")
			}
			if strings.Contains(reply.text, original) || strings.Contains(reply.text, replacement) {
				t.Fatal("secret leaked in result")
			}
			if err := a.store.DeleteTool(tool.ID); err != nil {
				t.Fatal(err)
			}
			history, err := a.ListApprovals("all", 100)
			if err != nil || len(history) != 1 || history[0].Title != r.Title || history[0].Nonce != "" || len(history[0].Params) != 3 {
				t.Fatal("history lost its snapshots")
			}
			var stored string
			if err := a.store.db.QueryRow(`SELECT args_display || final_args_display || preview_display || params_json || result FROM approvals WHERE id=?`, r.ID).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			blob := stored + string(compactJSON(history)) + string(compactJSON(preview))
			if strings.Contains(blob, original) || strings.Contains(blob, replacement) || strings.Contains(stored, r.Nonce) {
				t.Fatal("secret or nonce leaked into persisted approval")
			}
		})
	}
}

func TestApprovalTimeoutCancelAndShutdown(t *testing.T) {
	for _, mode := range []string{"timeout", "cancelled", "shutdown"} {
		t.Run(mode, func(t *testing.T) {
			var hits atomic.Int32
			upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
			a := approvalTestApp(t)
			a.approvalTimeout = 200 * time.Millisecond
			saveApprovalTool(t, a, upstream, "always")
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			call := startApprovalCall(a, ctx, map[string]any{"value": "one"})
			r := pendingApprovals(t, a, 1)[0]
			if mode == "cancelled" {
				cancel()
			}
			if mode == "shutdown" {
				a.Shutdown()
			}
			reply := getApprovalReply(t, call)
			if !reply.isError || hits.Load() != 0 {
				t.Fatal("cancelled or timed out call executed")
			}
			expected := mode
			if mode == "shutdown" {
				expected = "cancelled"
			}
			rows, err := a.ListApprovals("all", 10)
			if err != nil || len(rows) != 1 || rows[0].Status != expected {
				t.Fatal("wrong final approval status")
			}
			if mode == "timeout" && !strings.Contains(reply.text, "审批超时，未执行。如需继续请再次调用。") {
				t.Fatal("timeout message missing")
			}
			requireApprovalStatus(t, a.DecideApproval(r.ID, r.Nonce, "approve", nil, "", r.PreviewHash), 409)
		})
	}
}

func TestApprovalSecretClassificationFrozen(t *testing.T) {
	a := approvalTestApp(t)
	original, replacement := privateTestValue(t), privateTestValue(t)
	if err := a.vault.Upsert("rotating", "plain", original, "", ""); err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 1)
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		received <- body["label"]
		io.WriteString(w, body["label"])
	}))
	tool, _ := saveApprovalTool(t, a, upstream, "always")
	tool.Body = `{"value":"{{value}}","label":"{{label}}"}`
	tool.Params = append(tool.Params, Param{Name: "label", Type: "string", Required: true})
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	call := startApprovalCall(a, context.Background(), map[string]any{"value": "old", "label": original})
	r := pendingApprovals(t, a, 1)[0]
	if !r.Params[1].Secret {
		t.Fatal("vault plaintext was not marked sensitive")
	}
	if err := a.vault.Upsert("rotating", "plain", replacement, "", ""); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"value": "new", "label": ApprovalSecretUnchanged}
	preview, err := a.PreviewApproval(r.ID, r.Nonce, args)
	if err != nil {
		t.Fatal("secret classification changed during preview")
	}
	if err := a.DecideApproval(r.ID, r.Nonce, "edit", args, "", preview.PreviewHash); err != nil {
		t.Fatal("secret classification changed during decision")
	}
	reply := getApprovalReply(t, call)
	if reply.isError || <-received != original || strings.Contains(reply.text, original) {
		t.Fatal("original secret was not preserved or leaked")
	}
	rows, err := a.ListApprovals("all", 10)
	if err != nil || strings.Contains(string(compactJSON(rows)), original) {
		t.Fatal("rotated secret leaked in history")
	}
}

func TestApprovalResultWriteFailureDoesNotChangeCall(t *testing.T) {
	a := approvalTestApp(t)
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "executed") }))
	saveApprovalTool(t, a, upstream, "always")
	if _, err := a.store.db.Exec(`CREATE TRIGGER fail_approval_result BEFORE UPDATE OF result ON approvals WHEN OLD.status='approved' BEGIN SELECT RAISE(FAIL,'injected result failure'); END`); err != nil {
		t.Fatal(err)
	}
	call := startApprovalCall(a, context.Background(), map[string]any{"value": "one"})
	r := pendingApprovals(t, a, 1)[0]
	approveRecord(t, a, r)
	if reply := getApprovalReply(t, call); reply.isError || !strings.Contains(reply.text, "executed") {
		t.Fatal("audit failure changed the executed result")
	}
}

func TestApprovalCompetingDecisionsAndPersistFailure(t *testing.T) {
	var hits atomic.Int32
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	a := approvalTestApp(t)
	saveApprovalTool(t, a, upstream, "always")
	for i := 0; i < 12; i++ {
		before := hits.Load()
		ctx, cancel := context.WithCancel(context.Background())
		call := startApprovalCall(a, ctx, map[string]any{"value": "one"})
		r := pendingApprovals(t, a, 1)[0]
		a.approvalMu.Lock()
		p := a.approvals[r.ID]
		a.approvalMu.Unlock()
		var wg sync.WaitGroup
		for _, action := range []func(){
			func() { a.DecideApproval(r.ID, r.Nonce, "approve", nil, "", r.PreviewHash) },
			func() { a.DecideApproval(r.ID, r.Nonce, "reject", nil, "请重试", "") },
			func() { a.endPending(p, "timeout") },
			cancel,
		} {
			wg.Add(1)
			go func(fn func()) { defer wg.Done(); fn() }(action)
		}
		wg.Wait()
		getApprovalReply(t, call)
		rows, err := a.ListApprovals("all", 1)
		if err != nil || len(rows) != 1 || rows[0].Status == "pending" {
			t.Fatal("race left pending approval")
		}
		expected := int32(0)
		if rows[0].Status == "approved" {
			expected = 1
		}
		if hits.Load()-before != expected {
			t.Fatal("decision race executed more than the winner")
		}
	}
	before := hits.Load()
	a.approvalDecideHook = func() error { return errors.New("injected write failure") }
	call := startApprovalCall(a, context.Background(), map[string]any{"value": "one"})
	r := pendingApprovals(t, a, 1)[0]
	requireApprovalStatus(t, a.DecideApproval(r.ID, r.Nonce, "approve", nil, "", r.PreviewHash), 500)
	if reply := getApprovalReply(t, call); !reply.isError || !strings.Contains(reply.text, "未执行") {
		t.Fatal("persist failure was not fail-closed")
	}
	if hits.Load() != before {
		t.Fatal("failed decision write executed")
	}
}

func TestApprovalLimitsAndInsertFailure(t *testing.T) {
	var hits atomic.Int32
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	a := approvalTestApp(t)
	saveApprovalTool(t, a, upstream, "always")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := []<-chan approvalReply{}
	for i := 0; i < 20; i++ {
		calls = append(calls, startApprovalCall(a, ctx, map[string]any{"value": "one"}))
	}
	pendingApprovals(t, a, 20)
	if reply := getApprovalReply(t, startApprovalCall(a, ctx, map[string]any{"value": "extra"})); !reply.isError || !strings.Contains(reply.text, "待审批") {
		t.Fatal("21st pending call was accepted")
	}
	cancel()
	for _, call := range calls {
		getApprovalReply(t, call)
	}
	pendingApprovals(t, a, 0)
	oversized := map[string]any{"value": strings.Repeat("x", maxApprovalArgs+1)}
	if reply := getApprovalReply(t, startApprovalCall(a, context.Background(), oversized)); !reply.isError || reply.text != "参数过大，无法审批，未执行" {
		t.Fatal("oversized call was accepted")
	}
	a.approvalInsertHook = func() error { return errors.New("injected insert failure") }
	if reply := getApprovalReply(t, startApprovalCall(a, context.Background(), map[string]any{"value": "one"})); !reply.isError || reply.text != "审批记录保存失败，未执行" {
		t.Fatal("failed insert was not fail-closed")
	}
	if hits.Load() != 0 {
		t.Fatal("limited call executed")
	}
}

func TestApprovalTieredCallUsesGate(t *testing.T) {
	var hits atomic.Int32
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	a := approvalTestApp(t)
	saveApprovalTool(t, a, upstream, "always")
	done := make(chan approvalReply, 1)
	go func() {
		params := compactJSON(map[string]any{"name": "call_pack_tool", "arguments": map[string]any{"tool": "approval_call", "arguments": map[string]any{"value": "one"}}})
		res, err := a.dispatchMCP(context.Background(), rpcReq{Method: "tools/call", Params: params}, &mcpCtx{})
		done <- unpackApprovalReply(res, err)
	}()
	r := pendingApprovals(t, a, 1)[0]
	if hits.Load() != 0 {
		t.Fatal("tiered call bypassed approval")
	}
	approveRecord(t, a, r)
	if getApprovalReply(t, done).isError || hits.Load() != 1 {
		t.Fatal("tiered approved call failed")
	}
	for _, def := range a.toolList(nil) {
		if strings.Contains(def["name"].(string), "approval") {
			t.Fatal("approval tool exposed to MCP")
		}
	}
}
