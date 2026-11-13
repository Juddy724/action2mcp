package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestApprovalStickySourceFloor(t *testing.T) {
	for _, change := range []string{"overwrite_source", "import_without_source", "console_lower", "console_raise_lower"} {
		t.Run(change, func(t *testing.T) {
			a := approvalTestApp(t)
			var hits atomic.Int32
			upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
			a.httpClient = upstream.Client()
			recID, err := a.store.CreateRecording("来源下限测试", upstream.URL)
			if err != nil {
				t.Fatal(err)
			}
			requests := []*ReqRecord{}
			for i := 1; i <= 2; i++ {
				q := &ReqRecord{RecordingID: recID, Seq: i, Method: "GET", URL: fmt.Sprintf("%s/api/%d", upstream.URL, i), ResourceType: "Fetch", Status: 200}
				if err := a.store.InsertRequest(q); err != nil {
					t.Fatal(err)
				}
				requests = append(requests, q)
			}
			pack := &Pack{Name: "来源下限测试包", Enabled: true}
			if err := a.store.SavePack(pack); err != nil {
				t.Fatal(err)
			}
			tool := &Tool{Name: "source_a", Method: "GET", URL: requests[0].URL, SourceReqID: requests[0].ID, Approval: "always"}
			if change == "console_raise_lower" {
				tool.Approval = "off"
			}
			if err := a.store.SaveTool(tool); err != nil {
				t.Fatal(err)
			}
			wantSource := requests[0].ID
			switch change {
			case "overwrite_source":
				if _, bad := a.recSaveTool(nil, map[string]any{"request_id": requests[1].ID, "name": tool.Name, "pack": pack.Name, "overwrite": true}); bad {
					t.Fatal("source overwrite failed")
				}
				wantSource = requests[1].ID
			case "import_without_source":
				file := compactJSON(map[string]any{"format": "action2mcp", "tools": []map[string]any{{"name": tool.Name, "method": "GET", "url": tool.URL, "approval": "off"}}})
				if _, err := a.Import(file); err != nil {
					t.Fatal(err)
				}
			case "console_lower", "console_raise_lower":
				if change == "console_raise_lower" {
					w := approvalAPIRequest(t, a.Handler(), http.MethodPut, fmt.Sprintf("/api/tools/%d", tool.ID), "", "application/json",
						map[string]any{"name": tool.Name, "method": "GET", "url": tool.URL, "approval": "always"})
					requireApprovalAPIResponse(t, w, 200, nil)
				}
				w := approvalAPIRequest(t, a.Handler(), http.MethodPut, fmt.Sprintf("/api/tools/%d", tool.ID), "", "application/json",
					map[string]any{"name": tool.Name, "method": "GET", "url": tool.URL, "approval": "off"})
				requireApprovalAPIResponse(t, w, 200, nil)
			}
			stored, err := a.store.GetTool(tool.ID)
			if err != nil || stored.SourceReqID != wantSource {
				t.Fatal("overwrite lost or failed to update the current source")
			}
			wantPolicy := "always"
			if strings.HasPrefix(change, "console_") {
				wantPolicy = "off"
			}
			if stored.Approval != wantPolicy {
				t.Fatal("overwrite policy is incorrect")
			}
			// Exact review scenario: A moved from R1 to R2, then R1 is saved as B.
			if _, bad := a.recSaveTool(nil, map[string]any{"request_id": requests[0].ID, "name": "approval_call", "pack": pack.Name}); bad {
				t.Fatal("renamed source save failed")
			}
			derived, err := a.store.GetToolByName("approval_call")
			if err != nil || derived.Approval != "always" || derived.SourceReqID != requests[0].ID {
				t.Fatal("MCP rename-save bypassed the sticky source floor")
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			call := startApprovalCall(a, ctx, nil)
			pending := pendingApprovals(t, a, 1)[0]
			if hits.Load() != 0 {
				t.Fatal("derived tool executed before approval")
			}
			approveRecord(t, a, pending)
			if getApprovalReply(t, call).isError || hits.Load() != 1 {
				t.Fatal("approved derived tool did not execute once")
			}
		})
	}
}

func TestApprovalFloorBackfillAndHistoricalSources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "floors.db")
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { s.db.Close() }()
	tool := &Tool{Name: "historical", Method: "GET", URL: "https://example.com/api", SourceReqID: 1, Approval: "always"}
	if err := s.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	// Simulate a pre-floor 0.5.3 database, then backfill twice without lowering it.
	if _, err := s.db.Exec(`DELETE FROM source_approval_floor; DELETE FROM tool_approval_sources`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		s.db.Close()
		s, err = OpenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		var floor string
		if err := s.db.QueryRow(`SELECT approval FROM source_approval_floor WHERE source_request_id=1`).Scan(&floor); err != nil || floor != "always" {
			t.Fatal("backfill lost the persistent floor")
		}
		tool.Approval = "off"
		if err := s.SaveTool(tool); err != nil {
			t.Fatal(err)
		}
	}
	// Console changes can leave the current source with off while a much older
	// source remains always. An MCP overwrite must consult that full history.
	for _, source := range []int64{2, 3} {
		tool.SourceReqID = source
		if err := s.SaveTool(tool); err != nil {
			t.Fatal(err)
		}
	}
	s.db.Close()
	s, err = OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	pack := &Pack{Name: "历史来源包", Enabled: true}
	if err := s.SavePack(pack); err != nil {
		t.Fatal(err)
	}
	tool.Name, tool.SourceReqID = "historical_renamed", 4
	if err := s.SaveToolInPack(tool, pack.ID); err != nil || tool.Approval != "always" {
		t.Fatal("MCP overwrite missed a historical source floor")
	}
	for _, source := range []int64{1, 2, 3, 4} {
		var floor string
		if err := s.db.QueryRow(`SELECT approval FROM source_approval_floor WHERE source_request_id=?`, source).Scan(&floor); err != nil || floor != "always" {
			t.Fatal("write did not raise all involved source floors")
		}
	}
	if err := s.DeleteTool(tool.ID); err != nil {
		t.Fatal(err)
	}
	derived := &Tool{Name: "after_delete", Method: "GET", URL: tool.URL, SourceReqID: 1}
	if err := s.SaveToolInPack(derived, pack.ID); err != nil || derived.Approval != "always" {
		t.Fatal("deleting a tool erased its source floor")
	}
	imported := &Tool{Name: "import_with_source", Method: "GET", URL: tool.URL, SourceReqID: 1, Approval: "off"}
	if _, err := s.ImportTool(imported); err != nil || imported.Approval != "always" {
		t.Fatal("new import ignored a source floor")
	}
	for _, source := range []int64{0, -1} {
		plain := &Tool{Name: fmt.Sprintf("no_source_%d", -source), Method: "GET", URL: tool.URL, SourceReqID: source, Approval: "always"}
		if err := s.SaveTool(plain); err != nil {
			t.Fatal(err)
		}
	}
	var invalid int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM source_approval_floor WHERE source_request_id<=0`).Scan(&invalid); err != nil || invalid != 0 {
		t.Fatal("nonpositive source IDs participated in the floor")
	}
}

func TestApprovalOverwriteTargetByID(t *testing.T) {
	for _, renamed := range []bool{false, true} {
		t.Run(fmt.Sprint(renamed), func(t *testing.T) {
			a := approvalTestApp(t)
			tool := &Tool{Name: "old", Method: "GET", URL: "https://example.com/api", Approval: "always"}
			if err := a.store.SaveTool(tool); err != nil {
				t.Fatal(err)
			}
			pack := &Pack{Name: "覆盖目标包", Enabled: true}
			if err := a.store.SavePack(pack); err != nil {
				t.Fatal(err)
			}
			incoming := &Tool{ID: tool.ID, Name: "new", Method: "GET", URL: tool.URL}
			if renamed {
				incoming.Name = "old" // ID/name were resolved before the console rename.
				tool.Name = "console_renamed"
				if err := a.persistTool(tool); err != nil {
					t.Fatal(err)
				}
			}
			if err := a.store.SaveToolInPack(incoming, pack.ID); err != nil || incoming.Approval != "always" {
				t.Fatal("overwrite lost the approval of its ID target")
			}
			stored, err := a.store.GetTool(tool.ID)
			if err != nil || stored.Name != incoming.Name || stored.Approval != "always" {
				t.Fatal("ID target was not updated safely")
			}
		})
	}
}

func TestApprovalRecSaveMidflightRename(t *testing.T) {
	a := approvalTestApp(t)
	tool := &Tool{Name: "old", Method: "GET", URL: "https://example.com/api", Approval: "always"}
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	pack := &Pack{Name: "交错重命名包", Enabled: true}
	if err := a.store.SavePack(pack); err != nil {
		t.Fatal(err)
	}
	recID, err := a.store.CreateRecording("交错重命名", tool.URL)
	if err != nil {
		t.Fatal(err)
	}
	q := &ReqRecord{RecordingID: recID, Seq: 1, Method: "GET", URL: tool.URL, ResourceType: "Fetch", Status: 200}
	if err := a.store.InsertRequest(q); err != nil {
		t.Fatal(err)
	}
	// EnsureSite runs after rec_save_tool's name lookup but before its write tx.
	// A trigger makes this interleaving deterministic without sleeps or hooks.
	if _, err := a.store.db.Exec(fmt.Sprintf(`CREATE TRIGGER rename_during_save AFTER INSERT ON sites BEGIN UPDATE tools SET name='console_renamed',rev=rev+1 WHERE id=%d; END`, tool.ID)); err != nil {
		t.Fatal(err)
	}
	if _, bad := a.recSaveTool(nil, map[string]any{"request_id": q.ID, "name": "old", "pack": pack.Name, "overwrite": true}); bad {
		t.Fatal("interleaved rec_save_tool overwrite failed")
	}
	stored, err := a.store.GetTool(tool.ID)
	if err != nil || stored.Name != "old" || stored.Rev != 3 || stored.Approval != "always" || stored.SourceReqID != q.ID {
		t.Fatal("mid-flight rename bypassed the target's approval")
	}
}

func TestApprovalUnquotedSecretAPIAndHistory(t *testing.T) {
	for _, input := range []string{"number", "string"} {
		t.Run(input, func(t *testing.T) {
			a := approvalTestApp(t)
			a.cfg.Port = 19000
			handler := a.Handler()
			origin := "http://127.0.0.1:19000"
			n, err := strconv.ParseUint(privateTestValue(t)[:12], 16, 48)
			if err != nil {
				t.Fatal("cannot create private numeric value")
			}
			secret := strconv.FormatUint(n, 10)
			replacement := strconv.FormatUint(n+1, 10)
			var got atomic.Bool
			upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				got.Store(strings.Contains(string(body), `"password":`+replacement))
				w.Write(body)
			}))
			tool, _ := saveApprovalTool(t, a, upstream, "always")
			tool.Body = `{"password":{{label}},"value":"{{value}}"}`
			tool.Params = append(tool.Params, Param{Name: "label", Type: "integer", Required: true})
			if !paramIsSecret(tool, tool.Params[1]) {
				t.Fatal("unquoted renamed integer secret was missed")
			}
			if err := a.store.SaveTool(tool); err != nil {
				t.Fatal(err)
			}
			var value any = float64(n)
			if input == "string" {
				value = secret
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			call := startApprovalCall(a, ctx, map[string]any{"value": "old", "label": value})
			pendingApprovals(t, a, 1)
			pending := listApprovalAPI(t, handler, origin, "pending")[0]
			if pending.ArgsDisplay["label"] != secretMask || !pending.Params[1].Secret {
				t.Fatal("unquoted secret leaked into card fields")
			}
			diff := map[string]any{"label": replacement}
			w := approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/approvals/%d/preview", pending.ID), origin, "application/json", map[string]any{"args": diff, "nonce": pending.Nonce})
			var preview ApprovalPreview
			requireApprovalAPIResponse(t, w, 200, &preview)
			w = approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/approvals/%d/decide", pending.ID), origin, "application/json",
				map[string]any{"action": "edit", "args": diff, "nonce": pending.Nonce, "preview_hash": preview.PreviewHash})
			requireApprovalAPIResponse(t, w, 200, nil)
			reply := getApprovalReply(t, call)
			if reply.isError || !got.Load() || !strings.Contains(reply.text, "修改的参数：label）") {
				t.Fatal("unquoted secret edit failed or its prefix included a value")
			}
			history := listApprovalAPI(t, handler, origin, "all")
			var stored string
			if err := a.store.db.QueryRow(`SELECT args_display || final_args_display || preview_display || params_json || result FROM approvals WHERE id=?`, pending.ID).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			all := string(compactJSON(pending)) + string(compactJSON(preview)) + string(compactJSON(history)) + reply.text + stored
			if strings.Contains(all, secret) || strings.Contains(all, replacement) {
				t.Fatal("raw unquoted secret leaked into approval output")
			}
		})
	}
}

func TestApprovalPartialEditsKeepOriginalVerbatimArgs(t *testing.T) {
	a := approvalTestApp(t)
	secret := privateTestValue(t)
	if err := a.vault.Upsert("partial", "secret", secret, "", ""); err != nil {
		t.Fatal(err)
	}
	original := "before-" + secret + "-after"
	received := make(chan map[string]any, 1)
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(400)
			return
		}
		received <- body
	}))
	tool, _ := saveApprovalTool(t, a, upstream, "always")
	tool.Body = `{"value":"{{value}}","count":{{count}}}`
	tool.Params = append(tool.Params, Param{Name: "count", Type: "integer", Required: true})
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	call := startApprovalCall(a, ctx, map[string]any{"value": original, "count": 1, "extra": "original"})
	r := pendingApprovals(t, a, 1)[0]
	if r.Params[0].Secret || r.ArgsDisplay["value"] != original {
		t.Fatal("non-secret parameter must be displayed verbatim")
	}
	requirePrivateApprovalValuesAbsent(t, r.Preview, secret)
	unchanged, err := a.PreviewApproval(r.ID, r.Nonce, nil)
	if err != nil || unchanged.PreviewHash != r.PreviewHash {
		t.Fatal("empty preview diff did not preserve originals")
	}
	diff := map[string]any{"count": "2"}
	preview, err := a.PreviewApproval(r.ID, r.Nonce, diff)
	if err != nil {
		t.Fatal("partial preview failed")
	}
	a.approvalMu.Lock()
	p := a.approvals[r.ID]
	merged, err := a.editApprovalArgs(p, diff)
	unchangedOriginal := p.args["count"] == float64(1) && p.args["value"] == original
	a.approvalMu.Unlock()
	if err != nil || !unchangedOriginal || merged["value"] != original || merged["extra"] != "original" {
		t.Fatal("partial merge lost or mutated an original argument")
	}
	expected, err := a.Prepare(tool, map[string]any{"value": original, "count": "2", "extra": "original"})
	if err != nil || expected.PreviewHash != preview.PreviewHash {
		t.Fatal("preview did not merge the partial edit with raw originals")
	}
	if err := a.DecideApproval(r.ID, r.Nonce, "edit", diff, "", preview.PreviewHash); err != nil {
		t.Fatal("partial decision failed")
	}
	if getApprovalReply(t, call).isError {
		t.Fatal("partially edited call failed")
	}
	body := <-received
	if body["value"] != original || body["count"] != float64(2) {
		t.Fatal("untouched parameter was not preserved verbatim")
	}
}

func TestApprovalTerminalWriteFailureRepairsOrphan(t *testing.T) {
	for _, repair := range []string{"list", "next_call"} {
		t.Run(repair, func(t *testing.T) {
			a := approvalTestApp(t)
			a.approvalTimeout = 150 * time.Millisecond
			var hits atomic.Int32
			saveApprovalTool(t, a, newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) })), "always")
			if _, err := a.store.db.Exec(`CREATE TRIGGER fail_terminal BEFORE UPDATE OF status ON approvals WHEN OLD.status='pending' BEGIN SELECT RAISE(FAIL,'injected terminal failure'); END`); err != nil {
				t.Fatal(err)
			}
			call := startApprovalCall(a, context.Background(), map[string]any{"value": "one"})
			r := pendingApprovals(t, a, 1)[0]
			if reply := getApprovalReply(t, call); !reply.isError || !strings.Contains(reply.text, "审批超时") || hits.Load() != 0 {
				t.Fatal("terminal write failure changed the timeout result")
			}
			var status string
			if err := a.store.db.QueryRow(`SELECT status FROM approvals WHERE id=?`, r.ID).Scan(&status); err != nil || status != "pending" {
				t.Fatal("fixture did not leave a failed terminal write")
			}
			requireApprovalStatus(t, a.DecideApproval(r.ID, r.Nonce, "approve", nil, "", r.PreviewHash), 409)
			if _, err := a.store.db.Exec(`DROP TRIGGER fail_terminal`); err != nil {
				t.Fatal(err)
			}
			if repair == "list" {
				pendingApprovals(t, a, 0)
			}
			a.approvalTimeout = time.Minute
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls := []<-chan approvalReply{startApprovalCall(a, ctx, map[string]any{"value": "new"})}
			// Observe memory directly so the next_call case cannot be repaired by List.
			deadline := time.Now().Add(5 * time.Second)
			for {
				a.approvalMu.Lock()
				live := len(a.approvals)
				a.approvalMu.Unlock()
				if live == 1 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("new call was blocked by an orphan")
				}
				time.Sleep(time.Millisecond)
			}
			if err := a.store.db.QueryRow(`SELECT status FROM approvals WHERE id=?`, r.ID).Scan(&status); err != nil || status != "cancelled" {
				t.Fatal("orphan pending row was not repaired")
			}
			for i := 1; i < maxPendingApprovals; i++ {
				calls = append(calls, startApprovalCall(a, ctx, map[string]any{"value": "new"}))
			}
			pendingApprovals(t, a, maxPendingApprovals)
			extra := getApprovalReply(t, startApprovalCall(a, ctx, map[string]any{"value": "extra"}))
			if !extra.isError || !strings.Contains(extra.text, "待审批调用过多") {
				t.Fatal("live pending cap was not enforced")
			}
			cancel()
			for _, call := range calls {
				getApprovalReply(t, call)
			}
			requireApprovalStatus(t, a.DecideApproval(r.ID, r.Nonce, "approve", nil, "", r.PreviewHash), 409)
			if hits.Load() != 0 {
				t.Fatal("orphan repair or cancellation executed a request")
			}
		})
	}
}

func TestApprovalConsoleFieldPresence(t *testing.T) {
	a := approvalTestApp(t)
	handler := a.Handler()
	base := map[string]any{"name": "presence", "method": "POST", "url": "https://example.com/api"}
	var tool Tool
	w := approvalAPIRequest(t, handler, http.MethodPost, "/api/tools", "", "application/json", base)
	requireApprovalAPIResponse(t, w, 200, &tool)
	if tool.Approval != "always" {
		t.Fatal("omitted create approval did not use the method default")
	}
	for _, endpoint := range []struct{ method, path string }{
		{http.MethodPost, "/api/tools"}, {http.MethodPut, fmt.Sprintf("/api/tools/%d", tool.ID)},
	} {
		for _, value := range []any{"", nil, "invalid"} {
			base["approval"] = value
			w = approvalAPIRequest(t, handler, endpoint.method, endpoint.path, "", "application/json", base)
			requireApprovalAPIResponse(t, w, 400, nil)
		}
	}
	delete(base, "approval")
	base["method"] = "GET"
	w = approvalAPIRequest(t, handler, http.MethodPut, fmt.Sprintf("/api/tools/%d", tool.ID), "", "application/json", base)
	requireApprovalAPIResponse(t, w, 200, &tool)
	if tool.Approval != "always" {
		t.Fatal("omitted update approval did not preserve the existing value")
	}
	base["approval"] = "off"
	w = approvalAPIRequest(t, handler, http.MethodPut, fmt.Sprintf("/api/tools/%d", tool.ID), "", "application/json", base)
	requireApprovalAPIResponse(t, w, 200, &tool)
	if tool.Approval != "off" {
		t.Fatal("explicit console downgrade was rejected")
	}
}

func TestApprovalDocumentation(t *testing.T) {
	for _, path := range []string{"README.md", "packaging/README.tmpl.md"} {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range []string{"审批模式", "off", "always", "写入工具默认", "待审批卡片", "等待超时", "接入 AI / 设置", "通过 MCP", "localhost HTTP", "伪造请求", "已经发出后无法撤回", "MCP 会话 DELETE", "stdio 桥退出不保证取消", "拒绝或超时", "大整数精度", "float64"} {
			if !strings.Contains(string(b), required) {
				t.Fatalf("%s is missing approval documentation for %s", path, required)
			}
		}
		if path == "README.md" && !strings.Contains(string(b), "| 平台 | 安装包 (v0.5.11) |") {
			t.Fatal("download table version is not 0.5.11")
		}
	}
}
