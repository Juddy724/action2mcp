package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestApprovalMigrationAndDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v5.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE tools(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, title TEXT, description TEXT, method TEXT, url TEXT, headers TEXT, body TEXT, params TEXT, cred_headers TEXT, source_request_id INTEGER, created_at TEXT, updated_at TEXT);
INSERT INTO tools(name,title,description,method,url,headers,body,params,cred_headers,source_request_id,created_at,updated_at) VALUES('legacy','旧工具','','POST','https://example.com/api','{}','','[]','[]',0,'','');
PRAGMA user_version=5;`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		s, err := OpenStore(path)
		if err != nil {
			t.Fatal(err)
		}
		if !s.hasColumn("tools", "approval") || !s.hasColumn("tools", "rev") || !s.hasColumn("tools", "config") {
			t.Fatal("schema columns missing")
		}
		old, err := s.GetToolByName("legacy")
		if err != nil || old.Approval != "off" || old.Rev != 1 {
			t.Fatal("migration changed old tool policy or revision")
		}
		var version int
		if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != 8 {
			t.Fatal("wrong schema version")
		}
		s.db.Close()
	}
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.db.Close()
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "WS"} {
		tool := &Tool{Name: "tool_" + method, Method: method, URL: "https://example.com/api"}
		if err := s.SaveTool(tool); err != nil {
			t.Fatal(err)
		}
		want := "off"
		if method == "POST" || method == "PUT" || method == "PATCH" || method == "DELETE" || method == "WS" {
			want = "always"
		}
		if tool.Approval != want || tool.Rev != 1 {
			t.Fatal("new method policy or revision incorrect")
		}
		tool.SourceReqID = 42
		if err := s.SaveTool(tool); err != nil {
			t.Fatal(err)
		}
		stored, err := s.GetTool(tool.ID)
		if err != nil || stored.Rev != 2 || stored.SourceReqID != 42 {
			t.Fatal("overwrite did not update source and revision")
		}
	}
	for _, tc := range []struct {
		value string
		want  time.Duration
	}{
		{"", 300 * time.Second}, {"bad", 300 * time.Second}, {"1", 30 * time.Second}, {"450", 450 * time.Second}, {"9000", 1800 * time.Second},
	} {
		if err := s.SetSetting("approval_timeout_secs", tc.value); err != nil {
			t.Fatal(err)
		}
		if s.ApprovalTimeout() != tc.want {
			t.Fatal("timeout setting was not clamped")
		}
	}
}

func TestApprovalPolicyConsoleMCPAndImport(t *testing.T) {
	a := approvalTestApp(t)
	recID, err := a.store.CreateRecording("策略测试", "https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	q := &ReqRecord{RecordingID: recID, Seq: 1, Method: "GET", URL: "https://example.com/api?value=one", ResourceType: "Fetch", Status: 200}
	if err := a.store.InsertRequest(q); err != nil {
		t.Fatal(err)
	}
	pack := &Pack{Name: "策略测试包", Enabled: true}
	if err := a.store.SavePack(pack); err != nil {
		t.Fatal(err)
	}
	tool := &Tool{Name: "from_recording", Method: "GET", URL: q.URL, SourceReqID: q.ID, Approval: "always"}
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"from_recording", "renamed_recording"} {
		_, bad := a.recSaveTool(nil, map[string]any{"request_id": q.ID, "pack": pack.Name, "name": name, "overwrite": true, "approval": "off"})
		if bad {
			t.Fatal("MCP tool save failed")
		}
		stored, err := a.store.GetToolByName(name)
		if err != nil || stored.Approval != "always" || stored.SourceReqID != q.ID {
			t.Fatal("MCP lowered policy on overwrite or rename")
		}
	}
	current, err := a.store.GetToolByName(tool.Name)
	if err != nil || current.Rev != 2 {
		t.Fatal("MCP overwrite did not increment revision")
	}
	if _, err := a.Import([]byte(`{"format":"action2mcp","tools":[{"name":"from_recording","method":"GET","url":"https://example.com/api","approval":"off"}]}`)); err != nil {
		t.Fatal(err)
	}
	current, err = a.store.GetToolByName(tool.Name)
	if err != nil || current.Approval != "always" || current.Rev != 3 {
		t.Fatal("import lowered policy or lost revision")
	}
	current.Approval = ""
	if err := a.persistTool(current); err != nil {
		t.Fatal(err)
	}
	if current.Approval != "always" || current.Rev != 4 {
		t.Fatal("omitted policy did not preserve existing value")
	}
	current.Approval = "off"
	if err := a.persistTool(current); err != nil {
		t.Fatal(err)
	}
	if current.Approval != "off" || current.Rev != 5 {
		t.Fatal("console could not lower policy")
	}
	current.Approval = "sometimes"
	if err := a.persistTool(current); err == nil || !strings.Contains(err.Error(), "off 或 always") {
		t.Fatal("invalid console policy accepted")
	}
	if _, err := a.Import([]byte(`{"format":"action2mcp","tools":[{"name":"invalid_import","method":"GET","url":"https://example.com/api","approval":"invalid"}]}`)); err == nil {
		t.Fatal("invalid import policy accepted")
	}
	for _, method := range []string{"POST", "GET"} {
		created := &Tool{Name: "console_" + method, Method: method, URL: "https://example.com/api"}
		if err := a.persistTool(created); err != nil {
			t.Fatal(err)
		}
		if created.Approval != defaultApproval(method) {
			t.Fatal("console omitted policy did not use method default")
		}
	}
	write := &Tool{Name: "mcp_write", Method: "POST", URL: "https://example.com/api", Approval: "off"}
	if err := a.store.SaveToolInPack(write, pack.ID); err != nil || write.Approval != "always" {
		t.Fatal("MCP accepted a lower policy for a write tool")
	}
	if _, err := a.Import([]byte(`{"format":"action2mcp","tools":[{"name":"import_default","method":"POST","url":"https://example.com/api"},{"name":"import_explicit","method":"POST","url":"https://example.com/api","approval":"off"}]}`)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, policy string }{{"import_default", "always"}, {"import_explicit", "off"}} {
		stored, err := a.store.GetToolByName(tc.name)
		if err != nil || stored.Approval != tc.policy {
			t.Fatal("new import policy incorrect")
		}
	}
}

func TestApprovalConcurrentStorePathsDoNotDeadlock(t *testing.T) {
	a := approvalTestApp(t)
	a.store.db.SetMaxOpenConns(1)
	recID, err := a.store.CreateRecording("并发测试", "https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	q := &ReqRecord{RecordingID: recID, Seq: 1, Method: "GET", URL: "https://example.com/api?value=one", ResourceType: "Fetch", Status: 200}
	if err := a.store.InsertRequest(q); err != nil {
		t.Fatal(err)
	}
	pack := &Pack{Name: "并发测试包", Enabled: true}
	if err := a.store.SavePack(pack); err != nil {
		t.Fatal(err)
	}
	tool := &Tool{Name: "concurrent_save", Method: "GET", URL: q.URL, SourceReqID: q.ID, Approval: "always"}
	if err := a.store.SaveTool(tool); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errors := make(chan error, 3)
	for _, kind := range []string{"store", "rec", "import"} {
		wg.Add(1)
		go func(kind string) {
			defer wg.Done()
			for i := 0; i < 5; i++ {
				switch kind {
				case "store":
					copy := *tool
					copy.Approval = "off"
					if err := a.store.SaveToolInPack(&copy, pack.ID); err != nil {
						errors <- err
						return
					}
				case "rec":
					if _, bad := a.recSaveTool(nil, map[string]any{"request_id": q.ID, "name": tool.Name, "pack": pack.Name, "overwrite": true}); bad {
						errors <- fmt.Errorf("concurrent rec save failed")
						return
					}
				case "import":
					file := compactJSON(map[string]any{"format": "action2mcp", "tools": []map[string]any{{"name": tool.Name, "method": "GET", "url": q.URL, "approval": "off"}}})
					if _, err := a.Import(file); err != nil {
						errors <- err
						return
					}
				}
			}
		}(kind)
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("transaction-scoped save deadlocked")
	}
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal("concurrent save path failed")
		}
	}
	stored, err := a.store.GetTool(tool.ID)
	if err != nil || stored.Approval != "always" || stored.Rev != 16 {
		t.Fatal("concurrent saves lost policy or revisions")
	}
}

func TestApprovalExportImportAndCandidateSecrets(t *testing.T) {
	a := approvalTestApp(t)
	for _, kind := range []string{"query", "form", "body"} {
		q := &ReqRecord{Method: "POST", URL: "https://example.com/api", ReqHeaders: map[string]string{}}
		chosen := Candidate{Loc: kind, Name: "label", Path: "password", Type: "string", Example: privateTestValue(t), Secret: true}
		switch kind {
		case "query":
			q.URL += "?password=removed"
		case "form":
			q.ReqBody = "password=removed"
			q.ReqHeaders["Content-Type"] = "application/x-www-form-urlencoded"
		case "body":
			q.ReqBody = `{"password":"removed"}`
			q.ReqHeaders["Content-Type"] = "application/json"
		}
		tool, err := BuildDraft(q, []Candidate{chosen})
		if err != nil || len(tool.Params) != 1 || !tool.Params[0].Secret || tool.Params[0].Default != "" {
			t.Fatal("draft lost candidate secret flag")
		}
		tool.Name = "candidate_" + kind
		tool.Approval = "always"
		if err := a.persistTool(tool); err != nil {
			t.Fatal(err)
		}
	}
	data, err := a.Export()
	if err != nil {
		t.Fatal(err)
	}
	var file exportFile
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatal(err)
	}
	if len(file.Tools) != 3 {
		t.Fatal("export missing tools")
	}
	for _, tool := range file.Tools {
		if tool.Approval != "always" || len(tool.Params) != 1 || !tool.Params[0].Secret {
			t.Fatal("export lost policy or secret flag")
		}
	}
	other := approvalTestApp(t)
	if _, err := other.Import(data); err != nil {
		t.Fatal(err)
	}
	tools, err := other.store.ListTools()
	if err != nil || len(tools) != 3 {
		t.Fatal("import missing tools")
	}
	for _, tool := range tools {
		if tool.Approval != "always" || !tool.Params[0].Secret || tool.Rev != 1 {
			t.Fatal("round trip lost policy or secret flag")
		}
	}
}

func TestApprovalStartupCleanupOnlyOnServe(t *testing.T) {
	a := approvalTestApp(t)
	r := ApprovalRecord{TS: now(), Tool: "snapshot", Title: "历史标题", ArgsDisplay: map[string]string{}, Params: []Param{}, Preview: RequestPreview{Method: "GET", URL: "https://example.com/", Headers: map[string]string{}}}
	if err := a.store.insertApproval(&r); err != nil {
		t.Fatal(err)
	}
	other, err := NewApp(a.dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Shutdown()
	if _, err := other.Export(); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Import([]byte(`{"format":"action2mcp"}`)); err != nil {
		t.Fatal(err)
	}
	rows, err := a.store.listApprovals("pending", 100)
	if err != nil || len(rows) != 1 || rows[0].ID != r.ID {
		t.Fatal("NewApp/export/import cancelled an in-progress approval")
	}
	if err := other.store.CancelPendingApprovals(); err != nil {
		t.Fatal(err)
	}
	rows, err = a.ListApprovals("all", 100)
	if err != nil || len(rows) != 1 || rows[0].Status != "cancelled" {
		t.Fatal("serve cleanup did not cancel leftovers")
	}
}

func TestApprovalRetentionAndOrphanPendingCleanup(t *testing.T) {
	a := approvalTestApp(t)
	r := ApprovalRecord{TS: now(), Tool: "pending_snapshot", ArgsDisplay: map[string]string{}, Params: []Param{}, Preview: RequestPreview{Headers: map[string]string{}}}
	if err := a.store.insertApproval(&r); err != nil {
		t.Fatal(err)
	}
	_, err := a.store.db.Exec(`WITH RECURSIVE seq(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM seq WHERE n<1005)
INSERT INTO approvals(ts,tool,tool_id,tool_rev,client,args_display,final_args_display,status,feedback,decided_at,result,title,preview_display,params_json)
SELECT '', 'finished', 0, 1, '', '{}', '{}', 'rejected', '', '', '', '历史快照', '{}', '[]' FROM seq`)
	if err != nil {
		t.Fatal(err)
	}
	last := r
	if err := a.store.insertApproval(&last); err != nil {
		t.Fatal(err)
	}
	last.Status = "cancelled"
	last.DecidedAt = now()
	if err := a.store.finishApproval(&last); err != nil {
		t.Fatal(err)
	}
	var pending, finished int
	if err := a.store.db.QueryRow(`SELECT COUNT(*) FROM approvals WHERE status='pending'`).Scan(&pending); err != nil {
		t.Fatal(err)
	}
	if err := a.store.db.QueryRow(`SELECT COUNT(*) FROM approvals WHERE status<>'pending'`).Scan(&finished); err != nil {
		t.Fatal(err)
	}
	if pending != 1 || finished != 1000 {
		t.Fatal("retention deleted pending or retained too much history")
	}
	for i := 1; i < 20; i++ {
		copy := r
		if err := a.store.insertApproval(&copy); err != nil {
			t.Fatal(err)
		}
	}
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("orphan cleanup executed request") }))
	saveApprovalTool(t, a, upstream, "always")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	call := startApprovalCall(a, ctx, map[string]any{"value": "one"})
	rows := pendingApprovals(t, a, 1)
	if rows[0].Nonce == "" {
		t.Fatal("new call did not get a decidable pending approval")
	}
	if err := a.store.db.QueryRow(`SELECT COUNT(*) FROM approvals WHERE status='pending'`).Scan(&pending); err != nil || pending != 1 {
		t.Fatal("database-only pending rows were not repaired")
	}
	cancel()
	if !getApprovalReply(t, call).isError {
		t.Fatal("cancelled call executed")
	}
}
