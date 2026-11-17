package app

import (
	"action2mcp/internal/approval"
	"action2mcp/internal/store"
	"action2mcp/internal/vault"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

// Public history API contract, independent of the owner's private constants.
const (
	approvalResultPreviewBytes = 2 * 1024
	approvalResultFullMax      = 1 << 20
	approvalResultTruncMark    = "…[已截断]"
	approvalResultFullCapNote  = "…[已截断]（结果超过 1MB，已截断保存）"
)

func TestApprovalResultFullAPIAndStorage(t *testing.T) {
	body := strings.Repeat("row-data-line\n", 80) + "TAIL-MARKER-XYZ"
	if len(body) < approvalResultPreviewBytes {
		body = strings.Repeat("x", approvalResultPreviewBytes+100) + "\n" + body
	}
	secret := "sess_" + privateTestValue(t)
	upstream := newApprovalTarget(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "visible "+secret+"\n"+body)
	}))
	a := approvalTestApp(t)
	a.cfg.Port = 19051
	if err := a.vault.Upsert("svc_token", "secret", secret, "https://example.com", ""); err != nil {
		t.Fatal(err)
	}
	saveApprovalTool(t, a, upstream, "always")

	handler := a.Handler()
	origin := fmt.Sprintf("http://127.0.0.1:%d", a.cfg.Port)

	done := startApprovalCall(a, context.Background(), map[string]any{"value": "one"})
	pending := pendingApprovals(t, a, 1)[0]
	approveRecord(t, a, pending)
	reply := getApprovalReply(t, done)
	if reply.isError {
		t.Fatalf("call failed: %s", reply.text)
	}
	if strings.Contains(reply.text, secret) {
		t.Fatal("AI result leaked vault secret")
	}
	if !strings.Contains(reply.text, "TAIL-MARKER-XYZ") || !strings.Contains(reply.text, vault.Mask) {
		t.Fatalf("AI result missing tail or mask: %s", truncate(reply.text, 200))
	}

	rows := listApprovalAPI(t, handler, origin, "all")
	if len(rows) != 1 {
		t.Fatalf("list len=%d", len(rows))
	}
	if !rows[0].HasFullResult {
		t.Fatal("expected has_full_result")
	}
	if strings.Contains(rows[0].Result, "TAIL-MARKER-XYZ") {
		t.Fatal("list preview should not include the tail past the 2KB / 20-line cut")
	}
	if !strings.Contains(rows[0].Result, approvalResultTruncMark) {
		t.Fatalf("preview should be marked truncated: %q", truncate(rows[0].Result, 120))
	}
	if strings.Contains(rows[0].Result, secret) {
		t.Fatal("list preview leaked secret")
	}
	raw, _ := json.Marshal(rows)
	if strings.Contains(string(raw), "TAIL-MARKER-XYZ") {
		t.Fatal("list JSON included the full result")
	}
	if strings.Contains(string(raw), `"result_full"`) {
		t.Fatal("list JSON exposed result_full")
	}

	w := approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/approvals/%d/result", rows[0].ID), origin, "application/json", map[string]any{})
	var out struct {
		ID        int64  `json:"id"`
		Result    string `json:"result"`
		Truncated bool   `json:"truncated"`
	}
	requireApprovalAPIResponse(t, w, http.StatusOK, &out)
	if out.ID != rows[0].ID || out.Truncated {
		t.Fatalf("unexpected result payload id=%d truncated=%v", out.ID, out.Truncated)
	}
	if !strings.Contains(out.Result, "TAIL-MARKER-XYZ") {
		t.Fatal("full result missing tail")
	}
	if strings.Contains(out.Result, secret) {
		t.Fatal("full result leaked secret")
	}
	if !strings.Contains(out.Result, vault.Mask) {
		t.Fatal("full result should be scrubbed the same way the AI saw")
	}

	for _, originBad := range []string{
		"",
		"null",
		fmt.Sprintf("http://127.0.0.1:%d", a.cfg.Port+1),
		fmt.Sprintf("http://example.com:%d", a.cfg.Port),
	} {
		g := approvalAPIRequest(t, handler, http.MethodPost, fmt.Sprintf("/api/approvals/%d/result", rows[0].ID), originBad, "application/json", map[string]any{})
		requireApprovalAPIResponse(t, g, http.StatusForbidden, nil)
	}

	missing := approvalAPIRequest(t, handler, http.MethodPost, "/api/approvals/999999/result", origin, "application/json", map[string]any{})
	requireApprovalAPIResponse(t, missing, http.StatusNotFound, nil)
}

func TestApprovalResultFullCapAndMigration(t *testing.T) {
	huge := strings.Repeat("Z", approvalResultFullMax+2048)
	a := approvalTestApp(t)
	if err := a.store.Approvals.Insert(&approval.Record{TS: now(), Tool: "t", Title: "t", Status: "pending", Client: "c"}); err != nil {
		t.Fatal(err)
	}
	rows, err := a.store.Approvals.List("pending", 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("insert: %v %d", err, len(rows))
	}
	a.approvals().Service().RecordResult(rows[0].ID, huge)
	full, truncated, err := a.approvals().Result(rows[0].ID)
	if err != nil || !truncated {
		t.Fatalf("cap: truncated=%v err=%v", truncated, err)
	}
	if !strings.Contains(full, approvalResultFullCapNote) {
		t.Fatal("missing 1MB cap note")
	}
	hist, err := a.approvals().List("all", 10)
	if err != nil || len(hist) != 1 || !hist[0].HasFullResult {
		t.Fatal("list should flag full result")
	}
	if len(hist[0].Result) > approvalResultPreviewBytes+len(approvalResultTruncMark)+16 {
		t.Fatalf("list preview too large: %d", len(hist[0].Result))
	}

	dir := t.TempDir()
	path := dir + "/v9.DB()"
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("CREATE TABLE approvals(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, tool TEXT, tool_id INTEGER, tool_rev INTEGER, client TEXT, args_display TEXT, final_args_display TEXT, status TEXT, feedback TEXT, decided_at TEXT, result TEXT, title TEXT, preview_display TEXT, params_json TEXT);\n" +
		"CREATE TABLE tools(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, title TEXT, description TEXT, method TEXT, url TEXT, headers TEXT, body TEXT, params TEXT, cred_headers TEXT, source_request_id INTEGER, created_at TEXT, updated_at TEXT);\n" +
		"CREATE TABLE settings(key TEXT PRIMARY KEY, value TEXT);\n" +
		"INSERT INTO approvals(ts,tool,tool_id,tool_rev,client,args_display,final_args_display,status,feedback,decided_at,result,title,preview_display,params_json) VALUES('t','old',1,1,'c','{}','{}','approved','','t2','HTTP 200 old-summary','title','{}','[]');\n" +
		"PRAGMA user_version=9;")
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	s, err := store.OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.DB().Close()
	if !tableHasColumn(s, "approvals", "result_full") {
		t.Fatal("result_full column missing after migration")
	}
	var ver int
	if err := s.DB().QueryRow("PRAGMA user_version").Scan(&ver); err != nil || ver != wantSchemaUserVersion {
		t.Fatalf("version=%d err=%v", ver, err)
	}
	got, err := s.Approvals.List("all", 10)
	if err != nil || len(got) != 1 || got[0].Result != "HTTP 200 old-summary" {
		t.Fatalf("migration lost old result: %+v %v", got, err)
	}
	if got[0].HasFullResult {
		t.Fatal("legacy row should not claim a full result")
	}
}
