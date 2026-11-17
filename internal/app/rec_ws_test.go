package app

import (
	"action2mcp/internal/execution"
	"action2mcp/internal/recording"
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildWSDraftBindsTokenAndSQL(t *testing.T) {
	token := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	sent := recording.NewEnvelope([]recording.Frame{{Op: 1, Text: `execute {"data":{"sql":"SELECT id FROM t WHERE id=1 LIMIT 10","spaceCode":"s"},"token":"` + token + `"}`}}, false, "", "")
	recv := recording.NewEnvelope([]recording.Frame{
		{Op: 1, Text: `execResult {"data":{"success":true,"done":true}}`},
		{Op: 1, Text: `close {}`},
	}, false, "closed", "")
	sb, _ := json.Marshal(sent)
	rb, _ := json.Marshal(recv)
	q := &recording.Request{Method: "WS", URL: "wss://sql.example.com/api/ws/execute", ResourceType: "WebSocket", Status: 101,
		ReqHeaders: map[string]string{"sso-epctoken": token, "Content-Type": "application/json"},
		ReqBody:    string(sb), RespBody: string(rb)}
	cands := execution.SuggestParams(q)
	var sqlCand Candidate
	for _, c := range cands {
		if strings.HasSuffix(c.Path, "data.sql") || strings.HasSuffix(c.Path, ":data.sql") {
			sqlCand = c
			sqlCand.Name = "sql"
		}
		if strings.Contains(strings.ToLower(c.Path), "token") && c.Example != "" {
			t.Fatalf("token candidate should not expose example: %+v", c)
		}
	}
	if sqlCand.Path == "" {
		t.Fatalf("sql candidate missing: %+v", cands)
	}
	tool, err := execution.BuildDraft(q, []Candidate{sqlCand})
	if err != nil {
		t.Fatal(err)
	}
	if tool.Method != "WS" || tool.Config.SQLGuard == nil || !tool.Config.SQLGuard.Enabled {
		t.Fatalf("draft: %+v", tool.Config)
	}
	msg := strings.Join(tool.Config.Messages, "\n")
	if strings.Contains(msg, token) {
		t.Fatal("draft kept literal token")
	}
	if !strings.Contains(msg, "{{header.sso-epctoken}}") || !strings.Contains(msg, "{{sql}}") {
		t.Fatalf("bindings missing: %s", msg)
	}
	if err := execution.ValidateWSCredentialBindings(tool); err != nil {
		t.Fatal(err)
	}
	tool.Name = "ws_sql"
	a, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Shutdown)
	if err := a.tools().Persist(tool); err != nil {
		t.Fatal(err)
	}
	got, _ := a.store.GetToolByName("ws_sql")
	if got.Approval != "always" {
		t.Fatalf("approval=%s", got.Approval)
	}
	// literal token must be rejected
	bad := *tool
	bad.ID = 0
	bad.Name = "ws_sql_bad"
	bad.Config.Messages = []string{`execute {"data":{"sql":"{{sql}}"},"token":"` + token + `"}`}
	if err := a.tools().Persist(&bad); err == nil {
		t.Fatal("literal token should be rejected")
	}
}

func TestBuildWSDraftRejectsTruncated(t *testing.T) {
	env := recording.NewEnvelope([]recording.Frame{{Op: 1, Text: `execute {"data":{"sql":"SELECT 1 LIMIT 1"}}`}}, true, "", "")
	b, _ := json.Marshal(env)
	_, err := execution.BuildWSDraft(&recording.Request{Method: "WS", URL: "wss://sql.example.com/ws", ReqBody: string(b)}, nil)
	if err == nil || !strings.Contains(err.Error(), "截断") {
		t.Fatalf("err=%v", err)
	}
}
