package app

import (
	"action2mcp/internal/domain"
	"action2mcp/internal/execution"
	"action2mcp/internal/flow"
	"action2mcp/internal/mcp"
	"action2mcp/internal/store"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestFlowConsoleAndMCPIntegration(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/a":
			id := r.URL.Query().Get("id")
			json.NewEncoder(w).Encode(map[string]any{"user_id": id, "org": "acme"})
		case "/api/b":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			json.NewEncoder(w).Encode(map[string]any{"score": 95, "org": body["org"]})
		case "/api/c":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			json.NewEncoder(w).Encode(map[string]any{"summary": body["summary"], "accepted": true})
		default:
			w.WriteHeader(404)
		}
	}))
	defer upstream.Close()

	application, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer application.Shutdown()
	srv := httptest.NewServer(application.Handler())
	defer srv.Close()

	// 1. GET /api/runtimes
	rtResp, err := http.Get(srv.URL + "/api/runtimes")
	if err != nil {
		t.Fatal(err)
	}
	defer rtResp.Body.Close()
	if rtResp.StatusCode != 200 {
		t.Fatalf("GET /api/runtimes status=%d", rtResp.StatusCode)
	}
	var rtOut struct {
		Runtimes []flow.RuntimeInfo `json:"runtimes"`
	}
	if err := json.NewDecoder(rtResp.Body).Decode(&rtOut); err != nil {
		t.Fatal(err)
	}
	if len(rtOut.Runtimes) == 0 || rtOut.Runtimes[0].ID != "builtin_js" || !rtOut.Runtimes[0].Available {
		t.Fatalf("expected builtin_js ready first, got %+v", rtOut.Runtimes)
	}

	// Save atomic child tools A, B, C (deliberately NOT added to any enabled pack).
	toolA := &execution.Tool{
		Approval: "off", Name: "sub_a", Title: "A", Method: "GET", URL: upstream.URL + "/api/a?id={{uid}}",
		Params: []domain.Param{{Name: "uid", Type: "string", Required: true}},
	}
	toolB := &execution.Tool{
		Approval: "off", Name: "sub_b", Title: "B", Method: "POST", URL: upstream.URL + "/api/b",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"org":"{{org}}"}`,
		Params:  []domain.Param{{Name: "org", Type: "string", Required: true}},
	}
	toolC := &execution.Tool{
		Approval: "off", Name: "sub_c", Title: "C", Method: "POST", URL: upstream.URL + "/api/c",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"summary":"{{summary}}"}`,
		Params:  []domain.Param{{Name: "summary", Type: "string", Required: true}},
	}
	for _, st := range []*execution.Tool{toolA, toolB, toolC} {
		if err := application.store.SaveTool(st); err != nil {
			t.Fatal(err)
		}
	}
	application.store.ReplaceCookies([]Cookie{{Name: "sid", Value: "test-session", Domain: "127.0.0.1", Path: "/"}})

	// 2. POST /api/tools/flow/test with empty args (falls back to default param values)
	draft := execution.Tool{
		Approval:    "off",
		Name:        "user_report_flow",
		Title:       "组合报告",
		Description: "获取用户和组织分数后汇总提交",
		Method:      "FLOW",
		Params: []domain.Param{
			{Name: "uid", Type: "string", Required: true, Default: "u100"},
			{Name: "org", Type: "string", Required: true, Default: "acme"},
		},
		Config: execution.ToolConfig{
			Flow: &execution.FlowConfig{
				Steps: []execution.FlowStep{
					{ID: "step_a", Kind: "tool", ToolName: "sub_a", Args: map[string]any{"uid": "{{input.uid}}"}},
					{ID: "step_b", Kind: "tool", ParallelWithPrev: true, ToolName: "sub_b", Args: map[string]any{"org": "{{input.org}}"}},
					{
						ID: "merge_js", Kind: "script", Runtime: "builtin_js",
						Code: `function main(input, steps) {
							return { text: steps.step_a.user_id + "@" + steps.step_b.org + ":" + steps.step_b.score };
						}`,
					},
					{ID: "step_c", Kind: "tool", ToolName: "sub_c", Args: map[string]any{"summary": "{{steps.merge_js.text}}"}},
				},
				Output: execution.FlowOutput{Mode: "last"},
			},
		},
	}

	testPayload, _ := json.Marshal(map[string]any{"tool": draft, "args": map[string]any{}})
	testResp, err := http.Post(srv.URL+"/api/tools/flow/test", "application/json", bytes.NewReader(testPayload))
	if err != nil {
		t.Fatal(err)
	}
	defer testResp.Body.Close()
	if testResp.StatusCode != 200 {
		t.Fatalf("POST /api/tools/flow/test status=%d", testResp.StatusCode)
	}
	var runRes flow.RunResult
	if err := json.NewDecoder(testResp.Body).Decode(&runRes); err != nil {
		t.Fatal(err)
	}
	if !runRes.OK || len(runRes.StepsTrace) != 4 || !strings.Contains(runRes.Body, "u100@acme:95") {
		t.Fatalf("unexpected flow test result: %+v", runRes)
	}

	// 3. Save FLOW tool via POST /api/tools, test via POST /api/tools/{id}/run, and invoke via MCP
	toolJSON, _ := json.Marshal(draft)
	saveResp, err := http.Post(srv.URL+"/api/tools", "application/json", bytes.NewReader(toolJSON))
	if err != nil {
		t.Fatal(err)
	}
	defer saveResp.Body.Close()
	if saveResp.StatusCode != 200 {
		t.Fatalf("POST /api/tools status=%d", saveResp.StatusCode)
	}
	var saved execution.Tool
	if err := json.NewDecoder(saveResp.Body).Decode(&saved); err != nil {
		t.Fatal(err)
	}

	runByIDResp, err := http.Post(
		srv.URL+"/api/tools/"+strconv.FormatInt(saved.ID, 10)+"/run",
		"application/json",
		strings.NewReader(`{"args":{"uid":"u200","org":"beta"}}`),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer runByIDResp.Body.Close()
	var runByIDRes flow.RunResult
	if err := json.NewDecoder(runByIDResp.Body).Decode(&runByIDRes); err != nil {
		t.Fatal(err)
	}
	if !runByIDRes.OK || !strings.Contains(runByIDRes.Body, "u200@beta:95") {
		t.Fatalf("unexpected run-by-id result: %+v", runByIDRes)
	}

	if err := application.store.SavePack(&store.Pack{
		Name: "自定义流程包", Enabled: true, ToolIDs: []int64{saved.ID},
	}); err != nil {
		t.Fatal(err)
	}
	application.store.SetSetting("mcp_mode", mcp.ModeFlat)

	sid := ""
	rpc := func(body string) map[string]any {
		req, _ := http.NewRequest("POST", srv.URL+"/mcp", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if sid != "" {
			req.Header.Set("Mcp-Session-Id", sid)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if s := resp.Header.Get("Mcp-Session-Id"); s != "" {
			sid = s
		}
		var out map[string]any
		json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	rpc(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	list := rpc(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	lb, _ := json.Marshal(list)
	if !strings.Contains(string(lb), "user_report_flow") {
		t.Fatalf("flow tool missing from tools/list: %s", lb)
	}
	if strings.Contains(string(lb), `"sub_a"`) {
		t.Fatalf("hidden sub-tool should not appear in tools/list: %s", lb)
	}
	call := rpc(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"user_report_flow","arguments":{"uid":"u300","org":"gamma"}}}`)
	cb, _ := json.Marshal(call)
	if !strings.Contains(string(cb), "u300@gamma:95") {
		t.Fatalf("unexpected MCP flow call result: %s", cb)
	}
}
