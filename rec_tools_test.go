package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"
)

const (
	secStart     = "STARTTOKEN-value-77"
	secCookie    = "COOKIESECRET-value-77"
	secAuth      = "AUTHSECRET-value-77"
	secPass      = "PASSWORDSECRET-value-77"
	secQuery     = "QUERYTOKEN-value-77"
	secSetCookie = "SETCOOKIESECRET-value-77"
	secVault     = "VAULTSECRET-value-77"
)

func recSecrets() []string {
	return []string{secStart, secCookie, secAuth, secPass, secQuery, secSetCookie, secVault}
}

func assertNoSecrets(t *testing.T, label, text string) {
	t.Helper()
	for _, s := range recSecrets() {
		if strings.Contains(text, s) {
			t.Fatalf("%s leaked %s\n%s", label, s, text)
		}
	}
}

// Exercise the real HTTP/SSE handlers without binding a socket. This also
// verifies inline notifications in environments where listening is prohibited.
type recTestClient struct {
	t       *testing.T
	handler http.Handler
	sid     string
	id      int
}

func (c *recTestClient) call(method string, params any) ([]map[string]any, map[string]any) {
	c.t.Helper()
	c.id++
	body := compactJSON(map[string]any{"jsonrpc": "2.0", "id": c.id, "method": method, "params": params})
	req := httptest.NewRequest("POST", "https://example.com/mcp", strings.NewReader(string(body)))
	req.Host = "127.0.0.1"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.sid != "" {
		req.Header.Set("Mcp-Session-Id", c.sid)
	}
	w := httptest.NewRecorder()
	c.handler.ServeHTTP(w, req)
	if w.Code != 200 {
		c.t.Fatalf("MCP %s: status %d: %s", method, w.Code, w.Body.String())
	}
	if sid := w.Header().Get("Mcp-Session-Id"); sid != "" {
		c.sid = sid
	}
	var msgs []map[string]any
	decode := func(b []byte) {
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			c.t.Fatalf("MCP response: %v: %s", err, b)
		}
		msgs = append(msgs, m)
	}
	if strings.HasPrefix(w.Header().Get("Content-Type"), "text/event-stream") {
		readSSE(w.Body, decode)
	} else {
		decode(w.Body.Bytes())
	}
	for _, m := range msgs {
		if m["id"] != nil {
			return msgs, m
		}
	}
	c.t.Fatalf("no response for %s", method)
	return nil, nil
}

func (c *recTestClient) tool(name string, args any) (string, bool) {
	c.t.Helper()
	_, r := c.call("tools/call", map[string]any{"name": name, "arguments": args})
	if e, ok := r["error"].(map[string]any); ok {
		return e["message"].(string), true
	}
	res := r["result"].(map[string]any)
	return res["content"].([]any)[0].(map[string]any)["text"].(string), res["isError"] == true
}

func (c *recTestClient) toolNames() []string {
	_, r := c.call("tools/list", map[string]any{})
	var names []string
	for _, tool := range r["result"].(map[string]any)["tools"].([]any) {
		names = append(names, tool.(map[string]any)["name"].(string))
	}
	return names
}

func startRecServer(t *testing.T) (*App, http.Handler, *recTestClient) {
	t.Helper()
	app, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	srv := app.Handler()
	c := &recTestClient{t: t, handler: srv}
	c.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "rec-test"}})
	return app, srv, c
}

func apiRaw(t *testing.T, handler http.Handler, method, url, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Host = "127.0.0.1"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	resp := w.Result()
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

func TestRecToolsListingAndToggle(t *testing.T) {
	app, srv, c := startRecServer(t)
	code, settings := apiRaw(t, srv, "GET", "https://example.com/api/settings", "")
	if code != 200 || settings["rec_analysis"] != true || settings["mcp_mode"] != "tiered" {
		t.Fatalf("default settings %d %v", code, settings)
	}

	names := c.toolNames()
	if len(names) != 4 || has(names, "rec_list_recordings") {
		t.Fatalf("tiered initial tools: %v", names)
	}
	listed, isErr := c.tool("list_packs", map[string]any{})
	if isErr || !strings.Contains(listed, `"录制分析"`) || !strings.Contains(listed, `"builtin":true`) {
		t.Fatalf("list_packs builtin: %s", listed)
	}
	var lp struct {
		Packs []struct {
			ID        int64    `json:"id"`
			Name      string   `json:"name"`
			ToolNames []string `json:"tool_names"`
			Builtin   bool     `json:"builtin"`
		} `json:"packs"`
	}
	if err := json.Unmarshal([]byte(listed), &lp); err != nil {
		t.Fatalf("list_packs json: %v %s", err, listed)
	}
	var builtinID int64
	for _, p := range lp.Packs {
		if p.Name == "录制分析" {
			builtinID = p.ID
			if !p.Builtin || !has(p.ToolNames, "rec_get_recording") || !has(p.ToolNames, "rec_save_tool") || !has(p.ToolNames, "rec_list_target_packs") {
				t.Fatalf("builtin pack: %+v", p)
			}
		}
	}
	if builtinID != recPackID {
		t.Fatalf("builtin id %d", builtinID)
	}

	loaded, isErr := c.tool("load_pack", map[string]any{"pack": "录制分析"})
	if isErr || !strings.Contains(loaded, "rec_annotate") || !strings.Contains(loaded, "必须先问") {
		t.Fatalf("load rec pack: %s", loaded)
	}
	names = c.toolNames()
	for _, n := range []string{"list_packs", "rec_list_recordings", "rec_get_recording", "rec_get_request", "rec_annotate", "rec_save_tool", "rec_list_target_packs"} {
		if !has(names, n) {
			t.Fatalf("after load missing %s in %v", n, names)
		}
	}
	byID, isErr := c.tool("load_pack", map[string]any{"pack": recPackID})
	if isErr || !strings.Contains(byID, `"builtin":true`) {
		t.Fatalf("load by id: err=%v %s", isErr, byID)
	}

	// Lenient: another session that never loaded the pack can still call it.
	c2 := &recTestClient{t: t, handler: srv}
	c2.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "rec-2"}})
	if n := c2.toolNames(); has(n, "rec_list_recordings") || len(n) != 4 {
		t.Fatalf("unloaded session leaked tools: %v", n)
	}
	txt, isErr := c2.tool("rec_list_recordings", map[string]any{})
	if isErr || !strings.Contains(txt, `"recordings"`) {
		t.Fatalf("lenient call: %s", txt)
	}
	txt, isErr = c2.tool("call_pack_tool", map[string]any{"tool": "rec_list_target_packs", "arguments": map[string]any{}})
	if isErr || !strings.Contains(txt, `"packs"`) {
		t.Fatalf("call_pack_tool rec: %s", txt)
	}

	unloaded, isErr := c.tool("unload_pack", map[string]any{"pack": "录制分析"})
	if isErr || !strings.Contains(unloaded, `"was_loaded":true`) {
		t.Fatalf("unload: %s", unloaded)
	}
	if n := c.toolNames(); has(n, "rec_get_request") || len(n) != 4 {
		t.Fatalf("after unload: %v", n)
	}

	// Flat mode lists the tools directly and keeps the toggle.
	code, settings = apiRaw(t, srv, "PUT", "https://example.com/api/settings", `{"mcp_mode":"flat"}`)
	if code != 200 || settings["mcp_mode"] != "flat" || settings["rec_analysis"] != true {
		t.Fatalf("set flat %d %v", code, settings)
	}
	flat := &recTestClient{t: t, handler: srv}
	flat.call("initialize", map[string]any{"protocolVersion": "2025-06-18", "clientInfo": map[string]any{"name": "flat"}})
	fn := flat.toolNames()
	if has(fn, "list_packs") || !has(fn, "rec_list_recordings") || !has(fn, "rec_save_tool") || !has(fn, "rec_list_target_packs") {
		t.Fatalf("flat tools: %v", fn)
	}

	code, settings = apiRaw(t, srv, "PUT", "https://example.com/api/settings", `{"rec_analysis":false}`)
	if code != 200 || settings["rec_analysis"] != false || settings["mcp_mode"] != "flat" {
		t.Fatalf("toggle off %d %v", code, settings)
	}
	if n := flat.toolNames(); has(n, "rec_list_recordings") || has(n, "rec_save_tool") {
		t.Fatalf("toggle off still listed: %v", n)
	}
	if txt, isErr = flat.tool("rec_get_recording", map[string]any{"recording_id": 1}); !isErr || !strings.Contains(txt, "已关闭") {
		t.Fatalf("disabled call: err=%v %s", isErr, txt)
	}
	app.store.SetSetting("mcp_mode", ModeTiered)
	tiered := &recTestClient{t: t, handler: srv}
	tiered.call("initialize", map[string]any{"protocolVersion": "2025-06-18"})
	if txt, isErr = tiered.tool("list_packs", map[string]any{}); isErr || strings.Contains(txt, "录制分析") {
		t.Fatalf("disabled list_packs: %s", txt)
	}
	if txt, isErr = tiered.tool("load_pack", map[string]any{"pack": "录制分析"}); !isErr {
		t.Fatalf("disabled load should fail: %s", txt)
	}

	code, settings = apiRaw(t, srv, "PUT", "https://example.com/api/settings", `{"rec_analysis":true}`)
	if code != 200 || settings["rec_analysis"] != true {
		t.Fatalf("toggle on %d %v", code, settings)
	}

	code, body := apiRaw(t, srv, "POST", "https://example.com/api/tools", `{"name":"rec_get_recording","method":"GET","url":"https://example.com/x"}`)
	if code == 200 {
		t.Fatalf("reserved name accepted: %v", body)
	}
	errText, _ := json.Marshal(body)
	if !strings.Contains(string(errText), "保留") {
		t.Fatalf("reserved name error: %s", errText)
	}
}

func TestRecToolsAnnotateSaveScrub(t *testing.T) {
	app, srv, c := startRecServer(t)
	if err := app.vault.Upsert("svc_token", "secret", secVault, "https://api.example.com", ""); err != nil {
		t.Fatal(err)
	}
	recID, err := app.store.CreateRecording("线上问题排查", "https://app.example.com/app/start?token="+secStart)
	if err != nil {
		t.Fatal(err)
	}
	orders := &ReqRecord{RecordingID: recID, Seq: 1, Method: "GET", URL: "https://api.example.com/v1/orders?id=100&access_token=" + secQuery, ResourceType: "Fetch", Status: 200}
	if err := app.store.InsertRequest(orders); err != nil {
		t.Fatal(err)
	}
	dup := &ReqRecord{RecordingID: recID, Seq: 2, Method: "GET", URL: "https://api.example.com/v1/orders?id=101&access_token=" + secQuery, ResourceType: "Fetch", Status: 200}
	if err := app.store.InsertRequest(dup); err != nil {
		t.Fatal(err)
	}
	dup2 := &ReqRecord{RecordingID: recID, Seq: 3, Method: "GET", URL: "https://api.example.com/v1/orders?id=102", ResourceType: "Fetch", Status: 200}
	if err := app.store.InsertRequest(dup2); err != nil {
		t.Fatal(err)
	}
	post := &ReqRecord{
		RecordingID: recID, Seq: 4, Method: "POST",
		URL:          "https://api.example.com/v1/orders?access_token=" + secQuery,
		ResourceType: "Fetch", Status: 201,
		ReqHeaders: map[string]string{
			"Cookie": "sid=" + secCookie, "Authorization": "Bearer " + secAuth, "Content-Type": "application/json",
		},
		ReqBody: `{"id":"ORD-9","password":"` + secPass + `","note":"hello"}`,
		RespHeaders: map[string]string{
			"Set-Cookie": "sid=" + secSetCookie + "; Path=/", "Content-Type": "application/json",
		},
		RespBody: `{"ok":true,"message":"` + secVault + `","echo":"` + secQuery + `"}`,
	}
	if err := app.store.InsertRequest(post); err != nil {
		t.Fatal(err)
	}
	users := &ReqRecord{RecordingID: recID, Seq: 5, Method: "GET", URL: "https://api.example.com/v1/users?kw=alice", ResourceType: "Fetch", Status: 200}
	if err := app.store.InsertRequest(users); err != nil {
		t.Fatal(err)
	}
	noise := &ReqRecord{RecordingID: recID, Seq: 6, Method: "GET", URL: "https://logs.example.com/collect", ResourceType: "Fetch", Status: 204, Noise: true, NoiseReason: "埋点/日志"}
	if err := app.store.InsertRequest(noise); err != nil {
		t.Fatal(err)
	}
	otherID, err := app.store.CreateRecording("其他", "https://other.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	other := &ReqRecord{RecordingID: otherID, Seq: 1, Method: "GET", URL: "https://other.example.com/a", ResourceType: "Fetch", Status: 200}
	if err := app.store.InsertRequest(other); err != nil {
		t.Fatal(err)
	}

	var sink strings.Builder
	grab := func(label, txt string) string {
		t.Helper()
		sink.WriteString(txt)
		assertNoSecrets(t, label, txt)
		return txt
	}

	listTxt := grab("list", mustTool(t, c, "rec_list_recordings", map[string]any{}))
	var listed struct {
		Recordings []struct {
			ID            int64  `json:"id"`
			Name          string `json:"name"`
			RequestCount  int    `json:"request_count"`
			BusinessCount int    `json:"business_count"`
			Origin        string `json:"origin"`
		} `json:"recordings"`
	}
	if err := json.Unmarshal([]byte(listTxt), &listed); err != nil {
		t.Fatal(err)
	}
	var foundRec bool
	for _, row := range listed.Recordings {
		if row.ID != recID {
			continue
		}
		foundRec = true
		if row.Origin != "https://app.example.com" || row.RequestCount != 6 || row.BusinessCount != 5 {
			t.Fatalf("list recordings: %s", listTxt)
		}
	}
	if !foundRec {
		t.Fatalf("list recordings: %s", listTxt)
	}
	if strings.Contains(listTxt, "/app/start") || strings.Contains(listTxt, "access_token") {
		t.Fatalf("list leaked url detail: %s", listTxt)
	}

	recTxt := grab("get_recording", mustTool(t, c, "rec_get_recording", map[string]any{"recording_id": recID}))
	var view struct {
		Summary  string   `json:"summary"`
		Hosts    []string `json:"hosts"`
		Requests []struct {
			ID        int64    `json:"id"`
			Count     int      `json:"count"`
			Method    string   `json:"method"`
			H         int      `json:"h"`
			Path      string   `json:"path"`
			QueryKeys []string `json:"query_keys"`
			Noise     bool     `json:"noise"`
		} `json:"requests"`
	}
	if err := json.Unmarshal([]byte(recTxt), &view); err != nil {
		t.Fatalf("recording json: %v %s", err, recTxt)
	}
	var ordersRow, postRow bool
	for _, row := range view.Requests {
		if strings.Contains(row.Path, "/collect") {
			t.Fatalf("noise included by default: %+v", row)
		}
		if row.Method == "GET" && row.Path == "/v1/orders" {
			ordersRow = true
			if row.Count != 3 || row.ID != orders.ID || row.H < 0 || row.H >= len(view.Hosts) || view.Hosts[row.H] != "api.example.com" {
				t.Fatalf("orders group: %+v hosts %v want id %d", row, view.Hosts, orders.ID)
			}
			if !has(row.QueryKeys, "id") || !has(row.QueryKeys, "access_token") {
				t.Fatalf("query keys: %+v", row.QueryKeys)
			}
		}
		if row.Method == "POST" && row.Path == "/v1/orders" {
			postRow = row.Count == 1 && row.ID == post.ID
		}
	}
	if !ordersRow || !postRow {
		t.Fatalf("groups: %s", recTxt)
	}
	page, isErr := c.tool("rec_get_recording", map[string]any{"recording_id": recID, "limit": 1})
	grab("page", page)
	if isErr {
		t.Fatal(page)
	}
	var one struct {
		GroupCount int `json:"group_count"`
		Requests   []struct {
			ID int64 `json:"id"`
		} `json:"requests"`
	}
	if err := json.Unmarshal([]byte(page), &one); err != nil || one.GroupCount < 3 || len(one.Requests) != 1 || one.Requests[0].ID != orders.ID {
		t.Fatalf("limit: %s", page)
	}
	withNoise := grab("noise", mustTool(t, c, "rec_get_recording", map[string]any{"recording_id": recID, "include_noise": true}))
	if !strings.Contains(withNoise, "/collect") {
		t.Fatalf("include_noise: %s", withNoise)
	}

	detail := grab("get_request", mustTool(t, c, "rec_get_request", map[string]any{"request_id": post.ID, "max_body": 20}))
	var det struct {
		WriteHint        string `json:"write_hint"`
		ReqBody          string `json:"req_body"`
		ReqBodyTotal     int    `json:"req_body_total"`
		ReqBodyTruncated bool   `json:"req_body_truncated"`
		Candidates       []struct {
			Path    string `json:"path"`
			Example string `json:"example"`
			Secret  bool   `json:"secret"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal([]byte(detail), &det); err != nil {
		t.Fatalf("detail json: %v %s", err, detail)
	}
	if det.WriteHint == "" || !det.ReqBodyTruncated || det.ReqBodyTotal <= 20 || len(det.ReqBody) > 20 {
		t.Fatalf("truncation: %+v", det)
	}
	var sawPass, sawID bool
	for _, cnd := range det.Candidates {
		if cnd.Path == "password" {
			sawPass = cnd.Secret && cnd.Example == ""
		}
		if cnd.Path == "id" {
			sawID = cnd.Example == "ORD-9"
		}
	}
	if !sawPass || !sawID {
		t.Fatalf("candidates: %+v", det.Candidates)
	}

	bad, isErr := c.tool("rec_annotate", map[string]any{"recording_id": recID, "notes": []any{
		map[string]any{"request_id": orders.ID, "category": "query", "purpose": "查询订单"},
		map[string]any{"request_id": post.ID, "category": "nope"},
	}})
	grab("bad-category", bad)
	if !isErr || !strings.Contains(bad, "不合法") {
		t.Fatalf("bad category: %s", bad)
	}
	if notes, err := app.store.RequestNotes(recID); err != nil || len(notes) != 0 {
		t.Fatalf("partial annotate wrote notes: %+v %v", notes, err)
	}
	wrong, isErr := c.tool("rec_annotate", map[string]any{"recording_id": recID, "notes": []any{
		map[string]any{"request_id": other.ID, "category": "query", "purpose": "别的录制"},
	}})
	grab("wrong-recording", wrong)
	if !isErr || !strings.Contains(wrong, "不属于") {
		t.Fatalf("wrong recording: %s", wrong)
	}
	if notes, _ := app.store.RequestNotes(recID); len(notes) != 0 {
		t.Fatalf("wrong recording wrote notes: %+v", notes)
	}

	useful := true
	override := false
	okTxt := grab("annotate", mustTool(t, c, "rec_annotate", map[string]any{
		"recording_id": recID,
		"summary":      "查询订单并创建一条订单。",
		"notes": []any{
			map[string]any{"request_id": orders.ID, "purpose": "查询订单列表", "category": "query", "useful": useful},
			map[string]any{"request_id": post.ID, "purpose": "创建订单", "category": "write", "useful": useful},
			map[string]any{"request_id": noise.ID, "purpose": "业务日志，不是埋点", "category": "query", "useful": useful, "noise_override": override},
		},
	}))
	var ann struct {
		Updated        int     `json:"updated"`
		SummaryUpdated bool    `json:"summary_updated"`
		RequestIDs     []int64 `json:"request_ids"`
	}
	if err := json.Unmarshal([]byte(okTxt), &ann); err != nil || ann.Updated != 3 || !ann.SummaryUpdated || len(ann.RequestIDs) != 3 || strings.Contains(okTxt, `"source"`) || strings.Contains(okTxt, "查询订单并创建一条订单") {
		t.Fatalf("annotate result: %s", okTxt)
	}
	notes, err := app.store.RequestNotes(recID)
	if err != nil || notes[post.ID].Category != "write" || notes[post.ID].Source != "agent" || notes[noise.ID].NoiseOverride == nil || *notes[noise.ID].NoiseOverride {
		t.Fatalf("stored notes: %+v %v", notes, err)
	}
	after := grab("after-note", mustTool(t, c, "rec_get_recording", map[string]any{"recording_id": recID}))
	if !strings.Contains(after, "/collect") || !strings.Contains(after, "业务日志，不是埋点") || !strings.Contains(after, "查询订单并创建一条订单") {
		t.Fatalf("override not applied: %s", after)
	}

	missing, isErr := c.tool("rec_save_tool", map[string]any{"request_id": post.ID, "name": "create_order", "description": "创建订单"})
	grab("missing-pack", missing)
	if !isErr || !strings.Contains(missing, "询问用户") || !strings.Contains(missing, "create_pack") {
		t.Fatalf("missing pack: %s", missing)
	}
	if err := app.store.SavePack(&Pack{Name: "已有包", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	unknown, isErr := c.tool("rec_save_tool", map[string]any{"request_id": post.ID, "name": "create_order", "pack": "没有这个包", "description": "创建订单"})
	grab("unknown-pack", unknown)
	if !isErr || !strings.Contains(unknown, "询问用户") || !strings.Contains(unknown, "已有包") || !strings.Contains(unknown, "create_pack=true") {
		t.Fatalf("unknown pack: %s", unknown)
	}
	num, isErr := c.tool("rec_save_tool", map[string]any{"request_id": post.ID, "name": "create_order", "pack": "99999", "create_pack": true})
	grab("bad-id", num)
	if !isErr || !strings.Contains(num, "99999") || !strings.Contains(num, "询问用户") {
		t.Fatalf("numeric pack: %s", num)
	}
	builtin, isErr := c.tool("rec_save_tool", map[string]any{"request_id": post.ID, "name": "create_order", "pack": "录制分析", "create_pack": true})
	grab("builtin-pack", builtin)
	if !isErr || !strings.Contains(builtin, "录制分析") {
		t.Fatalf("builtin pack save: %s", builtin)
	}

	saved := grab("save", mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": post.ID, "pack": "客服查单", "create_pack": true, "name": "create_order",
		"title": "创建订单", "description": "按订单号创建一条订单",
		"params": []any{map[string]any{"name": "order_id", "from": "body:id", "type": "string", "description": "订单号", "required": true}},
	}))
	var toolOut struct {
		ToolID      int64          `json:"tool_id"`
		Name        string         `json:"name"`
		PackID      int64          `json:"pack_id"`
		PackName    string         `json:"pack_name"`
		CreatedPack bool           `json:"created_pack"`
		InputSchema map[string]any `json:"input_schema"`
	}
	if err := json.Unmarshal([]byte(saved), &toolOut); err != nil || toolOut.ToolID == 0 || toolOut.PackName != "客服查单" || !toolOut.CreatedPack {
		t.Fatalf("save: %v %s", err, saved)
	}
	props, _ := toolOut.InputSchema["properties"].(map[string]any)
	if props["order_id"] == nil {
		t.Fatalf("schema: %s", saved)
	}
	stored, err := app.store.GetTool(toolOut.ToolID)
	if err != nil {
		t.Fatal(err)
	}
	blob, _ := json.Marshal(stored)
	assertNoSecrets(t, "stored tool", string(blob))
	if strings.Contains(stored.URL, secQuery) || strings.Contains(stored.Body, secPass) || strings.Contains(stored.Body, secVault) {
		t.Fatalf("tool kept secrets url=%s body=%s", stored.URL, stored.Body)
	}
	if !strings.Contains(stored.Body, "{{order_id}}") || (!strings.Contains(stored.Body, "{{password}}") && !strings.Contains(stored.Body, "{{secret.")) {
		t.Fatalf("tool body not parameterised: %s", stored.Body)
	}
	var passParam *Param
	for i := range stored.Params {
		if stored.Params[i].Name == "password" {
			passParam = &stored.Params[i]
		}
	}
	if passParam == nil || !passParam.Required || passParam.Default != "" || passParam.Description != removedSecretDesc {
		t.Fatalf("password param: %+v", stored.Params)
	}
	if !strings.Contains(stored.URL, "{{") {
		t.Fatalf("token left literal in url: %s", stored.URL)
	}
	packs, _ := app.store.ListPacks()
	var inPack bool
	for _, p := range packs {
		if p.ID == toolOut.PackID {
			for _, id := range p.ToolIDs {
				if id == stored.ID {
					inPack = true
				}
			}
		}
	}
	if !inPack {
		t.Fatalf("tool not in pack: %+v", packs)
	}

	again, isErr := c.tool("rec_save_tool", map[string]any{"request_id": post.ID, "pack": "客服查单", "name": "create_order", "description": "再次保存"})
	grab("no-overwrite", again)
	if !isErr || !strings.Contains(again, "overwrite=true") {
		t.Fatalf("overwrite required: %s", again)
	}
	over := grab("overwrite", mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": post.ID, "pack": "客服查单", "name": "create_order", "overwrite": true, "description": "覆盖后的说明",
	}))
	var overOut struct {
		ToolID      int64 `json:"tool_id"`
		Overwritten bool  `json:"overwritten"`
	}
	if err := json.Unmarshal([]byte(over), &overOut); err != nil || overOut.ToolID != toolOut.ToolID || !overOut.Overwritten {
		t.Fatalf("overwrite: %s", over)
	}
	if got, _ := app.store.GetTool(toolOut.ToolID); got.Description != "覆盖后的说明" {
		t.Fatalf("description not updated: %+v", got)
	}

	byPackID := grab("save-by-id", mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": users.ID, "pack": toolOut.PackID, "name": "search_user", "description": "按关键字查用户",
		"params": []any{map[string]any{"name": "kw", "from": "query:kw", "description": "关键字", "required": true}},
	}))
	if !strings.Contains(byPackID, `"name":"search_user"`) || !strings.Contains(byPackID, "客服查单") {
		t.Fatalf("save by id: %s", byPackID)
	}
	targets := grab("targets", mustTool(t, c, "rec_list_target_packs", map[string]any{}))
	var targetOut struct {
		Packs []struct {
			Name      string   `json:"name"`
			ToolNames []string `json:"tool_names"`
		} `json:"packs"`
	}
	if err := json.Unmarshal([]byte(targets), &targetOut); err != nil {
		t.Fatalf("target packs json: %v %s", err, targets)
	}
	var sawTarget bool
	for _, p := range targetOut.Packs {
		if p.Name == "录制分析" {
			t.Fatalf("builtin pack listed as a save target: %s", targets)
		}
		if p.Name == "客服查单" && has(p.ToolNames, "search_user") && has(p.ToolNames, "create_order") {
			sawTarget = true
		}
	}
	if !sawTarget {
		t.Fatalf("target packs: %s", targets)
	}
	assertNoSecrets(t, "all outputs", sink.String())
	_ = srv
}

func mustTool(t *testing.T, c *recTestClient, name string, args map[string]any) string {
	t.Helper()
	txt, isErr := c.tool(name, args)
	if isErr {
		t.Fatalf("%s: %s", name, txt)
	}
	return txt
}

func seedRecRequest(t *testing.T, app *App, q *ReqRecord) {
	t.Helper()
	if q.RecordingID == 0 {
		var err error
		q.RecordingID, err = app.store.CreateRecording("分析测试", "https://example.com/")
		if err != nil {
			t.Fatal(err)
		}
	}
	if q.Method == "" {
		q.Method = "POST"
	}
	if q.URL == "" {
		q.URL = "https://example.com/search"
	}
	if err := app.store.InsertRequest(q); err != nil {
		t.Fatal(err)
	}
}

func decodeRec(t *testing.T, text string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("invalid JSON: %v: %s", err, text)
	}
	return out
}

func rejectRecLiterals(t *testing.T, text string, secrets ...string) {
	t.Helper()
	for _, secret := range secrets {
		for _, form := range literalForms(secret) {
			if strings.Contains(text, form) {
				t.Fatalf("leaked %q in %s", form, text)
			}
		}
	}
}

func TestRecSecurityBodyFormats(t *testing.T) {
	var multipartBody bytes.Buffer
	w := multipart.NewWriter(&multipartBody)
	if err := w.WriteField("password", "multipart-private-value"); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteField("note", "keep this field"); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, contentType, body, response, secret string
		hidden                                    bool
	}{
		{"multipart_password", w.FormDataContentType(), multipartBody.String(), `{"echo":"multipart-private-value"}`, "multipart-private-value", false},
		{"malformed_form", "application/x-www-form-urlencoded", "token=form-private-value&note=x;y", `{"echo":"form-private-value"}`, "form-private-value", false},
		{"malformed_sensitive_form_pair", "application/x-www-form-urlencoded", "token=malformed;private-value&note=%ZZ", `{"echo":"malformed;private-value"}`, "malformed;private-value", false},
		{"truncated_json", "application/json", `{"password":"truncated-private-value","note":"` + strings.Repeat("a", 1000) + "\n…[已截断]", `{"echo":"truncated-private-value"}`, "truncated-private-value", false},
		{"invalid_json", "application/problem+json", `{"password":"incomplete-private-value"`, "", "incomplete-private-value", true},
		{"invalid_multipart", "multipart/form-data; boundary=expected", "--expected\r\nContent-Disposition: form-data; name=\"password\"\r\n\r\nbroken-private-value", "", "broken-private-value", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, _, c := startRecServer(t)
			q := &ReqRecord{ReqHeaders: map[string]string{"Content-Type": tt.contentType}, ReqBody: tt.body, RespBody: tt.response, RespMime: "application/json"}
			seedRecRequest(t, app, q)
			text := mustTool(t, c, "rec_get_request", map[string]any{"request_id": q.ID})
			out := decodeRec(t, text)
			rejectRecLiterals(t, text, tt.secret)
			if out["req_body_hidden"] != tt.hidden {
				t.Fatalf("hidden=%v: %s", tt.hidden, text)
			}
			if out["req_body_total"] != float64(len(tt.body)) {
				t.Fatalf("original length lost: %s", text)
			}
			if tt.hidden && out["req_body"] != hiddenRecBody {
				t.Fatalf("unsafe body fallback: %s", text)
			}
			if tt.name == "truncated_json" && (out["req_body_partial"] != true || out["req_body"] == hiddenRecBody) {
				t.Fatalf("truncated body should be a partial sanitize: %s", text)
			}
			if tt.name == "multipart_password" && !strings.Contains(out["req_body"].(string), "keep this field") {
				t.Fatalf("safe multipart field lost: %s", text)
			}
			if tt.name == "malformed_form" && !strings.Contains(out["req_body"].(string), "x%3By") {
				t.Fatalf("malformed form field lost: %s", text)
			}
		})
	}
}

func TestRecSecurityHeadersEscapesAndShortValues(t *testing.T) {
	app, _, c := startRecServer(t)
	password := "quote\"slash\\newline\nprivate"
	q := &ReqRecord{
		ReqHeaders:  map[string]string{"Content-Type": "application/json", "Cookie": "a=first-cookie-private; b=middle-cookie-private; c=last-cookie-private", "Referer": "https://example.com/?token=referer-private"},
		ReqBody:     string(compactJSON(map[string]any{"password": password, "echo": password, "credentials": map[string]any{"value": "xy"}, "short_echo": "xy", "normal": "xylophone"})),
		RespHeaders: map[string]string{"Location": "https://example.com/callback?access_token=location-private", "Content-Location": "https://example.com/result?token=content-location-private", "Set-Cookie": "a=first-set-private; Expires=Wed, 09 Jun 2027 10:18:14 GMT; Path=/, b=middle-set-private; Path=/\nc=last-set-private; Path=/"},
		RespMime:    "application/json",
		RespBody:    string(compactJSON(map[string]any{"cookie": "middle-cookie-private", "set_cookie_echo": "middle-set-private", "redirect_echo": "location-private", "password_echo": password, "short_echo": "xy", "normal": "xylophone"})),
	}
	seedRecRequest(t, app, q)
	text := mustTool(t, c, "rec_get_request", map[string]any{"request_id": q.ID, "max_body": 10000})
	out := decodeRec(t, text)
	rejectRecLiterals(t, text, password, "middle-cookie-private", "middle-set-private", "location-private", "referer-private", "content-location-private")
	for _, key := range []string{"req_body", "resp_body"} {
		body := decodeRec(t, out[key].(string))
		for _, field := range []string{"echo", "password_echo"} {
			if value, ok := body[field]; ok && value != secretMask {
				t.Fatalf("escaped password echo survived: %s", text)
			}
		}
		if body["short_echo"] != "xy" || body["normal"] != "xylophone" {
			t.Fatalf("short literal handling: %s", text)
		}
	}
	if replaceLiterals(`echo=a\"b and a"b`, []string{`a"b`}) != "echo=****** and ******" {
		t.Fatal("JSON escaped form was not scrubbed")
	}
	if got := replaceLiterals("7 17 7.0", []string{"7"}); got != "****** 17 ******.0" {
		t.Fatalf("short token mask: %q", got)
	}
}

func TestRecSecurityRecordingWideAndErrors(t *testing.T) {
	app, _, c := startRecServer(t)
	secret := "recording-wide-private"
	q := &ReqRecord{URL: "https://example.com/reset/" + secret}
	seedRecRequest(t, app, q)
	other := &ReqRecord{RecordingID: q.RecordingID, Seq: 2, Noise: true, RespMime: "application/json", RespBody: `{"credentials":[{"value":"` + secret + `"}]}`}
	seedRecRequest(t, app, other)
	if err := app.store.SetRecordingSummary(q.RecordingID, "重置 "+secret); err != nil {
		t.Fatal(err)
	}
	if err := app.store.SetRequestNote(RequestNote{RequestID: q.ID, RecordingID: q.RecordingID, Category: "query", Purpose: "检查 " + secret, Source: "agent"}); err != nil {
		t.Fatal(err)
	}
	text := mustTool(t, c, "rec_get_recording", map[string]any{"recording_id": q.RecordingID})
	rejectRecLiterals(t, text, secret)
	if !strings.Contains(text, "/reset/******") {
		t.Fatalf("path not masked: %s", text)
	}
	text, bad := c.tool("rec_annotate", map[string]any{"recording_id": q.RecordingID, "notes": []any{map[string]any{"request_id": q.ID, "category": secret}}})
	if !bad || decodeRec(t, text)["error"] == nil {
		t.Fatalf("not a JSON error: %s", text)
	}
	rejectRecLiterals(t, text, secret)
	if err := app.vault.Upsert("error_secret", "secret", "error-vault-private", "https://example.com", ""); err != nil {
		t.Fatal(err)
	}
	if err := app.store.SavePack(&Pack{Name: "ops-error-vault-private", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	for _, pack := range []string{"", "unknown"} {
		text, bad := c.tool("rec_save_tool", map[string]any{"request_id": q.ID, "name": "safe_tool", "pack": pack})
		if !bad || decodeRec(t, text)["error"] == nil {
			t.Fatalf("not a JSON error: %s", text)
		}
		rejectRecLiterals(t, text, "error-vault-private")
	}
}

func TestRecSecurityTypedJSONAndCandidates(t *testing.T) {
	app, _, c := startRecServer(t)
	if err := app.vault.Upsert("numeric_secret", "secret", "200", "https://example.com", ""); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{"large": strings.Repeat("界", 5000)}
	for i := 0; i < 150; i++ {
		body[fmt.Sprintf("field_%03d", i)] = strings.Repeat("a", 300)
	}
	q := &ReqRecord{URL: "https://example.com/search?page=2000", ReqHeaders: map[string]string{"Content-Type": "application/json"}, ReqBody: string(compactJSON(body)), Status: 200}
	seedRecRequest(t, app, q)
	text := mustTool(t, c, "rec_get_request", map[string]any{"request_id": q.ID, "max_body": 0})
	out := decodeRec(t, text)
	if out["status"] != float64(200) || out["req_body"] != "" {
		t.Fatalf("typed output corrupted: %s", text)
	}
	if out["query"].([]any)[0].(map[string]any)["value"] != "2000" {
		t.Fatalf("short vault value corrupted a longer token: %s", text)
	}
	if out["candidates_truncated"] != true {
		t.Fatal("aggregate candidate cap missing")
	}
	candidates := out["candidates"].([]any)
	if len(compactJSON(candidates)) > 16100 || len(candidates) > 100 {
		t.Fatalf("candidate budget exceeded: %d", len(compactJSON(candidates)))
	}
	for _, item := range candidates {
		row := item.(map[string]any)
		if len(row["example"].(string)) > 200 || !utf8.ValidString(row["example"].(string)) || (row["example_total"].(float64) > 200 && row["example_truncated"] != true) {
			t.Fatalf("unbounded example: %+v", row)
		}
	}
	if _, present := out["write"]; present {
		t.Fatal("POST search declared a write")
	}
	if !strings.Contains(out["write_hint"].(string), "可能") {
		t.Fatal("method hint missing")
	}
}

func TestRecSecuritySaveSchemasAndTemplates(t *testing.T) {
	app, _, c := startRecServer(t)
	if err := app.store.SetSetting("mcp_mode", ModeFlat); err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{"prefix_secret": "vault-private", "existing_ref": "kept-private"} {
		if err := app.vault.Upsert(name, "secret", value, "https://example.com", ""); err != nil {
			t.Fatal(err)
		}
	}
	q := &ReqRecord{ReqHeaders: map[string]string{"Content-Type": "application/json"}, ReqBody: `{"credentials":{"value":"ancestor-private"},"password":"secret","known":"{{secret.existing_ref}}","metadata":"prefix-vault-private","id":"ORD-7","amount":42,"enabled":true}`}
	seedRecRequest(t, app, q)
	text := mustTool(t, c, "rec_save_tool", map[string]any{"request_id": q.ID, "pack": "safe pack", "create_pack": true, "name": "safe_saved", "params": []any{
		map[string]any{"from": "body:credentials.value", "name": "credential_value", "description": "ancestor-private"},
		map[string]any{"from": "body:metadata", "name": "meta"},
		map[string]any{"from": "body:id", "name": "order_id", "description": "prefix-vault-private and ancestor-private", "required": false, "default": "ORD-default"},
	}})
	rejectRecLiterals(t, text, "ancestor-private", "vault-private")
	tool, err := app.store.GetToolByName("safe_saved")
	if err != nil {
		t.Fatal(err)
	}
	rejectRecLiterals(t, string(compactJSON(tool)), "ancestor-private", "vault-private")
	body := decodeRec(t, tool.Body)
	if body["known"] != "{{secret.existing_ref}}" || body["amount"] != float64(42) || body["enabled"] != true {
		t.Fatalf("template structure or reference corrupted: %s", tool.Body)
	}
	// New secrets are required parameters. Only an existing vault value is reused.
	cred := body["credentials"].(map[string]any)["value"].(string)
	meta := fmt.Sprint(body["metadata"])
	if !strings.Contains(cred, "{{") || strings.Contains(cred, "ancestor-private") || strings.Contains(meta, "vault-private") || strings.Contains(meta, "ancestor-private") {
		t.Fatalf("sensitive value not parameterized: %s", tool.Body)
	}
	if app.vault.FindByValue("ancestor-private") != "" {
		t.Fatal("save created a vault entry for a new secret")
	}
	for _, p := range tool.Params {
		if strings.Contains(p.Default, "private") || strings.Contains(p.Description, "private") {
			t.Fatalf("persisted schema leaked: %+v", p)
		}
	}
	_, listed := c.call("tools/list", map[string]any{})
	rejectRecLiterals(t, string(compactJSON(listed)), "ancestor-private", "vault-private")
	if err := app.store.SetSetting("mcp_mode", ModeTiered); err != nil {
		t.Fatal(err)
	}
	loaded := mustTool(t, c, "load_pack", map[string]any{"pack": "safe pack"})
	rejectRecLiterals(t, loaded, "ancestor-private", "vault-private")
}

func TestRecSecurityParameterizeParsedValues(t *testing.T) {
	q := &ReqRecord{ReqHeaders: map[string]string{"Content-Type": "application/json"}, ReqBody: `{"credentials":{"value":123},"password":"secret","known":"{{secret.existing}}","normal":99,"enabled":true}`}
	tool := &Tool{URL: "https://example.com/?token=123", Body: q.ReqBody}
	if err := parameterizeRawSecrets(tool, q); err != nil {
		t.Fatal(err)
	}
	body := decodeRec(t, tool.Body)
	if body["known"] != "{{secret.existing}}" || body["normal"] != float64(99) || body["enabled"] != true {
		t.Fatalf("typed values or refs changed: %s", tool.Body)
	}
	if body["credentials"].(map[string]any)["value"] == float64(123) {
		t.Fatal("sensitive numeric field not parameterized")
	}
	for _, p := range tool.Params {
		if p.Default != "" || !p.Required {
			t.Fatalf("secret parameter kept default: %+v", p)
		}
	}
}

func TestRecSecuritySaveTypedSecrets(t *testing.T) {
	app, _, c := startRecServer(t)
	q := &ReqRecord{ReqHeaders: map[string]string{"Content-Type": "application/json"}, ReqBody: `{"pin":7,"credentials":{"value":12345},"normal":42,"enabled":true}`}
	seedRecRequest(t, app, q)
	detail := decodeRec(t, mustTool(t, c, "rec_get_request", map[string]any{"request_id": q.ID}))
	body := decodeRec(t, detail["req_body"].(string))
	if body["pin"] != secretMask || body["credentials"] != secretMask {
		t.Fatalf("typed secret fields survived: %v", body)
	}
	mustTool(t, c, "rec_save_tool", map[string]any{"request_id": q.ID, "pack": "typed", "create_pack": true, "name": "typed_secrets"})
	tool, err := app.store.GetToolByName("typed_secrets")
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]any{}
	for _, p := range tool.Params {
		if p.Type != "number" || !p.Required || p.Default != "" {
			t.Fatalf("secret type/default lost: %+v", p)
		}
		if p.Name == "pin" {
			args[p.Name] = float64(8)
		} else {
			args[p.Name] = float64(67890)
		}
	}
	if len(args) != 2 {
		t.Fatalf("missing typed secret params: %+v", tool.Params)
	}
	_, _, _, rendered, err := tool.RenderWith(args, app.vault.Resolve, nil)
	if err != nil {
		t.Fatal(err)
	}
	body = decodeRec(t, rendered)
	if body["pin"] != float64(8) || body["credentials"].(map[string]any)["value"] != float64(67890) || body["normal"] != float64(42) || body["enabled"] != true {
		t.Fatalf("render changed scalar types: %s", rendered)
	}
}

func TestRecParamSourcesAndPackResolution(t *testing.T) {
	app, _, c := startRecServer(t)
	ops := &Pack{Name: "Ops", Enabled: true}
	lower := &Pack{Name: "ops", Enabled: false}
	for _, p := range []*Pack{ops, lower} {
		if err := app.store.SavePack(p); err != nil {
			t.Fatal(err)
		}
	}
	q := &ReqRecord{URL: "https://example.com/search?id=query-id", ReqHeaders: map[string]string{"Content-Type": "application/json"}, ReqBody: `{"id":"body-id"}`}
	seedRecRequest(t, app, q)
	for _, tc := range []struct {
		specs []any
		want  string
	}{
		{[]any{map[string]any{"from": "query:id", "name": "id"}, map[string]any{"from": "body:id", "name": "id"}}, "名称重复"},
		{[]any{map[string]any{"from": "query:id", "name": "first"}, map[string]any{"from": "query.id", "name": "second"}}, "来源重复"},
	} {
		text, bad := c.tool("rec_save_tool", map[string]any{"request_id": q.ID, "pack": "ops", "name": "duplicate", "params": tc.specs})
		if !bad || !strings.Contains(decodeRec(t, text)["error"].(string), tc.want) {
			t.Fatalf("duplicate accepted: %s", text)
		}
	}
	if _, err := app.store.GetToolByName("duplicate"); err == nil {
		t.Fatal("duplicate saved")
	}
	text, bad := c.tool("rec_save_tool", map[string]any{"request_id": q.ID, "pack": "OPS", "name": "ambiguous"})
	if !bad || !strings.Contains(text, "不唯一") || !strings.Contains(text, "Ops") || !strings.Contains(text, "ops") {
		t.Fatalf("ambiguous match: %s", text)
	}
	text = mustTool(t, c, "rec_save_tool", map[string]any{"request_id": q.ID, "pack": "ops", "name": "separate_ids", "params": []any{
		map[string]any{"from": "query:id", "name": "query_id", "description": "query description", "required": true, "default": "query-default"},
		map[string]any{"from": "body:id", "name": "body_id", "description": "body description", "required": false, "default": "body-default"},
	}})
	out := decodeRec(t, text)
	if out["pack_id"] != float64(lower.ID) || out["pack_enabled"] != false {
		t.Fatalf("exact match did not win: %s", text)
	}
	tool, err := app.store.GetToolByName("separate_ids")
	if err != nil {
		t.Fatal(err)
	}
	params := map[string]Param{}
	for _, p := range tool.Params {
		params[p.Name] = p
	}
	if params["query_id"].Description != "query description" || params["query_id"].Default != "query-default" || !params["query_id"].Required || params["body_id"].Description != "body description" || params["body_id"].Default != "body-default" || params["body_id"].Required {
		t.Fatalf("overrides applied to wrong source: %+v", params)
	}
	if p, _, msg := app.lookupTargetPack(fmt.Sprint(ops.ID), false); msg != "" || p.ID != ops.ID {
		t.Fatalf("numeric pack match: %v %s", p, msg)
	}
}

func TestRecSaveAtomicAndInlineNotifications(t *testing.T) {
	for _, mode := range []string{ModeFlat, ModeTiered} {
		t.Run(mode, func(t *testing.T) {
			app, _, c := startRecServer(t)
			if err := app.store.SetSetting("mcp_mode", mode); err != nil {
				t.Fatal(err)
			}
			p := &Pack{Name: "target", Enabled: true}
			if err := app.store.SavePack(p); err != nil {
				t.Fatal(err)
			}
			if mode == ModeTiered {
				mustTool(t, c, "load_pack", map[string]any{"pack": "target"})
			}
			q := &ReqRecord{}
			seedRecRequest(t, app, q)
			msgs, reply := c.call("tools/call", map[string]any{"name": "rec_save_tool", "arguments": map[string]any{"request_id": q.ID, "pack": "target", "name": "inline_saved"}})
			if reply["result"].(map[string]any)["isError"] == true {
				t.Fatalf("save failed: %v", reply)
			}
			found := false
			for _, m := range msgs {
				if m["method"] == "notifications/tools/list_changed" {
					found = true
				}
			}
			if !found || !has(c.toolNames(), "inline_saved") {
				t.Fatalf("inline notification/tool missing: %v", msgs)
			}
			old, err := app.store.GetToolByName("inline_saved")
			if err != nil {
				t.Fatal(err)
			}
			if _, err := app.store.db.Exec(`CREATE TRIGGER reject_rec_member BEFORE INSERT ON pack_tools BEGIN SELECT RAISE(ABORT,'membership failed'); END`); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"new_failed", "inline_saved"} {
				text, bad := c.tool("rec_save_tool", map[string]any{"request_id": q.ID, "pack": "target", "name": name, "overwrite": true, "description": "should roll back"})
				if !bad || decodeRec(t, text)["error"] == nil {
					t.Fatalf("membership failure ignored: %s", text)
				}
			}
			if _, err := app.store.GetToolByName("new_failed"); err == nil {
				t.Fatal("orphan tool after membership failure")
			}
			got, err := app.store.GetTool(old.ID)
			if err != nil || got.Description != old.Description {
				t.Fatalf("overwrite survived rollback: %+v %v", got, err)
			}
			if _, err := app.store.db.Exec(`CREATE TRIGGER reject_rec_pack BEFORE INSERT ON packs BEGIN SELECT RAISE(ABORT,'pack failed'); END`); err != nil {
				t.Fatal(err)
			}
			text, bad := c.tool("rec_save_tool", map[string]any{"request_id": q.ID, "pack": "new pack", "create_pack": true, "name": "pack_failed"})
			if !bad || !strings.Contains(text, "创建流程包失败") {
				t.Fatalf("pack failure ignored: %s", text)
			}
			if _, err := app.store.GetToolByName("pack_failed"); err == nil {
				t.Fatal("tool saved before pack creation")
			}
		})
	}
}

func TestRecSettingsAtomic(t *testing.T) {
	app, handler, c := startRecServer(t)
	stream := make(chan []byte, 4)
	session := app.session(c.sid)
	session.stream = stream
	if _, err := app.store.db.Exec(`CREATE TRIGGER reject_rec_setting BEFORE INSERT ON settings WHEN NEW.key='rec_analysis' BEGIN SELECT RAISE(ABORT,'setting failed'); END`); err != nil {
		t.Fatal(err)
	}
	code, _ := apiRaw(t, handler, "PUT", "https://example.com/api/settings", `{"mcp_mode":"flat","rec_analysis":false}`)
	if code != 500 || app.mcpMode() != ModeTiered || !app.recAnalysisEnabled() {
		t.Fatal("partial settings update")
	}
	if len(stream) != 0 {
		t.Fatal("broadcast on failed settings transaction")
	}
	if _, err := app.store.db.Exec(`DROP TRIGGER reject_rec_setting`); err != nil {
		t.Fatal(err)
	}
	code, _ = apiRaw(t, handler, "PUT", "https://example.com/api/settings", `{"mcp_mode":"invalid","rec_analysis":false}`)
	if code != 400 || !app.recAnalysisEnabled() || len(stream) != 0 {
		t.Fatal("invalid settings changed state")
	}
	code, _ = apiRaw(t, handler, "PUT", "https://example.com/api/settings", `{"mcp_mode":"flat","rec_analysis":false}`)
	if code != 200 || app.mcpMode() != ModeFlat || app.recAnalysisEnabled() || len(stream) != 1 {
		t.Fatal("settings not committed and broadcast together")
	}
}

func TestRecExistingPackNameCollision(t *testing.T) {
	app, handler, c := startRecServer(t)
	r, err := app.store.db.Exec(`INSERT INTO packs(name,description,enabled,created_at) VALUES(?,?,1,?)`, recPackName, "legacy user pack", now())
	if err != nil {
		t.Fatal(err)
	}
	id, err := r.LastInsertId()
	if err != nil {
		t.Fatal(err)
	}
	p := &Pack{ID: id, Name: recPackName, Enabled: true, Description: "updated legacy pack"}
	if err := app.store.SavePack(p); err != nil {
		t.Fatalf("existing pack cannot update: %v", err)
	}
	code, _ := apiRaw(t, handler, "PUT", fmt.Sprintf("https://example.com/api/packs/%d", id), string(compactJSON(p)))
	if code != 200 {
		t.Fatalf("REST update failed: %d", code)
	}
	if err := app.store.SavePack(&Pack{Name: recPackName, Enabled: true}); err == nil {
		t.Fatal("new reserved pack allowed")
	}
	text := mustTool(t, c, "load_pack", map[string]any{"pack": recPackName})
	if decodeRec(t, text)["pack_id"] != float64(id) {
		t.Fatalf("legacy pack shadowed: %s", text)
	}
	text = mustTool(t, c, "load_pack", map[string]any{"pack": recPackID})
	if decodeRec(t, text)["builtin"] != true {
		t.Fatalf("builtin id ambiguous: %s", text)
	}
	listed := decodeRec(t, mustTool(t, c, "list_packs", map[string]any{}))
	builtin, user := false, false
	for _, item := range listed["packs"].([]any) {
		row := item.(map[string]any)
		if row["id"] == float64(recPackID) {
			builtin = row["builtin"] == true
		}
		if row["id"] == float64(id) {
			user = row["builtin"] != true
		}
	}
	if !builtin || !user {
		t.Fatalf("collision not distinguishable: %v", listed)
	}
	q := &ReqRecord{}
	seedRecRequest(t, app, q)
	text = mustTool(t, c, "rec_save_tool", map[string]any{"request_id": q.ID, "pack": recPackName, "name": "legacy_target"})
	if decodeRec(t, text)["pack_id"] != float64(id) {
		t.Fatalf("legacy save target shadowed: %s", text)
	}
	if err := app.store.SetSetting(settingRecAnalysis, "off"); err != nil {
		t.Fatal(err)
	}
	text = mustTool(t, c, "load_pack", map[string]any{"pack": recPackName})
	if decodeRec(t, text)["pack_id"] != float64(id) {
		t.Fatalf("disabled builtin shadows legacy pack: %s", text)
	}
}
