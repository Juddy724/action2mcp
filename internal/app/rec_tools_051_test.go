package app

import (
	"action2mcp/internal/execution"
	"action2mcp/internal/mwconfig"
	"action2mcp/internal/recording"
	"action2mcp/internal/store"
	"bytes"
	"encoding/json"
	"mime/multipart"
	"strings"
	"testing"
)

const (
	fakeToken = "tok-FAKE-123456789abcdef"
	fakeJWT   = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJmYWtlIn0.c2lnbmF0dXJl"
	fakeSID   = "FAKE-SESSION-abcdef123456"
)

func TestSensitiveKeyTable(t *testing.T) {
	yes := []string{
		"password", "passwd", "pwd", "passcode", "pass", "secret", "client_secret", "token",
		"access_token", "refresh_token", "authToken", "x-auth-token", "cookie", "set-cookie",
		"authorization", "api_key", "apikey", "x-api-key", "session", "sessionid", "sid",
		"jsessionid", "csrf", "xsrf", "csrf_token", "xsrf_token", "bearer", "credential",
		"credentials", "jwt", "private_key", "access_key", "secret_key", "pin", "otp",
		"signature", "sign",
	}
	no := []string{
		"passwordStrength", "passwordPolicy", "keepLogin", "rememberMe", "editor",
		"tokenType", "token_type", "expires_in", "login", "loginName", "account", "username",
		"retry_count", "name_length", "passwordHint", "value",
	}
	for _, k := range yes {
		if !execution.IsSensitiveKey(k) {
			t.Errorf("expected sensitive: %s", k)
		}
	}
	for _, k := range no {
		if execution.IsSensitiveKey(k) {
			t.Errorf("expected not sensitive: %s", k)
		}
	}
	if !execution.PathSensitive("credentials.value") || execution.IsSensitiveKey("credentials.value") {
		t.Fatal("children of a sensitive key are sensitive; the last segment alone is not")
	}
}

func TestRec051LeaksAndOvermask(t *testing.T) {
	app, _, c := startRecServer(t)
	if err := app.vault.Upsert("short_one", "secret", "1", "https://api.example.com", ""); err != nil {
		t.Fatal(err)
	}
	if err := app.vault.Upsert("short_true", "secret", "true", "https://api.example.com", ""); err != nil {
		t.Fatal(err)
	}
	frame := "execute " + string(execution.CompactJSON(map[string]any{"data": map[string]any{"n": 1}, "token": fakeToken}))
	reqBody := string(execution.CompactJSON(map[string]any{"frames": []any{map[string]any{"op": 1, "text": frame}}}))
	inner := string(execution.CompactJSON(map[string]any{"token": fakeJWT}))
	mid := string(execution.CompactJSON(map[string]any{"headers": inner}))
	resp := string(execution.CompactJSON(map[string]any{"body": mid, "ua": "Mozilla/5.0 (X11) Chrome/157.0.0.0", "q": "zh;q=0.9"}))
	q := &recording.Request{
		Method: "GET",
		URL:    "https://api.example.com/message-ajaxGetMessage-1.html?rpcId=1.1",
		ReqHeaders: map[string]string{
			"Content-Type":    "application/json",
			"User-Agent":      "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/157.0.0.0",
			"Accept-Language": "zh;q=0.9",
			"Cookie":          "theme=0; lang=1; sid=" + fakeSID,
		},
		ReqBody:      reqBody,
		RespMime:     "application/json",
		RespBody:     resp,
		ResourceType: "WebSocket",
		Status:       101,
	}
	seedRecRequest(t, app, q)
	detail := mustTool(t, c, "rec_get_request", map[string]any{"request_id": q.ID, "max_body": 100000})
	rejectRecLiterals(t, detail, fakeToken, fakeJWT, fakeSID)
	for _, keep := range []string{"5.0", "q=0.9", "157.0.0.0", "message-ajaxGetMessage-1.html", "rpcId=1.1"} {
		if !strings.Contains(detail, keep) {
			t.Fatalf("over-masked %q in %s", keep, detail)
		}
	}
	recTxt := mustTool(t, c, "rec_get_recording", map[string]any{"recording_id": q.RecordingID, "include_noise": true})
	rejectRecLiterals(t, recTxt, fakeToken, fakeJWT, fakeSID)
	if !strings.Contains(recTxt, "message-ajaxGetMessage-1.html") {
		t.Fatalf("path chewed: %s", recTxt)
	}
	saved := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "pack": "leak pack", "create_pack": true, "name": "leak_check",
	})
	rejectRecLiterals(t, saved, fakeToken, fakeJWT, fakeSID)
	tool, err := app.store.GetToolByName("leak_check")
	if err != nil {
		t.Fatal(err)
	}
	blob := string(execution.CompactJSON(tool))
	rejectRecLiterals(t, blob, fakeToken, fakeJWT, fakeSID)
	if !strings.Contains(blob, "{{secret.") && !strings.Contains(blob, execution.RemovedSecretDescription) {
		t.Fatalf("nested secret was not parameterized: %s", blob)
	}
	_, listed := c.call("tools/list", map[string]any{})
	rejectRecLiterals(t, string(execution.CompactJSON(listed)), fakeToken, fakeJWT, fakeSID)

	if err := app.store.SavePack(&store.Pack{Name: "已有包", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	packs, err := app.store.ListPacks()
	if err != nil || len(packs) == 0 {
		t.Fatal(err)
	}
	bad, isErr := c.tool("rec_save_tool", map[string]any{"request_id": q.ID, "name": "leak_check", "pack": "没有这个包"})
	if !isErr || !strings.Contains(bad, "create_pack=true") || !strings.Contains(bad, "overwrite=true") {
		t.Fatalf("save error lost control words: %s", bad)
	}
	if !strings.Contains(bad, "id="+itoa64(packs[0].ID)) && !strings.Contains(bad, "(id=") {
		t.Fatalf("save error lost pack id: %s", bad)
	}
}

func itoa64(n int64) string {
	return strings.TrimPrefix(strings.TrimPrefix(jsonNumber(n), ""), "")
}

func jsonNumber(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestRec051GroupingAnnotateAndCompact(t *testing.T) {
	app, _, c := startRecServer(t)
	recID, err := app.store.CreateRecording("分组", "")
	if err != nil {
		t.Fatal(err)
	}
	mk := func(seq int, method, raw string, noise bool, reason, res string, status int) *recording.Request {
		t.Helper()
		q := &recording.Request{
			RecordingID: recID, Seq: seq, Method: method, URL: "https://app.example.com" + raw,
			ResourceType: res, Status: status, Noise: noise, NoiseReason: reason, RespMime: "application/json",
		}
		if err := app.store.InsertRequest(q); err != nil {
			t.Fatal(err)
		}
		return q
	}
	a := mk(1, "POST", "/pro/action-editComment-26875561.html", false, "", "Fetch", 200)
	b := mk(2, "POST", "/pro/action-editComment-99999999.html", true, "埋点/日志", "Fetch", 200)
	mk(3, "GET", "/pro/bug-view-729927.html", false, "", "Fetch", 200)
	mk(4, "GET", "/message-ajaxGetMessage-1.html", false, "", "Document", 200)
	mk(5, "GET", "/static/app.js", true, "静态资源", "Script", 200)
	mk(6, "OPTIONS", "/pro/bug-view-1.html", true, "跨域预检", "Other", 204)
	suspect := mk(7, "POST", "/api/hidden-call", true, "埋点/日志", "XHR", 200)
	mk(8, "GET", "/app/log/queryLogList", true, "页面加载", "Document", 200)

	txt := mustTool(t, c, "rec_get_recording", map[string]any{"recording_id": recID})
	out := decodeRec(t, txt)
	if _, ok := out["host"]; ok {
		t.Fatalf("row host should be an index: %s", txt)
	}
	hosts, _ := out["hosts"].([]any)
	if len(hosts) == 0 || hosts[0] != "app.example.com" {
		t.Fatalf("hosts: %s", txt)
	}
	var sawEdit, sawBug, sawMsg bool
	for _, item := range out["requests"].([]any) {
		row := item.(map[string]any)
		path := row["path"].(string)
		if strings.Contains(path, "26875561") || strings.Contains(path, "99999999") || strings.Contains(path, "729927") {
			t.Fatalf("raw id leaked in path: %s", txt)
		}
		switch path {
		case "/pro/action-editComment-{id}.html":
			sawEdit = true
			if row["example_path"] != "/pro/action-editComment-26875561.html" || row["mixed_noise"] != true {
				t.Fatalf("edit group: %s", txt)
			}
			if int(row["count"].(float64)) != 1 {
				t.Fatalf("business view should count business members only: %s", txt)
			}
			ids := row["ids"].([]any)
			if len(ids) != 2 || int64(ids[0].(float64)) != a.ID || int64(ids[1].(float64)) != b.ID {
				t.Fatalf("group ids include every member: %v", ids)
			}
			if int64(row["id"].(float64)) != a.ID {
				t.Fatalf("representative id: %v", row["id"])
			}
		case "/pro/bug-view-{id}.html":
			sawBug = true
		case "/message-ajaxGetMessage-1.html":
			sawMsg = true
			if _, ok := row["example_path"]; ok {
				t.Fatalf("untemplated path should not set example_path: %s", txt)
			}
		}
		if path == "/static/app.js" {
			t.Fatalf("static noise included by default: %s", txt)
		}
		if row["noise"] == false {
			t.Fatalf("false noise should be omitted: %s", txt)
		}
	}
	if !sawEdit || !sawBug || !sawMsg {
		t.Fatalf("groups missing: %s", txt)
	}
	sn, _ := out["suspect_noise"].([]any)
	if len(sn) == 0 || int64(sn[0].(map[string]any)["id"].(float64)) != suspect.ID {
		t.Fatalf("suspect_noise: %s", txt)
	}
	for _, item := range sn {
		p := item.(map[string]any)["path"].(string)
		if strings.HasSuffix(p, ".js") || strings.Contains(p, "bug-view-1") {
			t.Fatalf("static or preflight listed as suspect: %s", txt)
		}
	}
	if out["next_offset"] != nil || out["has_more"] != false {
		t.Fatalf("paging: %s", txt)
	}
	page := decodeRec(t, mustTool(t, c, "rec_get_recording", map[string]any{"recording_id": recID, "limit": 1}))
	if page["has_more"] != true || page["next_offset"] == nil || page["total_groups"] == nil {
		t.Fatalf("has_more: %v", page)
	}
	filtered := mustTool(t, c, "rec_get_recording", map[string]any{
		"recording_id": recID, "include_noise": true, "exclude_reasons": []any{"静态资源"}, "include_noise_reasons": []any{"埋点/日志"},
	})
	if strings.Contains(filtered, "/static/app.js") || !strings.Contains(filtered, "action-editComment") {
		t.Fatalf("filters: %s", filtered)
	}
	both := decodeRec(t, mustTool(t, c, "rec_get_recording", map[string]any{"recording_id": recID, "include_noise": true}))
	for _, item := range both["requests"].([]any) {
		row := item.(map[string]any)
		if row["path"] == "/pro/action-editComment-{id}.html" {
			if int(row["count"].(float64)) != 2 || row["mixed_noise"] != true {
				t.Fatalf("full group: %s", mustCompact(row))
			}
			ids := row["ids"].([]any)
			if int64(ids[0].(float64)) != a.ID || int64(ids[1].(float64)) != b.ID {
				t.Fatalf("id order: %v", ids)
			}
		}
	}

	note := mustTool(t, c, "rec_annotate", map[string]any{
		"recording_id": recID,
		"notes": []any{
			map[string]any{"request_id": b.ID, "apply_to_group": true, "category": "write", "purpose": "改评论", "noise_override": false},
			map[string]any{"request_ids": []any{suspect.ID}, "category": "query", "purpose": "可疑接口"},
		},
	})
	ann := decodeRec(t, note)
	if ann["summary_updated"] != false || strings.Contains(note, "改评论") || strings.Contains(note, `"notes"`) {
		t.Fatalf("annotate echoed notes: %s", note)
	}
	ids, _ := ann["request_ids"].([]any)
	if len(ids) != 3 || ann["updated"] != float64(3) {
		t.Fatalf("group annotate: %s", note)
	}
	stored, err := app.store.RequestNotes(recID)
	if err != nil || stored[a.ID].Category != "write" || stored[b.ID].NoiseOverride == nil || *stored[b.ID].NoiseOverride || stored[suspect.ID].Purpose != "可疑接口" {
		t.Fatalf("stored group notes: %+v %v", stored, err)
	}

	list := mustTool(t, c, "rec_list_recordings", map[string]any{})
	if !strings.Contains(list, `"origin":"https://app.example.com"`) {
		t.Fatalf("origin fallback: %s", list)
	}
}

func mustCompact(v any) string { return string(execution.CompactJSON(v)) }

func TestRec051PartialMultipartAndSave(t *testing.T) {
	app, _, c := startRecServer(t)
	body := `{"token":"` + fakeToken + `","note":"` + strings.Repeat("b", 40) + "\n…[已截断]" + fakeJWT
	q := &recording.Request{
		Method: "POST", URL: "https://api.example.com/api/taskLog/list",
		ResourceType: "Fetch", Status: 200, RespMime: "application/json",
		ReqHeaders: map[string]string{"Content-Type": "application/json"},
		ReqBody:    body,
		RespBody:   `{"echo":"` + fakeToken + `","jwt":"` + fakeJWT + `"}`,
	}
	seedRecRequest(t, app, q)
	text := mustTool(t, c, "rec_get_request", map[string]any{"request_id": q.ID, "max_body": 100000})
	out := decodeRec(t, text)
	rejectRecLiterals(t, text, fakeToken, fakeJWT)
	if out["req_body_partial"] != true || out["req_body_hidden"] == true {
		t.Fatalf("partial: %s", text)
	}
	if strings.Count(out["req_body"].(string), "…[已截断]") != 1 || !strings.HasSuffix(out["req_body"].(string), "…[已截断]") {
		t.Fatalf("expected exactly one trailing truncation marker: %s", text)
	}
	if n, _ := out["req_body_truncation"].(string); !strings.Contains(n, "采集") {
		t.Fatalf("missing capture truncation note: %s", text)
	}
	if _, ok := out["resp_body_truncation"]; ok {
		t.Fatalf("complete response must not carry a truncation note: %s", text)
	}

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("title", "hello"); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteField("token", fakeToken); err != nil {
		t.Fatal(err)
	}
	fw, err := w.CreateFormFile("file", "a.txt")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("file-bytes")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	mq := &recording.Request{
		Method: "POST", URL: "https://api.example.com/upload",
		ReqHeaders:   map[string]string{"Content-Type": w.FormDataContentType()},
		ReqBody:      buf.String(),
		ResourceType: "Document", Status: 200, RespBody: "",
	}
	seedRecRequest(t, app, mq)
	md := decodeRec(t, mustTool(t, c, "rec_get_request", map[string]any{"request_id": mq.ID}))
	if md["resp_body_note"] != "响应体未采集（页面文档/重定向等不记录响应体）" {
		t.Fatalf("resp note: %v", md["resp_body_note"])
	}
	var sawTitle, sawFile bool
	for _, item := range md["candidates"].([]any) {
		row := item.(map[string]any)
		if row["loc"] == "multipart" && row["path"] == "title" && row["example"] == "hello" {
			sawTitle = true
		}
		if row["path"] == "file" {
			sawFile = true
		}
		if row["path"] == "token" && (row["secret"] != true || row["example"] != "") {
			t.Fatalf("multipart token candidate: %v", row)
		}
	}
	if !sawTitle || sawFile {
		t.Fatalf("multipart candidates: %s", mustCompact(md["candidates"]))
	}
	gq := &recording.Request{Method: "GET", URL: "https://api.example.com/page", ResourceType: "Document", Status: 200}
	seedRecRequest(t, app, gq)
	gd := decodeRec(t, mustTool(t, c, "rec_get_request", map[string]any{"request_id": gq.ID}))
	if gd["req_body_note"] != "请求体未采集（该方法通常没有请求体）" {
		t.Fatalf("req note: %v", gd["req_body_note"])
	}

	bad, isErr := c.tool("rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "Bad Name", "pack": "",
		"params": []any{
			map[string]any{"name": "a", "from": "body:missing", "type": "nope"},
			map[string]any{"name": "a", "from": "body:also-missing", "type": "string"},
		},
	})
	if !isErr {
		t.Fatal(bad)
	}
	obj := decodeRec(t, bad)
	probs, _ := obj["problems"].([]any)
	if len(probs) < 3 {
		t.Fatalf("expected several problems: %s", bad)
	}
	joined := obj["error"].(string)
	for _, phrase := range []string{"name 不合法", "必须指定 pack", "type 只能是", "对不上"} {
		if !strings.Contains(joined, phrase) && !problemHas(probs, phrase) {
			t.Fatalf("missing %q in %s", phrase, bad)
		}
	}
	if _, err := app.store.GetToolByName("Bad Name"); err == nil {
		t.Fatal("invalid save persisted")
	}

	before, _ := app.store.ListPacks()
	dry := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": mq.ID, "name": "upload_title", "pack": "dry-pack", "create_pack": true, "dry_run": true,
		"params": []any{map[string]any{"name": "title", "from": "multipart:title"}},
	})
	d := decodeRec(t, dry)
	if d["dry_run"] != true || d["name"] != "upload_title" || d["input_schema"] == nil {
		t.Fatalf("dry_run: %s", dry)
	}
	rejectRecLiterals(t, dry, fakeToken)
	after, _ := app.store.ListPacks()
	if len(after) != len(before) {
		t.Fatal("dry_run created a pack")
	}
	if _, err := app.store.GetToolByName("upload_title"); err == nil {
		t.Fatal("dry_run saved a tool")
	}
	if _, ok := d["body"].(string); !ok {
		t.Fatalf("dry_run body: %s", dry)
	}
}

func problemHas(probs []any, phrase string) bool {
	for _, p := range probs {
		if s, ok := p.(string); ok && strings.Contains(s, phrase) {
			return true
		}
	}
	return false
}

func TestRec051NoiseAndMiddlewareCount(t *testing.T) {
	list := func(method, raw, res, mime, body string, status int) (bool, string) {
		q := &recording.Request{Method: method, URL: "https://app.example.com" + raw, ResourceType: res, RespMime: mime, RespBody: body, Status: status}
		return recording.ClassifyNoise(q)
	}
	if n, why := list("POST", "/api/taskLog/list", "Fetch", "application/json", `{"list":[{"id":1}]}`, 200); n {
		t.Fatalf("taskLog list: %s", why)
	}
	if n, why := list("POST", "/api/businessLog/page", "Fetch", "application/json", `{"data":{"records":[{"id":1}],"total":3}}`, 200); n {
		t.Fatalf("businessLog page: %s", why)
	}
	if n, why := list("POST", "/app/log/queryLogList", "XHR", "application/json", `{"data":{"records":[1,2],"total":2}}`, 200); n {
		t.Fatalf("queryLogList: %s", why)
	}
	if n, why := list("POST", "/log/collect", "Fetch", "text/plain", "", 204); !n {
		t.Fatalf("collect should be noise: %s", why)
	}
	if n, _ := list("POST", "/beacon", "Ping", "", "", 204); !n {
		t.Fatal("beacon")
	}
	if n, _ := list("POST", "/mars/general/batch/collect", "Fetch", "text/plain", "", 200); !n {
		t.Fatal("batch collect")
	}
	if n, _ := recording.ClassifyNoise(&recording.Request{Method: "GET", URL: "https://www.google-analytics.com/g/collect", ResourceType: "Fetch", Status: 200}); !n {
		t.Fatal("analytics host")
	}
	if n, why := list("GET", "/api/userinfo", "Fetch", "application/json", `{"data":{"records":[{"id":1}],"total":1}}`, 200); n {
		t.Fatalf("business userinfo guarded: %s", why)
	}

	app, _, c := startRecServer(t)
	recID, err := app.store.CreateRecording("沿用", "https://app.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	first := &recording.Request{RecordingID: recID, Seq: 1, Method: "POST", URL: "https://app.example.com/log/collect", ResourceType: "Fetch", Status: 204, RespBody: ""}
	if err := app.store.InsertRequest(first); err != nil {
		t.Fatal(err)
	}
	off := false
	if err := app.store.SetRequestNote(recording.Note{RequestID: first.ID, RecordingID: recID, Category: "query", Purpose: "不是埋点", Source: "agent", NoiseOverride: &off}); err != nil {
		t.Fatal(err)
	}
	next := &recording.Request{RecordingID: recID, Method: "POST", URL: "https://app.example.com/log/collect", ResourceType: "Fetch", Status: 204}
	noise, why := app.store.ClassifyRecorded(next)
	if noise || why != "沿用之前的标注" {
		t.Fatalf("override carry: %v %s", noise, why)
	}

	db := &mwconfig.Middleware{Name: "订单库", Type: "mysql", Config: mwconfig.MWConfig{Host: "127.0.0.1", Port: 1, User: "u"}}
	if err := app.store.SaveMiddleware(db); err != nil {
		t.Fatal(err)
	}
	echo := &Tool{Name: "echo_one", Title: "回显", Method: "GET", URL: "https://api.example.com/echo"}
	if err := app.store.SaveTool(echo); err != nil {
		t.Fatal(err)
	}
	if err := app.store.SavePack(&store.Pack{Name: "计数包", Enabled: true, ToolIDs: []int64{echo.ID}, MiddlewareIDs: []int64{db.ID}}); err != nil {
		t.Fatal(err)
	}
	txt, _ := c.tool("list_packs", map[string]any{})
	var lp struct {
		Packs []struct {
			Name            string `json:"name"`
			ToolCount       int    `json:"tool_count"`
			MiddlewareCount int    `json:"middleware_count"`
		} `json:"packs"`
	}
	if err := json.Unmarshal([]byte(txt), &lp); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range lp.Packs {
		if p.Name == "计数包" && p.ToolCount == 1 && p.MiddlewareCount == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("middleware_count: %s", txt)
	}
}

func TestRecBodyTruncationMarkers(t *testing.T) {
	app, _, c := startRecServer(t)
	long := `{"items":[` + strings.Repeat(`{"name":"abcdefghij","n":1},`, 60) + `{"name":"end"}]}`
	q := &recording.Request{
		Method: "POST", URL: "https://api.example.com/api/list",
		ResourceType: "Fetch", Status: 200, RespMime: "application/json",
		ReqHeaders: map[string]string{"Content-Type": "application/json"},
		ReqBody:    `{"a":1}`,
		RespBody:   long,
	}
	seedRecRequest(t, app, q)
	text := mustTool(t, c, "rec_get_request", map[string]any{"request_id": q.ID, "max_body": 200})
	out := decodeRec(t, text)
	body, _ := out["resp_body"].(string)
	if out["resp_body_truncated"] != true || !strings.HasSuffix(body, "…[已截断]") {
		t.Fatalf("clipped body needs marker: %s", text)
	}
	if n, _ := out["resp_body_truncation"].(string); !strings.Contains(n, "max_body") || !strings.Contains(n, "原始体积") {
		t.Fatalf("clipped body needs note: %s", text)
	}
	if _, ok := out["req_body_truncation"]; ok || strings.Contains(out["req_body"].(string), "已截断") {
		t.Fatalf("small request body must be untouched: %s", text)
	}
	text = mustTool(t, c, "rec_get_request", map[string]any{"request_id": q.ID, "max_body": 100000})
	out = decodeRec(t, text)
	if _, ok := out["resp_body_truncation"]; ok || strings.Contains(out["resp_body"].(string), "已截断") {
		t.Fatalf("full body must not be marked: %s", text)
	}
}
