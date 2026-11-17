package app

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/url"
	"strings"
	"testing"
)

// Regression tests for the 0.5.1 review findings. Secrets and hosts are fake.

func forbidText(t *testing.T, label, text string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if p != "" && strings.Contains(text, p) {
			t.Fatalf("%s leaked %q\n%s", label, p, text)
		}
	}
}

func countTable(t *testing.T, app *App, table string) int {
	t.Helper()
	var n int
	if err := app.store.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func snapshotWrites(t *testing.T, app *App) [4]int {
	t.Helper()
	return [4]int{
		countTable(t, app, "vault"),
		countTable(t, app, "packs"),
		countTable(t, app, "tools"),
		countTable(t, app, "sites"),
	}
}

func assertNoWrites(t *testing.T, app *App, before [4]int) {
	t.Helper()
	if got := snapshotWrites(t, app); got != before {
		t.Fatalf("unexpected write: vault/packs/tools/sites %v, want %v", got, before)
	}
}

func TestReview051Finding01FailClosedStructured(t *testing.T) {
	app, _, c := startRecServer(t)
	recID, err := app.store.CreateRecording("截断", "https://api.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	// Command-prefixed JSON cut inside the token, plus a complete JWT earlier in the text.
	cut := "execute {\"note\":\"hello-field\",\"token\":\"" + fakeToken[:16]
	cmd := &ReqRecord{
		RecordingID: recID, Method: "POST", URL: "https://api.example.com/exec",
		ReqHeaders: map[string]string{"Content-Type": "text/plain"},
		ReqBody:    cut + "\n…[已截断]" + fakeJWT,
	}
	seedRecRequest(t, app, cmd)
	cmdText := mustTool(t, c, "rec_get_request", map[string]any{"request_id": cmd.ID, "max_body": 100000})
	forbidText(t, "command prefix", cmdText, "tok-FAKE", "eyJhbGci", fakeToken, fakeJWT)
	// Our own trailing marker is expected exactly once; the raw text after the
	// capture marker (the JWT) is already rejected by forbidText above.
	if strings.Count(cmdText, "…[已截断]") != 1 {
		t.Fatalf("expected exactly one truncation marker: %s", cmdText)
	}

	// Valid outer JSON whose inner string is incomplete JSON.
	inner := `{"token":"` + fakeToken
	outer := string(compactJSON(map[string]any{"wrap": inner}))
	nested := &ReqRecord{
		RecordingID: recID, Method: "POST", URL: "https://api.example.com/wrap",
		ReqHeaders: map[string]string{"Content-Type": "application/json"},
		ReqBody:    outer,
	}
	seedRecRequest(t, app, nested)
	nestedText := mustTool(t, c, "rec_get_request", map[string]any{"request_id": nested.ID, "max_body": 100000})
	forbidText(t, "inner json", nestedText, "tok-FAKE", fakeToken)

	// Depth exhaustion: a plain token nested in eight JSON strings is not under a sensitive key.
	deep := "depth-FAKE-token-xyz"
	for i := 0; i < 8; i++ {
		deep = string(compactJSON(map[string]any{"wrap": deep}))
	}
	if got := app.sanitizeString(deep, false, 0, nil); strings.Contains(got, "depth-FAKE-token-xyz") || !strings.Contains(got, structuredOmitted) {
		t.Fatalf("depth did not fail closed: %s", got)
	}
	deepReq := &ReqRecord{
		RecordingID: recID, Method: "POST", URL: "https://api.example.com/deep",
		ReqHeaders: map[string]string{"Content-Type": "application/json"},
		ReqBody:    deep,
	}
	seedRecRequest(t, app, deepReq)
	deepText := mustTool(t, c, "rec_get_request", map[string]any{"request_id": deepReq.ID, "max_body": 100000})
	forbidText(t, "deep request", deepText, "depth-FAKE-token-xyz")

	// Truncated multipart: complete parts are outlined; the incomplete file tail is dropped.
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("note", "keep-visible"); err != nil {
		t.Fatal(err)
	}
	if err := w.WriteField("password", fakeToken); err != nil {
		t.Fatal(err)
	}
	mp := &ReqRecord{
		RecordingID: recID, Method: "POST", URL: "https://api.example.com/mp-cut",
		ReqHeaders: map[string]string{"Content-Type": w.FormDataContentType()},
		ReqBody: buf.String() + "--" + w.Boundary() + "\r\n" +
			"Content-Disposition: form-data; name=\"blob\"; filename=\"x.json\"\r\n" +
			"Content-Type: application/json\r\n\r\n" +
			`{"token":"` + fakeJWT + "\n…[已截断]",
	}
	seedRecRequest(t, app, mp)
	mpText := mustTool(t, c, "rec_get_request", map[string]any{"request_id": mp.ID, "max_body": 100000})
	forbidText(t, "multipart cut", mpText, "tok-FAKE", "eyJhbGci", fakeToken, fakeJWT)
	if !strings.Contains(mpText, "keep-visible") || !strings.Contains(mpText, secretMask) {
		t.Fatalf("complete parts were not outlined: %s", mpText)
	}
}

func TestReview051Finding02MultipartFile(t *testing.T) {
	app, _, c := startRecServer(t)
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	fw, err := w.CreateFormFile("creds", "creds.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte(`{"password":"` + fakeToken + `"}`)); err != nil {
		t.Fatal(err)
	}
	bw, err := w.CreateFormFile("blob", "blob.bin")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bw.Write([]byte("\x00\x01" + fakeJWT)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	q := &ReqRecord{
		Method: "POST", URL: "https://api.example.com/upload",
		ReqHeaders: map[string]string{"Content-Type": w.FormDataContentType()},
		ReqBody:    buf.String(), Status: 200,
	}
	seedRecRequest(t, app, q)
	detail := mustTool(t, c, "rec_get_request", map[string]any{"request_id": q.ID, "max_body": 100000})
	forbidText(t, "get file", detail, fakeToken, fakeJWT, "tok-FAKE", "eyJhbGci")
	if !strings.Contains(detail, omittedFileValue) {
		t.Fatalf("binary file was not removed: %s", detail)
	}
	if !strings.Contains(detail, secretMask) && !strings.Contains(detail, "{{") && !strings.Contains(detail, structuredOmitted) {
		t.Fatalf("textual file was not sanitized: %s", detail)
	}

	before := snapshotWrites(t, app)
	dry := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "upload_creds", "pack": "file-pack", "create_pack": true, "dry_run": true,
	})
	forbidText(t, "dry_run file", dry, fakeToken, fakeJWT, "tok-FAKE", "eyJhbGci")
	if !strings.Contains(dry, omittedFileValue) {
		t.Fatalf("dry_run kept binary file: %s", dry)
	}
	assertNoWrites(t, app, before)

	saved := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "upload_creds", "pack": "file-pack", "create_pack": true,
	})
	forbidText(t, "save file", saved, fakeToken, fakeJWT, "tok-FAKE", "eyJhbGci")
	tool, err := app.store.GetToolByName("upload_creds")
	if err != nil {
		t.Fatal(err)
	}
	blob := tool.Body + string(compactJSON(tool))
	forbidText(t, "stored file", blob, fakeToken, fakeJWT, "tok-FAKE", "eyJhbGci")
	if !strings.Contains(tool.Body, omittedFileValue) {
		t.Fatalf("stored body kept binary file: %s", tool.Body)
	}
}

func TestReview051Finding03EncodedQuery(t *testing.T) {
	app, _, c := startRecServer(t)
	payload := string(compactJSON(map[string]any{"token": fakeToken, "note": "visible-note"}))
	rawURL := "https://api.example.com/search?payload=" + url.QueryEscape(payload) + "&again=" + url.QueryEscape(url.QueryEscape(payload))
	q := &ReqRecord{
		Method: "GET", URL: rawURL, Status: 200, ResourceType: "Fetch",
		RespMime: "application/json", RespBody: `{"ok":true}`,
	}
	seedRecRequest(t, app, q)
	detail := mustTool(t, c, "rec_get_request", map[string]any{"request_id": q.ID, "max_body": 100000})
	forbidText(t, "query url", detail, fakeToken, "tok-FAKE")
	out := decodeRec(t, detail)
	if !strings.Contains(out["url"].(string), "visible-note") && !strings.Contains(detail, "visible-note") {
		t.Fatalf("non-secret query text was dropped: %s", detail)
	}
	for _, item := range out["query"].([]any) {
		row := item.(map[string]any)
		if strings.Contains(row["value"].(string), "tok-FAKE") || strings.Contains(row["value"].(string), fakeToken) {
			t.Fatalf("query value leaked: %v", row)
		}
	}

	before := snapshotWrites(t, app)
	dry := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "search_payload", "pack": "query-pack", "create_pack": true, "dry_run": true,
		"params": []any{map[string]any{"name": "payload", "from": "query:payload", "description": payload}},
	})
	forbidText(t, "saved query", dry, fakeToken, "tok-FAKE")
	assertNoWrites(t, app, before)
	rejected, isErr := c.tool("rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "search_payload", "pack": "query-pack", "create_pack": true,
		"description": "look at " + payload, "title": "title " + payload,
		"params": []any{map[string]any{"name": "payload", "from": "query:payload", "description": payload, "default": payload}},
	})
	if !isErr || !strings.Contains(rejected, "已拒绝保存") {
		t.Fatalf("secret default accepted: %s", rejected)
	}
	forbidText(t, "query save error", rejected, fakeToken, "tok-FAKE")
	assertNoWrites(t, app, before)
	saved := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "search_payload", "pack": "query-pack", "create_pack": true,
		"description": "look at " + payload, "title": "title " + payload,
		"params": []any{map[string]any{"name": "payload", "from": "query:payload", "description": payload}},
	})
	forbidText(t, "save query", saved, fakeToken, "tok-FAKE")
	tool, err := app.store.GetToolByName("search_payload")
	if err != nil {
		t.Fatal(err)
	}
	forbidText(t, "stored query tool", tool.URL+"\n"+tool.Body+"\n"+tool.Description+"\n"+tool.Title+string(compactJSON(tool.Params)), fakeToken, "tok-FAKE")
}

func TestReview051Finding04SensitiveAncestry(t *testing.T) {
	app, _, c := startRecServer(t)
	const shortSecret = "Zk9q!"
	q := &ReqRecord{
		Method: "POST", URL: "https://api.example.com/login",
		ReqHeaders: map[string]string{"Content-Type": "application/json"},
		ReqBody:    string(compactJSON(map[string]any{"credentials": map[string]any{"value": shortSecret}, "note": "hello"})),
		Status:     200,
	}
	seedRecRequest(t, app, q)
	detail := decodeRec(t, mustTool(t, c, "rec_get_request", map[string]any{"request_id": q.ID}))
	forbidText(t, "detail", mustCompact(detail), shortSecret)
	var saw bool
	for _, item := range detail["candidates"].([]any) {
		row := item.(map[string]any)
		if row["path"] == "credentials.value" {
			saw = true
			if row["secret"] != true || row["example"] != "" {
				t.Fatalf("ancestry lost on candidate: %v", row)
			}
		}
	}
	if !saw {
		t.Fatalf("missing credentials.value candidate: %s", mustCompact(detail["candidates"]))
	}
	saved := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "rename_cred", "pack": "ancestry-pack", "create_pack": true,
		"params": []any{map[string]any{"name": "label", "from": "body:credentials.value", "description": "the value is " + shortSecret}},
	})
	forbidText(t, "save", saved, shortSecret)
	tool, err := app.store.GetToolByName("rename_cred")
	if err != nil {
		t.Fatal(err)
	}
	blob := tool.Body + "\n" + tool.Description + "\n" + string(compactJSON(tool.Params))
	forbidText(t, "renamed param", blob, shortSecret)
	var label *Param
	for i := range tool.Params {
		if tool.Params[i].Name == "label" {
			label = &tool.Params[i]
		}
	}
	if label == nil || !label.Required || label.Default != "" {
		t.Fatalf("renamed secret param: %+v", tool.Params)
	}
	if !label.Secret || !paramIsSecret(tool, *label) {
		t.Fatal("renamed secret flag lost")
	}
	legacy := *label
	legacy.Secret, legacy.Description = false, ""
	if !paramIsSecret(tool, legacy) {
		t.Fatal("legacy renamed secret location was not detected")
	}
	if strings.Contains(tool.Body, shortSecret) {
		t.Fatal(tool.Body)
	}
}

func TestReview051Finding05SavedMetadata(t *testing.T) {
	app, _, c := startRecServer(t)
	if err := app.store.SetSetting("mcp_mode", ModeFlat); err != nil {
		t.Fatal(err)
	}
	const other = "other-FAKE-secret-zzz"
	nested := string(compactJSON(map[string]any{"password": other}))
	q := &ReqRecord{
		Method: "POST", URL: "https://api.example.com/items",
		ReqHeaders: map[string]string{"Content-Type": "application/json"},
		ReqBody:    string(compactJSON(map[string]any{"q": "hello", "token": fakeToken})),
		Status:     200,
	}
	seedRecRequest(t, app, q)
	saved := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "meta_tool", "pack": "meta-pack", "create_pack": true,
		"title": fakeJWT, "description": nested,
		"params": []any{map[string]any{"name": "q", "from": "body:q", "description": nested}},
	})
	forbidText(t, "save meta", saved, other, fakeJWT, "eyJhbGci", fakeToken, "tok-FAKE")
	tool, err := app.store.GetToolByName("meta_tool")
	if err != nil {
		t.Fatal(err)
	}
	blob := tool.Title + "\n" + tool.Description + "\n" + tool.Body + "\n" + string(compactJSON(tool.Params))
	forbidText(t, "stored meta", blob, other, fakeJWT, "eyJhbGci", fakeToken, "tok-FAKE")
	for _, p := range tool.Params {
		if p.Name == "q" && strings.Contains(p.Description, other) {
			t.Fatalf("param description: %+v", p)
		}
		if (p.Name == "token" || isSensitiveKey(p.Name) || p.Required) && p.Default != "" && (strings.Contains(p.Default, "tok-FAKE") || strings.Contains(p.Default, other)) {
			t.Fatalf("default kept: %+v", p)
		}
	}
	_, listed := c.call("tools/list", map[string]any{})
	forbidText(t, "tools/list", string(compactJSON(listed)), other, fakeJWT, "eyJhbGci", fakeToken, "tok-FAKE")
	if err := app.store.SetSetting("mcp_mode", ModeTiered); err != nil {
		t.Fatal(err)
	}
	loaded := mustTool(t, c, "load_pack", map[string]any{"pack": "meta-pack"})
	forbidText(t, "load_pack", loaded, other, fakeJWT, "eyJhbGci", fakeToken, "tok-FAKE")

	rejected, isErr := c.tool("rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "meta_tool_2", "pack": "meta-pack",
		"params": []any{map[string]any{"name": "q", "from": "body:q", "default": nested}},
	})
	if !isErr {
		t.Fatalf("secret default accepted: %s", rejected)
	}
	forbidText(t, "default error", rejected, other, fakeToken, "tok-FAKE")
	if _, err := app.store.GetToolByName("meta_tool_2"); err == nil {
		t.Fatal("rejected default was stored")
	}

	badName, isErr := c.tool("rec_save_tool", map[string]any{
		"request_id": q.ID, "name": fakeToken, "pack": "meta-pack",
	})
	if !isErr || !strings.Contains(badName, "密钥或凭证") {
		t.Fatalf("credential tool name: %s", badName)
	}
	forbidText(t, "name error", badName, fakeToken, "tok-FAKE")

	vaultN := len(app.vault.List())
	badPack, isErr := c.tool("rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "ok_name", "pack": "pack-" + fakeToken, "create_pack": true,
	})
	if !isErr || !strings.Contains(badPack, "密钥或凭证") {
		t.Fatalf("credential pack name: %s", badPack)
	}
	forbidText(t, "pack error", badPack, fakeToken, "tok-FAKE")
	if len(app.vault.List()) != vaultN {
		t.Fatal("rejected pack created a vault entry")
	}
	packs, err := app.store.ListPacks()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range packs {
		if strings.Contains(p.Name, "tok-FAKE") || strings.Contains(p.Name, fakeToken) {
			t.Fatalf("pack stored: %s", p.Name)
		}
	}
}

func TestReview051Finding06EncodedLiteral(t *testing.T) {
	app, _, c := startRecServer(t)
	const raw = "FAKE/secret-abcdef"
	encoded := url.QueryEscape(raw)
	if encoded == raw || !strings.Contains(encoded, "%2F") && !strings.Contains(encoded, "%2f") {
		t.Fatalf("fixture did not encode: %s", encoded)
	}
	q := &ReqRecord{
		Method: "POST", URL: "https://api.example.com/echo",
		ReqHeaders: map[string]string{"Content-Type": "application/json"},
		ReqBody:    string(compactJSON(map[string]any{"password": raw, "echo": encoded})),
		Status:     200,
	}
	seedRecRequest(t, app, q)
	dry := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "echo_encoded", "pack": "enc-pack", "create_pack": true, "dry_run": true,
	})
	forbidText(t, "dry encoded", dry, raw, encoded, "FAKE%2F", "FAKE%2f")
	saved := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "echo_encoded", "pack": "enc-pack", "create_pack": true,
	})
	forbidText(t, "save encoded", saved, raw, encoded, "FAKE%2F", "FAKE%2f")
	tool, err := app.store.GetToolByName("echo_encoded")
	if err != nil {
		t.Fatal(err)
	}
	forbidText(t, "stored encoded", tool.Body+string(compactJSON(tool)), raw, encoded, "FAKE%2F", "FAKE%2f")
}

func TestReview051Finding07PlaceholderSubstring(t *testing.T) {
	const mixed = "FAKE-secret{{x}}tail"
	if isWholePlaceholder(mixed) || !isWholePlaceholder("{{secret.known}}") || !isWholePlaceholder("{{a}}{{b}}") {
		t.Fatal("placeholder classification")
	}
	app, _, c := startRecServer(t)
	q := &ReqRecord{
		Method: "POST", URL: "https://api.example.com/mix",
		ReqHeaders: map[string]string{"Content-Type": "application/json"},
		ReqBody:    string(compactJSON(map[string]any{"password": mixed, "note": mixed})),
		Status:     200,
	}
	seedRecRequest(t, app, q)
	dry := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "mixed_secret", "pack": "mix-pack", "create_pack": true, "dry_run": true,
	})
	forbidText(t, "dry mixed", dry, mixed, "FAKE-secret")
	saved := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "mixed_secret", "pack": "mix-pack", "create_pack": true,
	})
	forbidText(t, "save mixed", saved, mixed, "FAKE-secret")
	tool, err := app.store.GetToolByName("mixed_secret")
	if err != nil {
		t.Fatal(err)
	}
	forbidText(t, "stored mixed", tool.Body+string(compactJSON(tool.Params)), mixed, "FAKE-secret")
}

func TestReview051Finding08KeyCase(t *testing.T) {
	yes := []string{"AUTHToken", "ACCESSTOKEN", "X-AUTH-TOKEN", "AccessToken", "AUTH_TOKEN", "X_AUTH_TOKEN"}
	for _, k := range yes {
		if !isSensitiveKey(k) {
			t.Errorf("expected sensitive: %s", k)
		}
	}
	tableYes := []string{
		"password", "passwd", "pwd", "passcode", "pass", "secret", "client_secret", "token",
		"access_token", "refresh_token", "authToken", "x-auth-token", "cookie", "set-cookie",
		"authorization", "api_key", "apikey", "x-api-key", "session", "sessionid", "sid",
		"jsessionid", "csrf", "xsrf", "csrf_token", "xsrf_token", "bearer", "credential",
		"credentials", "jwt", "private_key", "access_key", "secret_key", "pin", "otp",
		"signature", "sign",
	}
	tableNo := []string{
		"passwordStrength", "passwordPolicy", "keepLogin", "rememberMe", "editor",
		"tokenType", "token_type", "expires_in", "login", "loginName", "account", "username",
		"retry_count", "name_length", "passwordHint", "value",
	}
	for _, k := range tableYes {
		if !isSensitiveKey(strings.ToUpper(k)) {
			t.Errorf("uppercase should be sensitive: %s", strings.ToUpper(k))
		}
	}
	for _, k := range append(tableNo, "PASSWORDSTRENGTH", "TOKENTYPE", "TOKEN_TYPE", "ACCOUNT", "PASSWORDHINT", "RETRY_COUNT") {
		if isSensitiveKey(k) || isSensitiveKey(strings.ToUpper(k)) {
			t.Errorf("expected not sensitive: %s", k)
		}
	}

	app, _, c := startRecServer(t)
	body := map[string]any{
		"AUTHToken":        "auth-FAKE-value-111",
		"ACCESSTOKEN":      "access-FAKE-value-222",
		"X-AUTH-TOKEN":     "xauth-FAKE-value-333",
		"PASSWORDSTRENGTH": "strength-keep-444",
		"tokenType":        "Bearer",
	}
	q := &ReqRecord{
		Method: "POST", URL: "https://api.example.com/keys",
		ReqHeaders: map[string]string{"Content-Type": "application/json"},
		ReqBody:    string(compactJSON(body)), Status: 200,
	}
	seedRecRequest(t, app, q)
	detail := mustTool(t, c, "rec_get_request", map[string]any{"request_id": q.ID})
	forbidText(t, "detail keys", detail, "auth-FAKE-value-111", "access-FAKE-value-222", "xauth-FAKE-value-333")
	if !strings.Contains(detail, "strength-keep-444") || !strings.Contains(detail, "Bearer") {
		t.Fatalf("non-secret key masked: %s", detail)
	}
	saved := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "key_case", "pack": "key-pack", "create_pack": true,
	})
	tool, err := app.store.GetToolByName("key_case")
	if err != nil {
		t.Fatalf("save: %s (%v)", saved, err)
	}
	blob := tool.Body + string(compactJSON(tool))
	forbidText(t, "saved keys", blob, "auth-FAKE-value-111", "access-FAKE-value-222", "xauth-FAKE-value-333")
	if !strings.Contains(blob, "strength-keep-444") {
		t.Fatalf("strength value removed: %s", blob)
	}
}

func TestReview051Finding09ShortVault(t *testing.T) {
	app, _, c := startRecServer(t)
	if err := app.vault.Upsert("short_page", "secret", "1", "https://api.example.com", ""); err != nil {
		t.Fatal(err)
	}
	if got := app.vault.secretVariants(); len(got) != 0 {
		t.Fatalf("short vault value produced variants: %v", got)
	}
	q := &ReqRecord{
		Method: "GET", URL: "https://api.example.com/list?page=1",
		ResourceType: "WebSocket", Status: 101,
		ReqHeaders: map[string]string{"Content-Type": "application/json"},
		ReqBody:    `{"op":1,"page":1}`,
	}
	seedRecRequest(t, app, q)
	detail := decodeRec(t, mustTool(t, c, "rec_get_request", map[string]any{"request_id": q.ID}))
	var sawPage, sawOp bool
	for _, item := range detail["candidates"].([]any) {
		row := item.(map[string]any)
		switch row["path"] {
		case "page", "op":
			if row["path"] == "page" {
				sawPage = true
			}
			if row["path"] == "op" {
				sawOp = true
			}
			if row["secret"] == true || row["example"] == "" {
				t.Fatalf("short vault classified %v as secret: %v", row["path"], row)
			}
		}
	}
	if !sawPage || !sawOp {
		t.Fatalf("candidates: %s", mustCompact(detail["candidates"]))
	}
	dry := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "page_one", "pack": "page-pack", "create_pack": true, "dry_run": true,
	})
	if strings.Contains(dry, "{{secret.short_page}}") {
		t.Fatalf("short vault became a reference: %s", dry)
	}
	schema := decodeRec(t, dry)["input_schema"].(map[string]any)
	if req, ok := schema["required"].([]any); ok {
		for _, name := range req {
			if name == "page" || name == "op" {
				t.Fatalf("page/op required because of vault \"1\": %s", dry)
			}
		}
	}
}

func TestReview051Finding10ErrorTemplate(t *testing.T) {
	app, _, c := startRecServer(t)
	if err := app.vault.Upsert("word_overwrite", "secret", "overwrite", "https://api.example.com", ""); err != nil {
		t.Fatal(err)
	}
	if err := app.store.SavePack(&Pack{Name: "team-overwrite-pack", Enabled: true}); err != nil {
		t.Fatal(err)
	}
	q := &ReqRecord{
		Method: "POST", URL: "https://api.example.com/items",
		ReqHeaders: map[string]string{"Content-Type": "application/json"},
		ReqBody:    `{"q":"hello"}`, Status: 200,
	}
	seedRecRequest(t, app, q)
	mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "echo_item", "pack": "team-overwrite-pack",
	})
	bad, isErr := c.tool("rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "echo_item", "pack": "missing-pack-name",
	})
	if !isErr {
		t.Fatal(bad)
	}
	if !strings.Contains(bad, "overwrite=true") || !strings.Contains(bad, "create_pack=true") {
		t.Fatalf("template words were masked: %s", bad)
	}
	if strings.Contains(bad, "******=true") {
		t.Fatalf("composed template was scrubbed: %s", bad)
	}
	if strings.Contains(bad, "team-overwrite-pack") || !strings.Contains(bad, "team-"+secretMask+"-pack") {
		t.Fatalf("pack name was not sanitized before composition: %s", bad)
	}
	if !strings.Contains(bad, "id=") {
		t.Fatalf("pack id missing: %s", bad)
	}
}

func TestReview051Finding11GroupIDs(t *testing.T) {
	app, _, c := startRecServer(t)
	recID, err := app.store.CreateRecording("混组", "https://app.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	noise := &ReqRecord{
		RecordingID: recID, Seq: 1, Method: "POST", URL: "https://app.example.com/item-10001",
		ResourceType: "Fetch", Status: 200, Noise: true, NoiseReason: "埋点/日志",
	}
	business := &ReqRecord{
		RecordingID: recID, Seq: 2, Method: "POST", URL: "https://app.example.com/item-10002",
		ResourceType: "Fetch", Status: 200,
	}
	if err := app.store.InsertRequest(noise); err != nil {
		t.Fatal(err)
	}
	if err := app.store.InsertRequest(business); err != nil {
		t.Fatal(err)
	}
	out := decodeRec(t, mustTool(t, c, "rec_get_recording", map[string]any{"recording_id": recID}))
	var row map[string]any
	for _, item := range out["requests"].([]any) {
		r := item.(map[string]any)
		if r["path"] == "/item-{id}" {
			row = r
		}
	}
	if row == nil {
		t.Fatalf("group missing: %s", mustCompact(out))
	}
	ids := row["ids"].([]any)
	if len(ids) != 2 || int64(ids[0].(float64)) != noise.ID || int64(ids[1].(float64)) != business.ID {
		t.Fatalf("ids: %v", ids)
	}
	if int64(row["id"].(float64)) != noise.ID {
		t.Fatalf("representative id: %v", row["id"])
	}
	if int(row["count"].(float64)) != 1 {
		t.Fatalf("business count: %v", row["count"])
	}
	if row["example_path"] != "/item-10001" {
		t.Fatalf("example_path: %v", row["example_path"])
	}
}

func TestReview051Finding12UUIDTemplate(t *testing.T) {
	got, changed := templatePath("/view-550e8400-e29b-41d4-a716-446655440000.html")
	if !changed || got != "/view-{id}.html" {
		t.Fatalf("uuid template: %s %v", got, changed)
	}
	digit, ok := templatePath("/pro/action-editComment-26875561.html")
	if !ok || digit != "/pro/action-editComment-{id}.html" {
		t.Fatalf("digit template: %s %v", digit, ok)
	}
	app, _, c := startRecServer(t)
	recID, err := app.store.CreateRecording("uuid", "https://app.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	a := &ReqRecord{RecordingID: recID, Seq: 1, Method: "GET", URL: "https://app.example.com/view-550e8400-e29b-41d4-a716-446655440000.html", Status: 200, ResourceType: "Fetch"}
	b := &ReqRecord{RecordingID: recID, Seq: 2, Method: "GET", URL: "https://app.example.com/view-11111111-2222-3333-4444-555555555555.html", Status: 200, ResourceType: "Fetch"}
	if err := app.store.InsertRequest(a); err != nil || app.store.InsertRequest(b) != nil {
		t.Fatal(err)
	}
	out := decodeRec(t, mustTool(t, c, "rec_get_recording", map[string]any{"recording_id": recID}))
	var row map[string]any
	for _, item := range out["requests"].([]any) {
		r := item.(map[string]any)
		if strings.Contains(r["path"].(string), "550e8400") || strings.Contains(r["path"].(string), "11111111") {
			t.Fatalf("raw uuid in path: %s", mustCompact(out))
		}
		if r["path"] == "/view-{id}.html" {
			row = r
		}
	}
	if row == nil || int(row["count"].(float64)) != 2 {
		t.Fatalf("uuid group: %s", mustCompact(out))
	}
	ids := row["ids"].([]any)
	if len(ids) != 2 || int64(ids[0].(float64)) != a.ID || int64(ids[1].(float64)) != b.ID {
		t.Fatalf("uuid ids: %v", ids)
	}
}

func TestReview051Finding13NestedJSONRender(t *testing.T) {
	tool := &Tool{
		Method:  "POST",
		URL:     "https://api.example.com/echo",
		Headers: map[string]string{"Content-Type": "application/json"},
		Body:    `{"body":"{\"password\":\"{{p}}\"}"}`,
		Params:  []Param{{Name: "p", Type: "string", Required: true}},
	}
	_, _, _, body, err := tool.RenderWith(map[string]any{"p": `say "hi"`}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	var outer map[string]any
	if err := json.Unmarshal([]byte(body), &outer); err != nil {
		t.Fatalf("outer json: %v %s", err, body)
	}
	inner, _ := outer["body"].(string)
	var payload map[string]any
	if err := json.Unmarshal([]byte(inner), &payload); err != nil {
		t.Fatalf("inner json: %v %s", err, inner)
	}
	if payload["password"] != `say "hi"` {
		t.Fatalf("password: %#v body %s", payload["password"], body)
	}
}

func TestReview051Finding14TrackingBoundary(t *testing.T) {
	list := func(raw, body string) (bool, string) {
		q := &ReqRecord{Method: "POST", URL: "https://app.example.com" + raw, ResourceType: "Fetch", RespMime: "application/json", RespBody: body, Status: 200}
		return ClassifyNoise(q)
	}
	if n, why := list("/report/login", `{"ok":true}`); n {
		t.Fatalf("/report/login: %s", why)
	}
	if n, why := list("/report/logistics", `{"ok":true}`); n {
		t.Fatalf("/report/logistics: %s", why)
	}
	if n, why := list("/report/log", `{"ok":true}`); !n {
		t.Fatalf("/report/log should be noise: %s", why)
	}
	if n, why := list("/log/collect", `{"ok":true}`); !n {
		t.Fatalf("/log/collect should be noise: %s", why)
	}
	if n, why := list("/logs/report", `{"ok":true}`); !n {
		t.Fatalf("/logs/report should be noise: %s", why)
	}
	if n, why := list("/batch/collect", `{"ok":true}`); !n {
		t.Fatalf("/batch/collect should be noise: %s", why)
	}
}

func TestReview051Finding15CarryEarlierOnly(t *testing.T) {
	app, _, _ := startRecServer(t)
	recID, err := app.store.CreateRecording("沿用边界", "https://app.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	mk := func(seq int, raw string) *ReqRecord {
		t.Helper()
		q := &ReqRecord{
			RecordingID: recID, Seq: seq, Method: "POST", URL: "https://app.example.com" + raw,
			ResourceType: "Fetch", Status: 204, Noise: true, NoiseReason: "埋点/日志",
		}
		if err := app.store.InsertRequest(q); err != nil {
			t.Fatal(err)
		}
		return q
	}
	early := mk(1, "/log/collect")
	late := mk(3, "/log/collect")
	sameLow := mk(4, "/report/log")
	sameHigh := mk(4, "/report/log")
	off := false
	on := true
	note := func(q *ReqRecord, override *bool) {
		t.Helper()
		if err := app.store.SetRequestNote(RequestNote{
			RequestID: q.ID, RecordingID: recID, Category: "query", Purpose: "标注", Source: "agent", NoiseOverride: override,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// A later request must not change an earlier one, and a request must not carry its own note.
	note(late, &off)
	if noise, why := app.classifyRecorded(early); !noise || why == "沿用之前的标注" {
		t.Fatalf("later note affected earlier request: %v %s", noise, why)
	}
	reloaded, err := app.store.GetRequest(late.ID)
	if err != nil {
		t.Fatal(err)
	}
	noise, why := app.classifyRecorded(reloaded)
	if !noise || why == "沿用之前的标注" {
		t.Fatalf("own note was applied: %v %s", noise, why)
	}
	reloaded.Noise, reloaded.NoiseReason = noise, why
	if err := app.store.UpdateRequest(reloaded); err != nil {
		t.Fatal(err)
	}
	if err := app.store.DeleteRequestNote(late.ID); err != nil {
		t.Fatal(err)
	}
	stored, err := app.store.GetRequest(late.ID)
	if err != nil || !stored.Noise || stored.NoiseReason == "沿用之前的标注" {
		t.Fatalf("own note was written into the stored heuristic: %+v %v", stored, err)
	}

	note(early, &off)
	if noise, why := app.classifyRecorded(late); noise || why != "沿用之前的标注" {
		t.Fatalf("earlier note did not carry: %v %s", noise, why)
	}
	if err := app.store.DeleteRequestNote(early.ID); err != nil {
		t.Fatal(err)
	}
	if noise, why := app.classifyRecorded(late); !noise || why == "沿用之前的标注" {
		t.Fatalf("clearing the earlier note did not restore the heuristic: %v %s", noise, why)
	}

	// Same sequence: only a lower id is earlier. The earliest override wins.
	note(sameHigh, &off)
	if noise, why := app.classifyRecorded(sameLow); !noise || why == "沿用之前的标注" {
		t.Fatalf("higher id influenced same seq: %v %s", noise, why)
	}
	note(sameLow, &on)
	if noise, why := app.classifyRecorded(sameHigh); !noise || why != "沿用之前的标注" {
		t.Fatalf("lower id should carry and win: %v %s", noise, why)
	}
}

func TestReview051Finding16CarryCache(t *testing.T) {
	app, _, _ := startRecServer(t)
	recID, err := app.store.CreateRecording("缓存", "https://app.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	var idx string
	if err := app.store.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_request_notes_group'`).Scan(&idx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(idx, "recording_id") || !strings.Contains(idx, "group_key") {
		t.Fatalf("group index: %s", idx)
	}
	mk := func(seq int, raw string) *ReqRecord {
		t.Helper()
		q := &ReqRecord{
			RecordingID: recID, Seq: seq, Method: "POST", URL: "https://app.example.com" + raw,
			ResourceType: "Fetch", Status: 204, Noise: true, NoiseReason: "埋点/日志",
		}
		if err := app.store.InsertRequest(q); err != nil {
			t.Fatal(err)
		}
		return q
	}
	off := false
	on := true
	for i := 0; i < 12; i++ {
		other := mk(i+1, "/api/other/"+strings.Repeat("n", i)+"/item")
		ov := &on
		if i%2 == 0 {
			ov = &off
		}
		if err := app.store.SetRequestNote(RequestNote{
			RequestID: other.ID, RecordingID: recID, Category: "noise", Purpose: "无关", Source: "agent", NoiseOverride: ov,
		}); err != nil {
			t.Fatal(err)
		}
	}
	first := mk(20, "/log/collect")
	second := mk(21, "/log/collect")
	current := mk(30, "/log/collect")
	if err := app.store.SetRequestNote(RequestNote{
		RequestID: second.ID, RecordingID: recID, Category: "query", Purpose: "较晚", Source: "agent", NoiseOverride: &off,
	}); err != nil {
		t.Fatal(err)
	}
	if err := app.store.SetRequestNote(RequestNote{
		RequestID: first.ID, RecordingID: recID, Category: "query", Purpose: "最早", Source: "agent", NoiseOverride: &on,
	}); err != nil {
		t.Fatal(err)
	}
	lookup := func() (bool, bool) {
		t.Helper()
		ov, ok, err := app.store.NoiseOverrideForGroup(recID, "POST", current.URL, current.Seq, current.ID)
		if err != nil {
			t.Fatal(err)
		}
		return ov, ok
	}
	if ov, ok := lookup(); !ok || !ov {
		t.Fatalf("earliest override: %v %v", ov, ok)
	}
	if ov, ok := lookup(); !ok || !ov {
		t.Fatalf("cached override: %v %v", ov, ok)
	}
	if err := app.store.SetRequestNote(RequestNote{
		RequestID: first.ID, RecordingID: recID, Category: "query", Purpose: "改了", Source: "agent", NoiseOverride: &off,
	}); err != nil {
		t.Fatal(err)
	}
	if ov, ok := lookup(); !ok || ov {
		t.Fatalf("cache was not invalidated: %v %v", ov, ok)
	}
	if err := app.store.DeleteRequestNote(first.ID); err != nil {
		t.Fatal(err)
	}
	if err := app.store.DeleteRequestNote(second.ID); err != nil {
		t.Fatal(err)
	}
	if _, ok := lookup(); ok {
		t.Fatal("cleared notes still carry")
	}
	// The current request's own note is never a source, even after the cache is warm.
	if err := app.store.SetRequestNote(RequestNote{
		RequestID: current.ID, RecordingID: recID, Category: "query", Purpose: "自己", Source: "agent", NoiseOverride: &off,
	}); err != nil {
		t.Fatal(err)
	}
	if _, ok := lookup(); ok {
		t.Fatal("own note was cached as a carry source")
	}
}

func TestReview051Finding17DraftWriteFree(t *testing.T) {
	app, _, c := startRecServer(t)
	q := &ReqRecord{
		Method: "POST", URL: "https://api.example.com/secret",
		ReqHeaders: map[string]string{"Content-Type": "application/json"},
		ReqBody:    string(compactJSON(map[string]any{"password": fakeToken, "note": "hello"})),
		Status:     200,
	}
	seedRecRequest(t, app, q)
	before := snapshotWrites(t, app)
	bad, isErr := c.tool("rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "list_packs", "pack": "should-not-exist", "create_pack": true,
	})
	if !isErr || !strings.Contains(bad, "已被保留") {
		t.Fatalf("reserved name: %s", bad)
	}
	assertNoWrites(t, app, before)
	if app.vault.FindByValue(fakeToken) != "" {
		t.Fatal("reserved-name save wrote the secret into the vault")
	}

	dry := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "preview_secret", "pack": "preview-pack", "create_pack": true, "dry_run": true,
	})
	assertNoWrites(t, app, before)
	forbidText(t, "dry_run", dry, fakeToken, "tok-FAKE")
	d := decodeRec(t, dry)
	if d["dry_run"] != true {
		t.Fatalf("dry_run: %s", dry)
	}
	schema := d["input_schema"].(map[string]any)
	props := schema["properties"].(map[string]any)
	req, _ := schema["required"].([]any)
	if len(req) == 0 {
		t.Fatalf("dry_run did not preview a required secret param: %s", dry)
	}
	for _, name := range req {
		prop := props[name.(string)].(map[string]any)
		if _, ok := prop["default"]; ok {
			t.Fatalf("dry_run secret default: %s", dry)
		}
		desc, _ := prop["description"].(string)
		if !strings.Contains(desc, "敏感") && !strings.Contains(dry, removedSecretDesc) {
			t.Fatalf("dry_run description: %s", dry)
		}
	}
	if _, err := app.store.GetToolByName("preview_secret"); err == nil {
		t.Fatal("dry_run saved a tool")
	}

	if err := app.vault.Upsert("known_fake", "secret", fakeToken, "https://api.example.com", ""); err != nil {
		t.Fatal(err)
	}
	vaultN := len(app.vault.List())
	reused := mustTool(t, c, "rec_save_tool", map[string]any{
		"request_id": q.ID, "name": "reuse_secret", "pack": "reuse-pack", "create_pack": true, "dry_run": true,
	})
	if !strings.Contains(reused, "{{secret.known_fake}}") {
		t.Fatalf("existing vault entry was not reused: %s", reused)
	}
	forbidText(t, "reuse", reused, fakeToken, "tok-FAKE")
	if len(app.vault.List()) != vaultN {
		t.Fatal("dry_run wrote the vault while reusing an entry")
	}
	if _, err := app.store.GetToolByName("reuse_secret"); err == nil {
		t.Fatal("reuse dry_run saved a tool")
	}
}
