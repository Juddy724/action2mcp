package app

import (
	"action2mcp/internal/execution"
	"action2mcp/internal/store"

	"action2mcp/internal/recording"
	sitecfg "action2mcp/internal/site"
	"action2mcp/internal/vault"
	"encoding/base64"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testVault(t *testing.T) (*store.Store, *vault.Vault, string) {
	dir := t.TempDir()
	st, err := store.OpenStore(filepath.Join(dir, "a2m.DB()"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := vault.OpenVault(st.DB(), filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	return st, v, dir
}

func TestVaultEncryptScrub(t *testing.T) {
	st, v, dir := testVault(t)
	if err := v.Upsert("b_password", "secret", "S3cr3t&pw!", "http://127.0.0.12:9202", ""); err != nil {
		t.Fatal(err)
	}
	v.Upsert("b_user", "plain", "alice", "http://127.0.0.12:9202", "")
	// key file permissions
	fi, _ := os.Stat(filepath.Join(dir, "secret.key"))
	if fi.Mode().Perm() != 0600 {
		t.Fatalf("key perm %v", fi.Mode().Perm())
	}
	// encrypted at rest
	var enc string
	st.DB().QueryRow(`SELECT value_enc FROM vault WHERE name='b_password'`).Scan(&enc)
	if strings.Contains(enc, "S3cr3t") || !strings.HasPrefix(enc, "v1:") {
		t.Fatalf("not encrypted: %s", enc)
	}
	// list masks secrets
	for _, it := range v.List() {
		if it.Name == "b_password" && (it.Value != "" || strings.Contains(it.Masked, "S3cr3t")) {
			t.Fatalf("list leaks: %+v", it)
		}
	}
	for _, s := range []string{"S3cr3t&pw!", url.QueryEscape("S3cr3t&pw!"), `"S3cr3t\u0026pw!"`, base64.StdEncoding.EncodeToString([]byte("S3cr3t&pw!"))} {
		if out := v.Scrub("x " + s + " y"); strings.Contains(out, "S3cr3t") || strings.Contains(out, base64.StdEncoding.EncodeToString([]byte("S3cr3t&pw!"))) {
			t.Fatalf("scrub failed: %s -> %s", s, out)
		}
	}
	if got := v.Scrub("alice"); got != "alice" {
		t.Fatalf("plain values must not be scrubbed: %s", got)
	}
	if got := v.ToRefs("pwd=" + url.QueryEscape("S3cr3t&pw!")); got != "pwd={{secret.b_password}}" {
		t.Fatalf("ToRefs: %s", got)
	}
	if val, err := v.Resolve("secret.b_password"); err != nil || val != "S3cr3t&pw!" {
		t.Fatal(val, err)
	}
	if _, err := v.Resolve("secret.nope"); err == nil || !strings.Contains(err.Error(), "配置") {
		t.Fatal(err)
	}
	// reopen with same key
	v2, err := vault.OpenVault(st.DB(), filepath.Join(dir, "secret.key"))
	if err != nil {
		t.Fatal(err)
	}
	if val, _ := v2.Resolve("secret.b_password"); val != "S3cr3t&pw!" {
		t.Fatal("reopen failed")
	}
	if n := v.FindByValue("S3cr3t&pw!"); n != "b_password" {
		t.Fatal(n)
	}
}

func TestNotLoggedIn(t *testing.T) {
	s := &sitecfg.Site{Origin: "https://zentao.example.com", Method: sitecfg.MethodSSO}
	cases := []struct {
		st   int
		body string
		ct   string
		hops []string
		want bool
	}{
		{401, `{}`, "application/json", nil, true},
		{200, `{"status":"success","data":[]}`, "application/json", nil, false},
		{200, `<html><form><input name=account><input type="password" name=password></form></html>`, "text/html", nil, true},
		{200, `<html><script>self.location='/zentao/user-login-L3plbnRhby8=.html';</script></html>`, "text/html", nil, true},
		{200, `{"code":"NOT_LOGIN","msg":"请先登录"}`, "application/json", nil, true},
		{200, `ok`, "text/plain", []string{"https://sso.example.com/login?x=1"}, true},
		{200, strings.Repeat("x", 3000) + "请先登录", "text/html", nil, false},
	}
	for i, c := range cases {
		got, why := s.NotLoggedIn(c.st, c.body, c.ct, c.hops, "https://zentao.example.com/api/x")
		if got != c.want {
			t.Errorf("case %d: got %v (%s)", i, got, why)
		}
	}
	// a tool that IS the login endpoint must not be flagged by redirects / default rules
	if got, _ := s.NotLoggedIn(200, `<input type=password>`, "text/html", nil, "https://zentao.example.com/user-login.html"); got {
		t.Error("login tool flagged")
	}
}

func TestBuildDraftRefs(t *testing.T) {
	q := &recording.Request{Method: "POST", URL: "http://b.local/api/do?x=1", ReqHeaders: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, ReqBody: "keyword=abc&pwd=hunter2"}
	cs := execution.SuggestParams(q)
	var chosen []Candidate
	for _, c := range cs {
		if c.Path == "pwd" {
			c.Secret, c.Ref = true, "b_password"
		}
		chosen = append(chosen, c)
	}
	tl, err := execution.BuildDraft(q, chosen)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(tl.Body, "hunter2") || !strings.Contains(tl.Body, "{{secret.b_password}}") {
		t.Fatal(tl.Body)
	}
	for _, p := range tl.Params {
		if strings.Contains(p.Name, "secret") || strings.Contains(p.Default, "hunter2") {
			t.Fatalf("ref leaked into params: %+v", p)
		}
	}
	vals := map[string]string{}
	_, _, _, body, err := tl.RenderWith(map[string]any{"keyword": "k", "x": 1}, func(r string) (string, error) { vals[r] = "1"; return "P&W", nil }, nil)
	if err != nil || !strings.Contains(body, "pwd=P%26W") {
		t.Fatal(body, err)
	}
}
