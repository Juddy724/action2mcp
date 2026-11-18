package login

import (
	"action2mcp/internal/browser"
	sitecfg "action2mcp/internal/site"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type fakeCaptureLoginTab struct {
	*fakeLoginTab
	creds     browser.CapturedCreds
	installed atomic.Bool
}

func (f *fakeCaptureLoginTab) InstallLoginCapture() error {
	f.installed.Store(true)
	return nil
}

func (f *fakeCaptureLoginTab) ReadCapturedCreds() browser.CapturedCreds {
	return f.creds
}

func smartLoginTestApp(t *testing.T, srv *httptest.Server, bs *fakeLoginBrowser, tab Surface) (*Service, *sitecfg.Site) {
	t.Helper()
	a, s := loginTestApp(t, srv, bs, &fakeLoginTab{})
	a.openLogin = func(target string) (LoginBrowser, Surface, error) {
		if _, err := browserHTTPURL(target); err != nil {
			return nil, nil, err
		}
		return bs, tab, nil
	}
	return a, s
}

func TestSmartOpenLoginCreatesVaultCredsWhenUnboundAndSucceedsOnNextRelogin(t *testing.T) {
	var validPass atomic.Value
	validPass.Store("pass_2026")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/login":
			_ = r.ParseForm()
			if r.FormValue("username") == "admin" && r.FormValue("password") == validPass.Load().(string) {
				http.SetCookie(w, &http.Cookie{Name: "sid", Value: "fresh-session", Path: "/"})
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"ok":true}`))
				return
			}
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`用户名或密码错误`))
		case "/me":
			if c, err := r.Cookie("sid"); err == nil && (c.Value == "ok-session" || c.Value == "fresh-session") {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"user":"admin"}`))
				return
			}
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`请先登录`))
		default:
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html><body>dashboard</body></html>`))
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	cs := []Cookie{{Name: "sid", Value: "ok-session", Domain: u.Hostname(), Path: "/", Session: true}}
	bs := newFakeBrowser(cs)
	baseTab := &fakeLoginTab{infoFn: func() (sitecfg.PageInfo, error) {
		return sitecfg.PageInfo{Href: srv.URL + "/home", Ready: "complete", Pass: false, Text: "欢迎 admin"}, nil
	}}
	capTab := &fakeCaptureLoginTab{
		fakeLoginTab: baseTab,
		creds: browser.CapturedCreds{
			Username: "admin",
			Password: "pass_2026",
			LoginURL: srv.URL + "/login",
		},
	}

	a, site := smartLoginTestApp(t, srv, bs, capTab)
	// Start with a site that has NO vault refs bound (e.g. newly created or imported manual site)
	site.Origin = "http://zentao.corp.test"
	// Keep CheckURL & EntryURL pointing to our test server, or use srv.URL directly as site.Origin
	site.Origin = srv.URL
	site.Method = sitecfg.MethodManual
	site.CheckURL = srv.URL + "/me"
	if err := a.repo.SaveSite(site); err != nil {
		t.Fatal(err)
	}

	// Pre-populate stale valid cookie; SmartOpenLogin must still see that MethodManual cannot auto-relogin,
	// clear the stale cookie, and pop the login window!
	a.repo.ReplaceCookies(cs)

	res, err := a.SmartOpenLogin(site, false)
	if err != nil {
		t.Fatalf("SmartOpenLogin failed: %v", err)
	}
	if !res.Opened || res.AlreadyValid {
		t.Fatalf("expected browser window to open, got %+v", res)
	}

	waitSitePending(t, a, site, false, 4*time.Second)

	if !capTab.installed.Load() {
		t.Fatal("expected InstallLoginCapture to be called on the login tab")
	}

	updated, err := a.repo.GetSite(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Method != sitecfg.MethodForm {
		t.Fatalf("expected site.Method to auto-switch to form, got %q", updated.Method)
	}
	if updated.Form.UsernameRef == "" || updated.Form.PasswordRef == "" {
		t.Fatalf("expected UsernameRef and PasswordRef to be auto-populated, got %+v", updated.Form)
	}
	if updated.Form.LoginURL != srv.URL+"/login" {
		t.Fatalf("expected LoginURL=%q, got %q", srv.URL+"/login", updated.Form.LoginURL)
	}

	gotUser, okU := a.vault.Lookup(strings.TrimPrefix(updated.Form.UsernameRef, "cfg."))
	gotPass, okP := a.vault.Lookup(strings.TrimPrefix(updated.Form.PasswordRef, "secret."))
	if !okU || gotUser != "admin" || !okP || gotPass != "pass_2026" {
		t.Fatalf("vault values mismatch: user=%q(%v) pass=%q(%v)", gotUser, okU, gotPass, okP)
	}
}

func TestSmartOpenLoginUpdatesBoundVaultRefsAndColdReplayVerifiesPassword(t *testing.T) {
	var serverPass atomic.Value
	serverPass.Store("new_secret_999")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = w.Write([]byte(`<html><body><form><input name="u"><input type="password" name="p"></form></body></html>`))
		case "/api/login":
			// Notice: Even if an old valid cookie "sid=stale-valid-cookie" were sent, a buggy server might accept it,
			// or our cold replay must NOT send stale cookies AND must verify the password from Vault!
			if c, err := r.Cookie("sid"); err == nil && c.Value == "stale-valid-cookie" {
				t.Errorf("cold replayLogin leaked stale session cookie %q into login request!", c.Value)
			}
			_ = r.ParseForm()
			if r.FormValue("u") == "bob" && r.FormValue("p") == serverPass.Load().(string) {
				http.SetCookie(w, &http.Cookie{Name: "sid", Value: "replayed-session", Path: "/"})
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"ok":true}`))
				return
			}
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`密码错误`))
		case "/me":
			if c, err := r.Cookie("sid"); err == nil && (c.Value == "stale-valid-cookie" || c.Value == "browser-session" || c.Value == "replayed-session") {
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"ok":true}`))
				return
			}
			w.WriteHeader(401)
			_, _ = w.Write([]byte(`请登录`))
		}
	}))
	defer srv.Close()

	u, _ := url.Parse(srv.URL)
	browserCookies := []Cookie{{Name: "sid", Value: "browser-session", Domain: u.Hostname(), Path: "/", Session: true}}
	bs := newFakeBrowser(browserCookies)
	baseTab := &fakeLoginTab{infoFn: func() (sitecfg.PageInfo, error) {
		return sitecfg.PageInfo{Href: srv.URL + "/dashboard", Ready: "complete"}, nil
	}}
	capTab := &fakeCaptureLoginTab{
		fakeLoginTab: baseTab,
		creds: browser.CapturedCreds{
			Username: "bob",
			Password: "new_secret_999",
			LoginURL: srv.URL + "/login",
		},
	}

	a, site := smartLoginTestApp(t, srv, bs, capTab)
	// Seed existing bound Vault items with an outdated password
	if err := a.vault.Upsert("my_custom_user", "plain", "bob_old", srv.URL, ""); err != nil {
		t.Fatal(err)
	}
	if err := a.vault.Upsert("my_custom_pass", "secret", "wrong_old_pass", srv.URL, ""); err != nil {
		t.Fatal(err)
	}

	site.Method = sitecfg.MethodForm
	site.CheckURL = srv.URL + "/me"
	site.Form = sitecfg.FormLogin{
		Mode:        "replay",
		UsernameRef: "cfg.my_custom_user",
		PasswordRef: "secret.my_custom_pass",
		LoginURL:    srv.URL + "/login",
		Request: &sitecfg.LoginRequest{
			Method:  "POST",
			URL:     srv.URL + "/api/login",
			Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"},
			Body:    "u={{cfg.my_custom_user}}&p={{secret.my_custom_pass}}",
		},
	}
	if err := a.repo.SaveSite(site); err != nil {
		t.Fatal(err)
	}

	// Put a stale valid cookie into repo: cold Relogin must NOT be fooled by it because password is wrong!
	a.repo.ReplaceCookies([]Cookie{{Name: "sid", Value: "stale-valid-cookie", Domain: u.Hostname(), Path: "/", Session: true}})

	if err := a.Relogin(site, a.Generation(site.Origin), true, false); err == nil {
		t.Fatal("expected cold Relogin to fail when Vault password is wrong, even if stale cookie was valid")
	}

	// Now user clicks "打开浏览器登录": pre-check fails -> opens browser -> user enters new_secret_999
	res, err := a.SmartOpenLogin(site, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Opened || res.AlreadyValid {
		t.Fatalf("expected SmartOpenLogin to open window when password was wrong, got %+v", res)
	}
	waitSitePending(t, a, site, false, 4*time.Second)

	// Verify existing bound Vault refs were updated in-place!
	gotU, _ := a.vault.Lookup("my_custom_user")
	gotP, _ := a.vault.Lookup("my_custom_pass")
	if gotU != "bob" || gotP != "new_secret_999" {
		t.Fatalf("expected bound vault items updated in-place, got user=%q pass=%q", gotU, gotP)
	}

	// Switch back to replay mode (or keep replay request) to test that subsequent "测试重新登录" succeeds with the updated Vault creds!
	updated, _ := a.repo.GetSite(site.ID)
	updated.Form.Mode = "replay"
	_ = a.repo.SaveSite(updated)

	if err := a.Relogin(updated, a.Generation(updated.Origin), true, false); err != nil {
		t.Fatalf("expected Relogin to succeed after browser login updated Vault credentials, got: %v", err)
	}

	// And now clicking "打开浏览器登录" again should see cold Relogin succeed and return AlreadyValid=true without opening window!
	res2, err := a.SmartOpenLogin(updated, false)
	if err != nil {
		t.Fatal(err)
	}
	if !res2.AlreadyValid || res2.Opened {
		t.Fatalf("expected AlreadyValid=true without opening browser when relogin works, got %+v", res2)
	}
}

func TestSmartOpenLoginSSORecordsMethodAndSSOHosts(t *testing.T) {
	srv := loginTestServer(t)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	cs := []Cookie{{Name: "sid", Value: "ok-session", Domain: u.Hostname(), Path: "/", Session: true}}
	bs := newFakeBrowser(cs)

	var step atomic.Int32
	baseTab := &fakeLoginTab{infoFn: func() (sitecfg.PageInfo, error) {
		if step.Add(1) <= 2 {
			return sitecfg.PageInfo{Href: "https://sso.custom-corp.test/oauth2/authorize", Ready: "complete"}, nil
		}
		return sitecfg.PageInfo{Href: srv.URL + "/app", Ready: "complete"}, nil
	}}
	// Empty CapturedCreds simulates QR code / WeCom SSO login where no password input was typed
	capTab := &fakeCaptureLoginTab{fakeLoginTab: baseTab}

	a, site := smartLoginTestApp(t, srv, bs, capTab)
	site.Method = sitecfg.MethodManual
	if err := a.repo.SaveSite(site); err != nil {
		t.Fatal(err)
	}

	res, err := a.SmartOpenLogin(site, false)
	if err != nil || !res.Opened {
		t.Fatalf("SmartOpenLogin: res=%+v err=%v", res, err)
	}
	waitSitePending(t, a, site, false, 5*time.Second)

	updated, err := a.repo.GetSite(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Method != sitecfg.MethodSSO {
		t.Fatalf("expected site.Method=%q after SSO/QR login, got %q", sitecfg.MethodSSO, updated.Method)
	}
	if !strings.Contains(updated.SSOHosts, "sso.custom-corp.test") {
		t.Fatalf("expected SSOHosts to include sso.custom-corp.test, got %q", updated.SSOHosts)
	}
}
