package login

import (
	sitecfg "action2mcp/internal/site"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeLoginBrowser struct {
	mu      sync.Mutex
	alive   bool
	cookies []Cookie
}

func newFakeBrowser(cs []Cookie) *fakeLoginBrowser {
	return &fakeLoginBrowser{alive: true, cookies: append([]Cookie(nil), cs...)}
}

func (b *fakeLoginBrowser) Alive() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.alive
}

func (b *fakeLoginBrowser) Cookies() ([]Cookie, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]Cookie(nil), b.cookies...), nil
}

func (b *fakeLoginBrowser) Close() {
	b.mu.Lock()
	b.alive = false
	b.mu.Unlock()
}

type fakeLoginTab struct {
	mu       sync.Mutex
	closed   bool
	reloads  int
	navs     []string
	infoFn   func() (sitecfg.PageInfo, error)
	reloadFn func() error
}

func (t *fakeLoginTab) Info() (sitecfg.PageInfo, error) {
	t.mu.Lock()
	fn := t.infoFn
	closed := t.closed
	t.mu.Unlock()
	if closed {
		return sitecfg.PageInfo{}, fmt.Errorf("tab closed")
	}
	if fn == nil {
		return sitecfg.PageInfo{}, fmt.Errorf("no page")
	}
	return fn()
}

func (t *fakeLoginTab) Close() {
	t.mu.Lock()
	t.closed = true
	t.mu.Unlock()
}

func (t *fakeLoginTab) Navigate(u string) error {
	t.mu.Lock()
	t.navs = append(t.navs, u)
	t.mu.Unlock()
	return nil
}

func (t *fakeLoginTab) Reload() error {
	t.mu.Lock()
	t.reloads++
	fn := t.reloadFn
	t.mu.Unlock()
	if fn != nil {
		return fn()
	}
	return nil
}

func (t *fakeLoginTab) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

func (t *fakeLoginTab) reloadCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.reloads
}

func loginTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("sid"); err != nil || c.Value != "ok-session" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(401)
			io.WriteString(w, `<html><body>请先登录 <input type="password"></body></html>`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
}

func loginTestApp(t *testing.T, srv *httptest.Server, bs *fakeLoginBrowser, tab *fakeLoginTab) (*Service, *sitecfg.Site) {
	t.Helper()
	a := testLoginService(t)
	a.pendingLoginMax = 5 * time.Second
	a.openLogin = func(target string) (LoginBrowser, Surface, error) {
		u, err := browserHTTPURL(target)
		if err != nil {
			return nil, nil, err
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return nil, nil, fmt.Errorf("non-http target %s", u)
		}
		return bs, tab, nil
	}
	s := &sitecfg.Site{Origin: srv.URL, Name: "demo", Method: sitecfg.MethodManual, CheckURL: srv.URL + "/me"}
	if err := a.repo.(*loginTestRepository).SaveSite(s); err != nil {
		t.Fatal(err)
	}
	return a, s
}

func waitSitePending(t *testing.T, a *Service, site *sitecfg.Site, want bool, d time.Duration) {
	t.Helper()
	st := a.state(site.Origin)
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		a.smu.Lock()
		p := st.pending
		a.smu.Unlock()
		if p == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	a.smu.Lock()
	p := st.pending
	a.smu.Unlock()
	t.Fatalf("pending=%v want %v", p, want)
}

func waitSiteStatus(t *testing.T, a *Service, site *sitecfg.Site, want string, d time.Duration) *sitecfg.Site {
	t.Helper()
	end := time.Now().Add(d)
	for time.Now().Before(end) {
		if got, err := a.repo.GetSite(site.ID); err == nil && got != nil && got.Status == want {
			return got
		}
		time.Sleep(15 * time.Millisecond)
	}
	got, _ := a.repo.GetSite(site.ID)
	t.Fatalf("status=%q err=%q want %q", got.Status, got.LastError, want)
	return got
}

func TestLoginAlreadyLoggedInFastPath(t *testing.T) {
	srv := loginTestServer(t)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	cs := []Cookie{{Name: "sid", Value: "ok-session", Domain: u.Hostname(), Path: "/", Session: true}}
	bs := newFakeBrowser(cs)
	tab := &fakeLoginTab{infoFn: func() (sitecfg.PageInfo, error) {
		return sitecfg.PageInfo{Href: srv.URL + "/login", Ready: "complete"}, nil
	}}
	a, site := loginTestApp(t, srv, bs, tab)
	a.repo.ReplaceCookies(cs)
	if err := a.OpenLoginWindow(site); err != nil {
		t.Fatal(err)
	}
	waitSitePending(t, a, site, true, time.Second)
	got := waitSiteStatus(t, a, site, "valid", 3*time.Second)
	if got.Status != "valid" {
		t.Fatalf("status=%q err=%q", got.Status, got.LastError)
	}
	if tab.isClosed() {
		t.Fatal("window must stay open until the user closes it manually")
	}
	bs.Close()
	waitSitePending(t, a, site, false, 2*time.Second)
	got, _ = a.repo.GetSite(site.ID)
	if got.Status != "valid" {
		t.Fatalf("closing window after valid login overwrote status=%q err=%q", got.Status, got.LastError)
	}
}

func TestLoginWaitTimeout(t *testing.T) {
	srv := loginTestServer(t)
	defer srv.Close()
	bs := newFakeBrowser(nil)
	tab := &fakeLoginTab{infoFn: func() (sitecfg.PageInfo, error) {
		return sitecfg.PageInfo{Href: srv.URL + "/login", Ready: "complete", Pass: true, Text: "请登录"}, nil
	}}
	a, site := loginTestApp(t, srv, bs, tab)
	a.pendingLoginMax = 800 * time.Millisecond
	if err := a.OpenLoginWindow(site); err != nil {
		t.Fatal(err)
	}
	waitSitePending(t, a, site, false, 3*time.Second)
	got, err := a.repo.GetSite(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != "invalid" || !strings.Contains(got.LastError, "超时") {
		t.Fatalf("status=%q err=%q", got.Status, got.LastError)
	}
	if tab.isClosed() {
		t.Fatal("window should not be forcefully closed on timeout")
	}
}

func TestLoginWaitCancel(t *testing.T) {
	srv := loginTestServer(t)
	defer srv.Close()
	bs := newFakeBrowser(nil)
	tab := &fakeLoginTab{infoFn: func() (sitecfg.PageInfo, error) {
		return sitecfg.PageInfo{Href: srv.URL + "/login", Ready: "complete", Pass: true, Text: "请登录"}, nil
	}}
	a, site := loginTestApp(t, srv, bs, tab)
	a.pendingLoginMax = 30 * time.Second
	if err := a.OpenLoginWindow(site); err != nil {
		t.Fatal(err)
	}
	waitSitePending(t, a, site, true, time.Second)
	if err := a.CancelLogin(site); err != nil {
		t.Fatal(err)
	}
	waitSitePending(t, a, site, false, 2*time.Second)
	got, _ := a.repo.GetSite(site.ID)
	if got.Status == "valid" {
		t.Fatalf("cancel marked the site valid: %+v", got)
	}
	if !strings.Contains(got.LastError, "取消") {
		t.Fatalf("last_error=%q", got.LastError)
	}
	if !tab.isClosed() {
		t.Fatal("window was not closed after cancel")
	}
}

func TestLoginWaitWindowClosed(t *testing.T) {
	srv := loginTestServer(t)
	defer srv.Close()
	bs := newFakeBrowser(nil)
	tab := &fakeLoginTab{infoFn: func() (sitecfg.PageInfo, error) {
		return sitecfg.PageInfo{Href: srv.URL + "/login", Ready: "complete", Pass: true}, nil
	}}
	a, site := loginTestApp(t, srv, bs, tab)
	a.pendingLoginMax = 30 * time.Second
	if err := a.OpenLoginWindow(site); err != nil {
		t.Fatal(err)
	}
	waitSitePending(t, a, site, true, time.Second)
	bs.Close()
	waitSitePending(t, a, site, false, 2*time.Second)
	got, _ := a.repo.GetSite(site.ID)
	if !strings.Contains(got.LastError, "关闭") {
		t.Fatalf("last_error=%q", got.LastError)
	}
}

func TestLoginWaitHarvestsRequiredHeader(t *testing.T) {
	srv := loginTestServer(t)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	cs := []Cookie{{Name: "sid", Value: "ok-session", Domain: u.Hostname(), Path: "/", Session: true}}
	bs := newFakeBrowser(cs)
	var a *Service
	var site *sitecfg.Site
	tab := &fakeLoginTab{}
	tab.infoFn = func() (sitecfg.PageInfo, error) {
		return sitecfg.PageInfo{Href: srv.URL + "/app", Ready: "complete"}, nil
	}
	tab.reloadFn = func() error {
		if err := a.HarvestRequestHeader("", srv.URL, "sso-epctoken", "tok_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"); err != nil {
			t.Errorf("harvest: %v", err)
		}
		return nil
	}
	a, site = loginTestApp(t, srv, bs, tab)
	a.repo.ReplaceCookies(cs)
	bindingURL := "ws://" + strings.TrimPrefix(srv.URL, "http://") + "/ws"
	a.options.MiddlewareBindings = func() []MiddlewareBinding {
		return []MiddlewareBinding{{URL: bindingURL, Names: []string{"sso-epctoken"}}}
	}

	need := a.requiredSiteHeaders(site)
	if len(need) != 1 || need[0] != "sso-epctoken" {
		t.Fatalf("required headers=%v", need)
	}
	if miss := a.missingSiteHeaders(site); len(miss) != 1 {
		t.Fatalf("missing before login=%v", miss)
	}
	if err := a.OpenLoginWindow(site); err != nil {
		t.Fatal(err)
	}
	got := waitSiteStatus(t, a, site, "valid", 4*time.Second)
	if got.Status != "valid" {
		t.Fatalf("status=%q err=%q reloads=%d", got.Status, got.LastError, tab.reloadCount())
	}
	if tab.reloadCount() < 1 {
		t.Fatal("did not reload to harvest the header")
	}
	if _, err := a.GetSiteHeader(bindingURL, "sso-epctoken"); err != nil {
		t.Fatalf("header not available via wss/ws url: %v", err)
	}
	if tab.isClosed() {
		t.Fatal("window must stay open until user closes it manually")
	}
	bs.Close()
	waitSitePending(t, a, site, false, 2*time.Second)
}

func TestLoginWindowDoesNotAutoCloseOnSPAShellOrSSOPage(t *testing.T) {
	// Simulates SPA console: root URL returns HTTP 200 React SPA shell even with zero cookies.
	spaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		io.WriteString(w, `<!doctype html><html><head><title>SPA</title></head><body><div id="root"></div><script>window.boot();</script></body></html>`)
	}))
	defer spaSrv.Close()

	u, _ := url.Parse(spaSrv.URL)
	bs := newFakeBrowser(nil)
	var mu sync.Mutex
	curPage := sitecfg.PageInfo{Href: "https://login.work.weixin.qq.com/wwlogin/sso/login", Ready: "complete", Text: "扫码登录"}
	tab := &fakeLoginTab{infoFn: func() (sitecfg.PageInfo, error) {
		mu.Lock()
		defer mu.Unlock()
		return curPage, nil
	}}

	a, site := loginTestApp(t, spaSrv, bs, tab)
	site.Method = sitecfg.MethodSSO
	site.CheckURL = "" // no explicit backend check_url, just like SPA console
	if err := a.repo.(*loginTestRepository).SaveSite(site); err != nil {
		t.Fatal(err)
	}

	// CheckSite must NOT treat an unauthenticated SPA shell as valid.
	if ok, _ := a.CheckSite(site); ok {
		t.Fatal("CheckSite falsely reported valid on empty SPA shell with no cookies")
	}

	if err := a.OpenLoginWindow(site); err != nil {
		t.Fatal(err)
	}
	waitSitePending(t, a, site, true, time.Second)
	// Wait past a full poll + CheckSite interval: window must NOT auto-close or mark valid on QR page!
	time.Sleep(1200 * time.Millisecond)
	if tab.isClosed() {
		t.Fatal("SSO QR login window auto-closed prematurely on SPA site")
	}
	got, _ := a.repo.GetSite(site.ID)
	if got.Status == "valid" {
		t.Fatalf("site falsely marked valid while user is still on WeCom QR page: %+v", got)
	}

	// Now user scans QR code: cookies appear and browser navigates back to SPA dashboard.
	bs.mu.Lock()
	bs.cookies = []Cookie{{Name: "console_sid", Value: "real-session", Domain: u.Hostname(), Path: "/", Session: true}}
	bs.mu.Unlock()
	mu.Lock()
	curPage = sitecfg.PageInfo{Href: spaSrv.URL + "/v2/clusters", Ready: "complete", Text: "发布大盘 集群列表"}
	mu.Unlock()

	waitSiteStatus(t, a, site, "valid", 3*time.Second)
	if tab.isClosed() {
		t.Fatal("window should remain open for user confirmation even after login is detected")
	}
	// User manually closes the browser window -> pending ends, status stays valid.
	bs.Close()
	waitSitePending(t, a, site, false, 2*time.Second)
	got, _ = a.repo.GetSite(site.ID)
	if got.Status != "valid" {
		t.Fatalf("expected status valid after user closed window, got %q (%q)", got.Status, got.LastError)
	}
}

func TestOpenLoginRejectsWSURL(t *testing.T) {
	if _, err := browserHTTPURL("wss://sql.example.com/ws"); err != nil {
		t.Fatal("derived ws url should map, got", err)
	}
	got, err := browserHTTPURL("wss://sql.example.com/ws")
	if err != nil || got != "https://sql.example.com/ws" {
		t.Fatalf("mapped=%q err=%v", got, err)
	}
	if _, err := browserHTTPURL("ftp://sql.example.com/login"); err == nil {
		t.Fatal("ftp should be rejected")
	}
}
