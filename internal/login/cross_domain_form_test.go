package login

import (
	sitecfg "action2mcp/internal/site"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCanFillOnHostAndFormNeedUserMessage(t *testing.T) {
	site := &sitecfg.Site{
		Origin:   "http://ops-portal.corp.example.com",
		Method:   sitecfg.MethodForm,
		EntryURL: "https://sso-portal.corp.example.com/#/login?redirectUrl=http%3A%2F%2Fops-portal.corp.example.com%2Fops-portal-web%2F",
		SSOHosts: "sso-portal.corp.example.com",
	}
	if !canFillOnHost(site, "sso-portal.corp.example.com", sitecfg.PageInfo{Pass: true}) {
		t.Fatal("expected cross-domain configured EntryURL host to allow form fill")
	}
	if !canFillOnHost(site, "sso-portal.corp.example.com", sitecfg.PageInfo{Pass: false}) {
		t.Fatal("expected cross-domain configured EntryURL host to allow password-tab click before input renders")
	}
	if !canFillOnHost(site, "ops-portal.corp.example.com", sitecfg.PageInfo{}) {
		t.Fatal("expected same-site host to allow form fill")
	}
	if !canFillOnHost(site, "passport.other.example", sitecfg.PageInfo{Pass: true}) {
		t.Fatal("expected non-WeCom page with password input to allow form fill")
	}
	if canFillOnHost(site, "open.work.weixin.qq.com", sitecfg.PageInfo{Pass: true}) {
		t.Fatal("WeCom QR host must never be treated as form-fill host")
	}

	svc := testLoginService(t)
	msg := svc.needUserMsg(site, &needUser{reason: "page"})
	if !strings.Contains(msg, "账号密码") || strings.Contains(msg, "企业微信") {
		t.Fatalf("MethodForm page fallback message should mention password login, not WeCom: %q", msg)
	}
}

func TestCheckSiteAndWatchWindowRejectExplicitSPAShellCheckURL(t *testing.T) {
	// Exact shape of ops-portal Vue SPA shell: no id="root", uses class="ops-portal-web root" + script src.
	spaHTML := `<!DOCTYPE html><html lang="zh"><head><meta charset="UTF-8"><title>示例后台</title></head><body><div class="ops-portal-web root"></div><script src="./assets/js/index.js"></script></body></html>`
	spaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		_, _ = io.WriteString(w, spaHTML)
	}))
	defer spaSrv.Close()

	if !isEmptySPAShell(spaHTML, "text/html") {
		t.Fatal("expected class-mounted SPA shell with external script to be recognized as empty SPA shell")
	}
	if isEmptySPAShell(`<html><body><div>欢迎 admin</div><script src="/a.js"></script></body></html>`, "text/html") {
		t.Fatal("non-empty HTML page with visible content must not be treated as empty SPA shell")
	}

	bs := newFakeBrowser(nil)
	tab := &fakeLoginTab{infoFn: func() (sitecfg.PageInfo, error) {
		return sitecfg.PageInfo{
			Href:  "https://sso-portal.corp.example.com/#/login?redirectUrl=ops",
			Ready: "complete",
			Pass:  true,
			Text:  "账号登录 密码登录",
		}, nil
	}}
	a, site := loginTestApp(t, spaSrv, bs, tab)
	site.Method = sitecfg.MethodForm
	site.EntryURL = "https://sso-portal.corp.example.com/#/login?redirectUrl=ops"
	site.CheckURL = spaSrv.URL + "/ops-portal-web/#/home/orders/gateway"
	site.SSOHosts = "sso-portal.corp.example.com"
	if err := a.repo.(*loginTestRepository).SaveSite(site); err != nil {
		t.Fatal(err)
	}

	ok, why := a.CheckSite(site)
	if ok || !strings.Contains(why, "前端单页壳") {
		t.Fatalf("CheckSite must reject explicit SPA shell CheckURL, got ok=%v why=%q", ok, why)
	}

	if err := a.OpenLoginWindow(site); err != nil {
		t.Fatal(err)
	}
	waitSitePending(t, a, site, true, time.Second)
	time.Sleep(1100 * time.Millisecond)
	got, _ := a.repo.GetSite(site.ID)
	if got.Status == "valid" {
		t.Fatalf("watchLoginWindow falsely marked site valid while sitting on cross-domain login page: %+v", got)
	}
	// Closing window without logging in must NOT mark site valid via SPA CheckURL.
	bs.Close()
	waitSitePending(t, a, site, false, 2*time.Second)
	got, _ = a.repo.GetSite(site.ID)
	if got.Status == "valid" {
		t.Fatalf("closing window without login must not mark site valid via SPA CheckURL: %+v", got)
	}
}

func TestPersistInteractiveLoginPreservesConfiguredFormMethod(t *testing.T) {
	srv := loginTestServer(t)
	defer srv.Close()
	bs := newFakeBrowser(nil)
	capTab := &fakeCaptureLoginTab{fakeLoginTab: &fakeLoginTab{}}
	a, site := smartLoginTestApp(t, srv, bs, capTab)
	site.Method = sitecfg.MethodForm
	site.Form.Mode = "fill"
	site.Form.UsernameRef = "cfg.portal_admin_username"
	site.Form.PasswordRef = "secret.portal_admin_password"
	if err := a.repo.SaveSite(site); err != nil {
		t.Fatal(err)
	}

	// Interactive login finishes without capturing a freshly typed password (e.g., portal SSO session).
	a.persistInteractiveLogin(site, capTab, "", []string{"sso-portal.corp.example.com"})
	updated, err := a.repo.GetSite(site.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Method != sitecfg.MethodForm {
		t.Fatalf("expected configured MethodForm with PasswordRef to be preserved, got %q", updated.Method)
	}
}
