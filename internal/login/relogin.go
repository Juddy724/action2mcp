package login

import (
	"action2mcp/internal/credential"
	"action2mcp/internal/execution"

	sitecfg "action2mcp/internal/site"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

func loginErr(f string, a ...any) error { return &LoginErr{Msg: fmt.Sprintf(f, a...)} }

const (
	formFailCooldown = 10 * time.Minute
	pendingLoginMax  = 5 * time.Minute
	browserLoginMax  = 35 * time.Second
	ssoStuckAfter    = 4 * time.Second
)

// Surface is a page opened for interactive login (a real browser tab or a test fake).
type Surface interface {
	Info() (sitecfg.PageInfo, error)
	Close()
	Navigate(u string) error
	Reload() error
}

type LoginBrowser interface {
	Alive() bool
	Cookies() ([]Cookie, error)
}

func (a *Service) loginWait() time.Duration {
	if a != nil && a.pendingLoginMax > 0 {
		return a.pendingLoginMax
	}
	return pendingLoginMax
}

func formatLoginWait(d time.Duration) string {
	if d >= time.Minute && d%time.Minute == 0 {
		return fmt.Sprintf("%d 分钟", int(d.Minutes()))
	}
	if d >= time.Second {
		return fmt.Sprintf("%d 秒", int(d.Seconds()))
	}
	return d.String()
}

func sleepCancel(d time.Duration, cancel <-chan struct{}) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-cancel:
		return false
	case <-t.C:
		return true
	}
}

func browserHTTPURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("登录地址不能为空")
	}
	mapped := sitecfg.MapWSToHTTPURL(raw)
	u, err := url.Parse(mapped)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", errors.New("登录地址必须是 http:// 或 https://")
	}
	return mapped, nil
}

var (
	loginFailRe = regexp.MustCompile(`(?i)(密码错误|密码不正确|密码有误|用户名或密码|账号或密码|帐号或密码|用户名不存在|账号不存在|帐号不存在|用户不存在|登录失败|登陆失败|认证失败|验证码|invalid\s*(user\s*name|username|password|credentials?|login)|incorrect|wrong\s*password|bad\s*credentials|authentication\s*failed|login\s*failed)`)
	captchaRe   = regexp.MustCompile(`(?i)(验证码|captcha|短信|sms\s*code)`)
	csrfNameRe  = regexp.MustCompile(`(?i)^(.*csrf.*|.*xsrf.*|_token|authenticity_token|__requestverificationtoken|formhash|verifycode_token)$`)
)

// ---------- per-site state helpers ----------

func (a *Service) siteGen(st *siteState) int64 {
	a.smu.Lock()
	defer a.smu.Unlock()
	return st.gen
}

func (a *Service) bumpGen(st *siteState) {
	a.smu.Lock()
	st.gen++
	st.relogins++
	st.failUntil = time.Time{}
	st.failMsg = ""
	a.smu.Unlock()
}

// ResetSiteFailures clears the wrong-password cooldown (after editing the site or the vault).
func (a *Service) ResetSiteFailures() {
	a.smu.Lock()
	for _, st := range a.sstates {
		st.failUntil = time.Time{}
		st.failMsg = ""
	}
	a.smu.Unlock()
}

func (a *Service) ReloginCount(origin string) int {
	st := a.state(credential.NormalizeOrigin(origin))
	a.smu.Lock()
	defer a.smu.Unlock()
	return st.relogins
}

func (a *Service) pendingErr(site *sitecfg.Site, st *siteState) error {
	a.smu.Lock()
	defer a.smu.Unlock()
	if st.pending && time.Since(st.pendingAt) < a.loginWait() {
		return loginErr("「%s」正在等待你在弹出的浏览器窗口中完成登录（%s），登录完成后再重试即可", site.DisplayName(), st.pendingMsg)
	}
	st.pending = false
	return nil
}

func (a *Service) markValid(site *sitecfg.Site, loggedIn bool) {
	if loggedIn || site.Status != "valid" {
		a.repo.SetSiteStatus(site.ID, "valid", "", loggedIn)
		site.Status = "valid"
	}
}

// ---------- re-login entry point ----------

// Relogin logs in to the site again. Calls for the same site are serialised; when another call
// already re-logged in since seenGen the call returns immediately so the caller just retries.
func (a *Service) Relogin(site *sitecfg.Site, seenGen int64, force, interactive bool) error {
	st := a.state(site.Origin)
	select {
	case st.mu <- struct{}{}:
	case <-time.After(2 * browserLoginMax):
		return loginErr("「%s」正在自动登录，等待超时，请稍后重试", site.DisplayName())
	}
	defer func() { <-st.mu }()
	if !force && a.siteGen(st) != seenGen {
		return nil // another call already logged in
	}
	if err := a.pendingErr(site, st); err != nil {
		return err
	}
	a.smu.Lock()
	if !force && time.Now().Before(st.failUntil) {
		msg := st.failMsg
		a.smu.Unlock()
		return &LoginErr{Msg: msg}
	}
	a.smu.Unlock()
	if fresh, err := a.repo.GetSite(site.ID); err == nil {
		site = fresh
	}
	start := time.Now()
	how, err := a.doRelogin(site, st, interactive)
	if err == nil {
		a.bumpGen(st)
		a.repo.SetSiteStatus(site.ID, "valid", "", true)
		log.Printf("自动登录成功：%s（%s，用时 %.1f 秒）", site.Origin, how, time.Since(start).Seconds())
		return nil
	}
	msg := a.vault.Scrub(err.Error())
	a.repo.SetSiteStatus(site.ID, "invalid", msg, false)
	log.Printf("自动登录失败：%s：%s", site.Origin, msg)
	return &LoginErr{Msg: msg}
}

type needUser struct {
	url    string
	reason string // sso | page | nocreds | captcha | manual
	detail string
}

func (n *needUser) Error() string { return "需要用户登录: " + n.reason }

type credFail struct{ msg string }

func (c *credFail) Error() string { return c.msg }

func (a *Service) doRelogin(site *sitecfg.Site, st *siteState, interactive bool) (string, error) {
	var err error
	how := ""
	switch site.Method {
	case sitecfg.MethodManual:
		err = &needUser{url: site.Entry(), reason: "manual"}
	case sitecfg.MethodForm:
		if site.Form.Mode != "fill" && site.Form.Request != nil && site.Form.Request.URL != "" {
			how = "重放登录请求"
			err = a.replayLogin(site)
			var nu *needUser
			if err != nil && !errors.As(err, new(*credFail)) && !errors.As(err, &nu) {
				// replay failed for another reason (e.g. the login API changed): try filling the form
				debugf("重放登录请求失败，改为浏览器填表: %v", err)
				how = "浏览器自动填表"
				err = a.browserLogin(site, true)
			}
		} else {
			how = "浏览器自动填表"
			err = a.browserLogin(site, true)
		}
	default:
		how = "企业微信 / 单点登录"
		err = a.browserLogin(site, false)
	}
	if err == nil {
		return how, nil
	}
	var cf *credFail
	if errors.As(err, &cf) {
		a.smu.Lock()
		st.failUntil = time.Now().Add(formFailCooldown)
		st.failMsg = cf.msg + "（10 分钟内不再自动重试，修改配置后会立即恢复）"
		a.smu.Unlock()
		return how, errors.New(st.failMsg)
	}
	var nu *needUser
	if errors.As(err, &nu) {
		msg := a.needUserMsg(site, nu)
		if !interactive {
			return how, errors.New(msg)
		}
		if nu.reason == "sso" && a.ssoWindowOpen(sitecfg.HostOf(nu.url)) {
			// the same SSO (企业微信) login window is already waiting for a scan: don't pop another one
			return how, errors.New(msg)
		}
		if perr := a.popLogin(site, st, nu, true); perr != nil {
			return how, fmt.Errorf("%s（弹出浏览器窗口失败：%v）", strings.TrimSuffix(msg, "。"), perr)
		}
		return how, errors.New(msg)
	}
	return how, err
}

func (a *Service) needUserMsg(site *sitecfg.Site, nu *needUser) string {
	n := site.DisplayName()
	switch nu.reason {
	case "sso":
		return fmt.Sprintf("「%s」需要重新登录：企业微信登录已过期，请在弹出的窗口扫码后重试", n)
	case "nocreds":
		return fmt.Sprintf("「%s」需要用账号密码登录，但「配置管理」里没有这个网站的账号密码。已弹出浏览器窗口，请在窗口中登录后重试；也可以在控制台「配置管理」里保存账号密码，以后就能自动登录", n)
	case "captcha":
		return fmt.Sprintf("「%s」登录需要验证码，无法自动完成。已弹出浏览器窗口，请在窗口中登录后重试", n)
	case "manual":
		return fmt.Sprintf("「%s」需要重新登录（登录方式为「手动登录」）。已弹出浏览器窗口，请在窗口中登录后重试", n)
	default:
		return fmt.Sprintf("「%s」需要重新登录：没能自动通过企业微信登录，已弹出浏览器窗口，请在窗口中登录后重试。如果这个网站用账号密码登录，可以在控制台「配置管理」保存账号密码，并在「登录中心」把登录方式改为「账号密码」", n)
	}
}

// ---------- credentials from the vault ----------

type siteCreds struct {
	user, pass       string
	userRef, passRef string
}

var passNameRe = regexp.MustCompile(`(?i)(pass|pwd|secret)`)

var userNameRe = regexp.MustCompile(`(?i)(user|account|acct|login|name|mail|phone|mobile)`)

func (a *Service) credsFor(site *sitecfg.Site) siteCreds {
	var c siteCreds
	if r := site.Form.UsernameRef; r != "" {
		c.userRef = r
		c.user, _ = a.vault.Lookup(strings.TrimPrefix(strings.TrimPrefix(r, "cfg."), "secret."))
	}
	if r := site.Form.PasswordRef; r != "" {
		c.passRef = r
		c.pass, _ = a.vault.Lookup(strings.TrimPrefix(strings.TrimPrefix(r, "cfg."), "secret."))
	}
	if c.user != "" && c.pass != "" {
		return c
	}
	items := a.vault.ForSite(site.Origin)
	for n, e := range items {
		if c.pass == "" && e.Type == "secret" && passNameRe.MatchString(n) {
			c.pass, c.passRef = e.Value, n
		}
	}
	for n, e := range items {
		if c.user == "" && n != c.passRef && userNameRe.MatchString(n) && !passNameRe.MatchString(n) {
			c.user, c.userRef = e.Value, n
		}
	}
	return c
}

const clickSSOJS = `(function(){var re=/(企业微信|企微|wecom|wechat\s*work|work\.weixin|扫码登录|扫码登陆|单点登录|sso\s*登录|sso\s*login)/i;
var els=document.querySelectorAll('a,button,input[type=button],input[type=submit],[role=button],[onclick],li,span,div,img,label');var best=null,bl=1e9;
for(var i=0;i<els.length;i++){var e=els[i];var s=((e.innerText||'')+' '+(e.value||'')+' '+(e.title||'')+' '+(e.alt||'')+' '+(e.getAttribute('href')||'')+' '+(e.className&&e.className.baseVal===undefined?e.className:'')).trim();
if(!re.test(s))continue;if(!(e.offsetParent!==null||e.getClientRects().length))continue;var l=s.length;if(e.tagName==='A'||e.tagName==='BUTTON')l-=5;if(l<bl){bl=l;best=e}}
if(!best)return false;var a=best.closest('a,button,[role=button],[onclick]')||best;a.click();return true})()`

const clickQuickJS = `(function(){var re=/^(快速登录|一键登录|使用企业微信快速登录|企业微信快速登录)$/;var els=document.querySelectorAll('a,button,[role=button],div,span');
for(var i=0;i<els.length;i++){var e=els[i];var s=(e.innerText||'').trim();if(re.test(s)&&(e.offsetParent!==null||e.getClientRects().length)){(e.closest('a,button,[role=button]')||e).click();return true}}return false})()`

func fillJS(user, pass, userSel, passSel, submitSel string) string {
	j := func(s string) string { b, _ := json.Marshal(s); return string(b) }
	return `(function(U,P,US,PS,SS){function vis(e){return e&&(e.offsetParent!==null||e.getClientRects().length)}
function set(e,v){var pr=Object.getPrototypeOf(e);var d=Object.getOwnPropertyDescriptor(pr,'value')||Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value');e.focus();d.set.call(e,v);e.dispatchEvent(new Event('input',{bubbles:true}));e.dispatchEvent(new Event('change',{bubbles:true}));e.blur&&e.blur()}
var p=PS?document.querySelector(PS):null;if(!p){var ps=document.querySelectorAll('input[type=password]');for(var i=0;i<ps.length;i++)if(vis(ps[i])){p=ps[i];break}}
if(!p)return 'nopass';var form=p.form||p.closest('form')||document;var u=US?document.querySelector(US):null;
if(!u){var ins=form.querySelectorAll('input');var cand=null;for(var i=0;i<ins.length;i++){var e=ins[i];if(e===p)break;var ty=(e.type||'text').toLowerCase();if((ty==='text'||ty==='email'||ty==='tel'||ty==='number')&&vis(e))cand=e}
if(!cand){for(var i=0;i<ins.length;i++){var e=ins[i];var ty=(e.type||'text').toLowerCase();if((ty==='text'||ty==='email'||ty==='tel')&&vis(e)){cand=e;break}}}u=cand}
if(u&&U)set(u,U);set(p,P);
var b=SS?document.querySelector(SS):null;if(!b){var bs=form.querySelectorAll('button,input[type=submit],input[type=button],a,[role=button]');var re=/^(登\s*录|登\s*陆|立即登录|登录系统|log\s*in|login|sign\s*in|submit|确定|提交)$/i;
for(var i=0;i<bs.length;i++){var e=bs[i];var s=(e.innerText||e.value||'').trim();if(vis(e)&&re.test(s)){b=e;break}}
if(!b){for(var i=0;i<bs.length;i++){var e=bs[i];if(vis(e)&&((e.type||'')==='submit')){b=e;break}}}}
setTimeout(function(){if(b){b.click()}else if(form.requestSubmit){form.requestSubmit()}else if(form.submit){form.submit()}},150);return 'ok'})(` +
		j(user) + "," + j(pass) + "," + j(userSel) + "," + j(passSel) + "," + j(submitSel) + ")"
}

func (a *Service) browserLogin(site *sitecfg.Site, fill bool) error {
	bs, err := a.browsers.AcquireBrowser()
	if err != nil {
		return err
	}
	defer a.browsers.ReleaseBrowser(bs)
	tab, err := bs.OpenTab(site.Entry(), true)
	if err != nil {
		return fmt.Errorf("打开登录入口失败：%v", err)
	}
	defer tab.Close()
	creds := a.credsFor(site)
	var (
		clickedSSO, filled, clickedQuick bool
		ssoSince, loginSince, filledAt   time.Time
		stableHref                       string
		stableSince                      time.Time
		lastErr                          string
		headerReload                     bool
		deadline                         = time.Now().Add(browserLoginMax)
	)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		pi, err := tab.Info()
		if err != nil {
			lastErr = err.Error()
			if !bs.Alive() {
				return errors.New("登录用的浏览器意外关闭")
			}
			continue
		}
		if strings.HasPrefix(pi.Href, "chrome-error:") {
			return loginErr("打不开「%s」的登录入口 %s（网络不通？）", site.DisplayName(), site.Entry())
		}
		h := sitecfg.HostOf(pi.Href)
		if pi.Href == "about:blank" || h == "" {
			continue
		}
		if site.LoggedInPage(pi) {
			if stableHref != pi.Href {
				stableHref, stableSince = pi.Href, time.Now()
				continue
			}
			if time.Since(stableSince) >= 800*time.Millisecond {
				cs, err := bs.Cookies()
				if err == nil && len(cs) > 0 {
					a.repo.ReplaceCookies(cs)
				}
				if miss := a.missingSiteHeaders(site); len(miss) > 0 {
					if !headerReload {
						headerReload = true
						_ = tab.Reload()
					}
					// Keep looping until the header is harvested or the deadline hits.
					stableSince = time.Now()
					continue
				}
				return nil
			}
			continue
		}
		stableHref = ""
		onSite := credential.SameSite("http://"+h, site.Origin)
		if !onSite {
			loginSince = time.Time{}
			if ssoSince.IsZero() {
				ssoSince = time.Now()
			}
			// 企业微信网页登录页上的「快速登录」（本机企业微信客户端已登录时可用）
			if !clickedQuick && pi.Ready == "complete" && site.IsWeComHost(h) && time.Since(ssoSince) > 800*time.Millisecond {
				clickedQuick = true
				var ok bool
				if tab.Eval(clickQuickJS, &ok) == nil && ok {
					debugf("%s：点击了企业微信快速登录", site.Origin)
					ssoSince = time.Now()
					continue
				}
			}
			stuck := ssoStuckAfter
			if !site.IsSSOHost(h) {
				stuck = 2 * ssoStuckAfter // some other intermediate page
			}
			if pi.Ready == "complete" && time.Since(ssoSince) > stuck {
				return &needUser{url: pi.Href, reason: "sso"}
			}
			continue
		}
		ssoSince = time.Time{}
		// on the site but not logged in: its own login page
		if loginSince.IsZero() {
			loginSince = time.Now()
		}
		if pi.Ready != "complete" {
			continue
		}
		if !fill && !clickedSSO && time.Since(loginSince) > 500*time.Millisecond {
			clickedSSO = true
			var ok bool
			if tab.Eval(clickSSOJS, &ok) == nil && ok {
				debugf("%s：点击了企业微信登录按钮", site.Origin)
				loginSince = time.Now()
				continue
			}
		}
		if pi.Pass && !filled && (fill || clickedSSO) {
			if creds.pass == "" {
				if fill || time.Since(loginSince) > 1500*time.Millisecond {
					if fill {
						return &needUser{url: pi.Href, reason: "nocreds"}
					}
					return &needUser{url: pi.Href, reason: "page"}
				}
				continue
			}
			var r string
			tab.Eval(fillJS(creds.user, creds.pass, site.Form.UserSelector, site.Form.PassSelector, site.Form.SubmitSelector), &r)
			if r == "ok" {
				filled, filledAt = true, time.Now()
				debugf("%s：已自动填写账号密码并提交", site.Origin)
			}
			continue
		}
		if filled && time.Since(filledAt) > 3*time.Second {
			if captchaRe.MatchString(pi.Text) && !loginFailRe.MatchString(strings.ReplaceAll(pi.Text, "验证码", "")) {
				return &needUser{url: pi.Href, reason: "captcha"}
			}
			if pi.Pass {
				hint := failSnippet(pi.Text)
				ref := creds.passRef
				return &credFail{fmt.Sprintf("「%s」自动登录失败：%s。请在控制台「配置管理」里检查 %s 的账号密码是否正确", site.DisplayName(), hint, refName(ref))}
			}
		}
		if !filled && time.Since(loginSince) > ssoStuckAfter {
			return &needUser{url: pi.Href, reason: "page"}
		}
	}
	if lastErr != "" {
		debugf("browser login last error: %s", lastErr)
	}
	return loginErr("「%s」自动登录超时（%d 秒）。请在控制台「登录中心」点击「打开浏览器登录」手动登录一次后重试", site.DisplayName(), int(browserLoginMax.Seconds()))
}

func refName(r string) string {
	if r == "" {
		return "这个网站"
	}
	return "「" + strings.TrimPrefix(strings.TrimPrefix(r, "secret."), "cfg.") + "」"
}

func failSnippet(text string) string {
	loc := loginFailRe.FindStringIndex(text)
	if loc == nil {
		return "网站没有接受这个账号密码"
	}
	// prefer the line that contains the message
	ls := strings.LastIndexAny(text[:loc[0]], "\n\r")
	le := strings.IndexAny(text[loc[1]:], "\n\r")
	line := text[ls+1:]
	if le >= 0 {
		line = text[ls+1 : loc[1]+le]
	}
	line = strings.Join(strings.Fields(line), " ")
	if rs := []rune(line); len(rs) > 40 || ls < 0 && le < 0 {
		// no line structure (e.g. text from raw HTML): a short window around the match
		pre := []rune(text[:loc[0]])
		post := []rune(text[loc[1]:])
		if len(pre) > 6 {
			pre = pre[len(pre)-6:]
		}
		if len(post) > 12 {
			post = post[:12]
		}
		line = strings.Join(strings.Fields(string(pre)+text[loc[0]:loc[1]]+string(post)), " ")
	}
	return "网站提示「" + line + "」"
}

// ---------- interactive login window ----------

// ssoWindowOpen reports whether some site's pending login window is on the given SSO host.
func (a *Service) ssoWindowOpen(host string) bool {
	if host == "" {
		return false
	}
	a.smu.Lock()
	defer a.smu.Unlock()
	for _, st := range a.sstates {
		if st.pending && st.ssoHost == host && time.Since(st.pendingAt) < a.loginWait() {
			return true
		}
	}
	return false
}

func (a *Service) openLoginSurface(target string) (LoginBrowser, Surface, error) {
	if a.openLogin != nil {
		return a.openLogin(target)
	}
	bs, tab, err := a.browsers.OpenVisibleTab(target)
	if err != nil {
		return nil, nil, err
	}
	return bs, tab, nil
}

func (a *Service) popLogin(site *sitecfg.Site, st *siteState, nu *needUser, block bool) error {
	_ = block // always track pending so the console can cancel or time out
	target := nu.url
	if target == "" || nu.reason == "manual" || nu.reason == "nocreds" {
		target = site.Entry()
	}
	target, err := browserHTTPURL(target)
	if err != nil {
		return err
	}
	a.smu.Lock()
	if st.pending && time.Since(st.pendingAt) < a.loginWait() {
		a.smu.Unlock()
		return errors.New("正在等待登录，请先在弹出的窗口中完成登录，或点「取消」")
	}
	a.smu.Unlock()
	bs, tab, err := a.openLoginSurface(target)
	if err != nil {
		return err
	}
	short := "等待扫码"
	if nu.reason != "sso" {
		short = "等待登录"
	}
	cancel := make(chan struct{})
	a.smu.Lock()
	st.pending, st.pendingAt, st.pendingMsg = true, time.Now(), short
	st.ssoHost = ""
	if nu.reason == "sso" {
		st.ssoHost = sitecfg.HostOf(nu.url)
	}
	st.cancel = cancel
	st.loginSurf = tab
	a.smu.Unlock()
	go func() {
		defer func() {
			a.smu.Lock()
			if st.cancel == cancel {
				st.pending = false
				st.cancel = nil
				st.loginSurf = nil
			}
			a.smu.Unlock()
		}()
		a.watchLoginWindow(site, st, bs, tab, cancel)
	}()
	return nil
}

func (a *Service) watchLoginWindow(site *sitecfg.Site, st *siteState, bs LoginBrowser, tab Surface, cancel <-chan struct{}) {
	var (
		stableHref  string
		stableSince time.Time
		fails       int
		didHarvest  bool
		lastCheck   time.Time
		checkedOK   bool
		poll        = 400 * time.Millisecond
		end         = time.Now().Add(a.loginWait())
	)
	for {
		if !sleepCancel(poll, cancel) {
			tab.Close()
			a.repo.SetSiteError(site.ID, "已取消登录等待")
			log.Printf("已取消登录等待：%s", site.Origin)
			return
		}
		if time.Now().After(end) {
			tab.Close()
			msg := "登录等待超时（" + formatLoginWait(a.loginWait()) + "）"
			if miss := a.missingSiteHeaders(site); len(miss) > 0 {
				msg += "，尚未收获请求头：" + strings.Join(miss, "、")
			}
			a.repo.SetSiteStatus(site.ID, "invalid", msg, false)
			log.Printf("%s：%s", site.Origin, msg)
			return
		}
		if bs != nil && !bs.Alive() {
			a.repo.SetSiteError(site.ID, "登录窗口已关闭")
			log.Printf("登录窗口已关闭：%s", site.Origin)
			return
		}
		pi, err := tab.Info()
		if err != nil {
			fails++
			if fails > 5 {
				a.repo.SetSiteError(site.ID, "登录窗口已关闭")
				log.Printf("登录窗口已关闭：%s", site.Origin)
				return
			}
			continue
		}
		fails = 0
		loggedIn := site.LoggedInPage(pi)
		if !loggedIn && pi.Ready == "complete" {
			if checkedOK && time.Since(lastCheck) < 2*time.Second {
				loggedIn = true
			} else if lastCheck.IsZero() || time.Since(lastCheck) >= 2*time.Second {
				if bs != nil {
					if cs, err := bs.Cookies(); err == nil && len(cs) > 0 {
						a.repo.ReplaceCookies(cs)
					}
				}
				lastCheck = time.Now()
				if ok, _ := a.CheckSite(site); ok {
					loggedIn, checkedOK = true, true
				} else {
					checkedOK = false
				}
			}
		}
		if !loggedIn {
			stableHref = ""
			continue
		}
		if stableHref != pi.Href {
			stableHref, stableSince = pi.Href, time.Now()
			continue
		}
		if time.Since(stableSince) < 300*time.Millisecond {
			continue
		}
		if bs != nil {
			if cs, err := bs.Cookies(); err == nil && len(cs) > 0 {
				a.repo.ReplaceCookies(cs)
			}
		}
		if miss := a.missingSiteHeaders(site); len(miss) > 0 {
			if !didHarvest {
				didHarvest = true
				entry, err := browserHTTPURL(site.Entry())
				if err != nil {
					entry = site.Origin + "/"
				}
				if rerr := tab.Reload(); rerr != nil {
					_ = tab.Navigate(entry)
				} else if !credential.SameSite(pi.Href, site.Origin) {
					_ = tab.Navigate(entry)
				}
				log.Printf("%s：已登录，正在刷新页面以收获请求头 %s", site.Origin, strings.Join(miss, "、"))
			}
			continue
		}
		a.bumpGen(st)
		a.repo.SetSiteStatus(site.ID, "valid", "", true)
		log.Printf("已在弹出的窗口中完成登录：%s", site.Origin)
		tab.Close()
		return
	}
}

// CancelLogin stops a waiting interactive login, closes the window it opened, and resets the waiting state.
func (a *Service) CancelLogin(site *sitecfg.Site) error {
	if site == nil {
		return errors.New("站点不存在")
	}
	st := a.state(site.Origin)
	a.smu.Lock()
	if !st.pending {
		a.smu.Unlock()
		return errors.New("当前没有等待中的登录")
	}
	ch, tab := st.cancel, st.loginSurf
	a.smu.Unlock()
	if ch != nil {
		select {
		case <-ch:
		default:
			close(ch)
		}
	}
	if tab != nil {
		tab.Close()
	}
	// Give the watcher a moment to record the cancelled state.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		a.smu.Lock()
		pending := st.pending
		a.smu.Unlock()
		if !pending {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	a.smu.Lock()
	st.pending = false
	a.smu.Unlock()
	a.repo.SetSiteError(site.ID, "已取消登录等待")
	return nil
}

func (a *Service) requiredSiteHeaders(site *sitecfg.Site) []string {
	if a == nil || a.repo == nil || site == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(names ...string) {
		for _, n := range names {
			n = credential.HeaderKey(n)
			if n == "" || n == "cookie" || n == "authorization" || !credential.IsCredHeader(n) {
				continue
			}
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	addRefs := func(parts ...string) {
		for _, s := range parts {
			for _, g := range execution.PlaceholderPattern().FindAllStringSubmatch(s, -1) {
				if credential.IsCookieJarRef(g[1]) {
					continue
				}
				if name, ok := credential.HeaderBindingName(g[1]); ok {
					add(name)
				}
			}
		}
	}
	if tools, err := a.repo.ListTools(); err == nil {
		for _, t := range tools {
			if !credential.SameSite(credential.Origin(t.URL), site.Origin) {
				continue
			}
			addRefs(t.URL, t.Body)
			for _, v := range t.Headers {
				addRefs(v)
			}
			for _, msg := range t.Config.Messages {
				addRefs(msg)
			}
			add(t.CredHeaders...)
		}
	}
	for _, binding := range a.options.MiddlewareBindings() {
		if credential.SameSite(credential.Origin(binding.URL), site.Origin) {
			add(binding.Names...)
		}
	}

	if site.Form.Request != nil {
		add(site.Form.Request.CredHeaders...)
	}
	return out
}

func (a *Service) missingSiteHeaders(site *sitecfg.Site) []string {
	var miss []string
	for _, name := range a.requiredSiteHeaders(site) {
		if _, err := a.GetSiteHeader(site.Origin, name); err != nil {
			miss = append(miss, name)
		}
	}
	return miss
}

// ---------- HTTP replay of a recorded login request ----------

type httpSession struct {
	cookies []Cookie
	client  *http.Client
}

func newHTTPSession(cs []Cookie) *httpSession {
	cp := append([]Cookie(nil), cs...)
	return &httpSession{cookies: cp, client: &http.Client{Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

func (hs *httpSession) absorb(resp *http.Response) []Cookie {
	var got []Cookie
	host := strings.ToLower(resp.Request.URL.Hostname())
	for _, hc := range resp.Cookies() {
		c := Cookie{Name: hc.Name, Value: hc.Value, Path: hc.Path, Secure: hc.Secure, HTTPOnly: hc.HttpOnly}
		if c.Path == "" {
			c.Path = "/"
		}
		if hc.Domain != "" {
			c.Domain = "." + strings.TrimPrefix(strings.ToLower(hc.Domain), ".")
		} else {
			c.Domain = host
		}
		del := hc.MaxAge < 0
		switch {
		case hc.MaxAge > 0:
			c.Expires = float64(time.Now().Unix() + int64(hc.MaxAge))
		case !hc.Expires.IsZero():
			c.Expires = float64(hc.Expires.Unix())
			if hc.Expires.Before(time.Now()) {
				del = true
			}
		default:
			c.Session = true
		}
		out := hs.cookies[:0]
		for _, o := range hs.cookies {
			if !(o.Name == c.Name && strings.EqualFold(o.Domain, c.Domain) && o.Path == c.Path) {
				out = append(out, o)
			}
		}
		hs.cookies = out
		if !del {
			hs.cookies = append(hs.cookies, c)
			got = append(got, c)
		}
	}
	return got
}

// do performs a request following redirects manually so every Set-Cookie is kept.
func (hs *httpSession) do(method, u string, headers map[string]string, body string) (int, string, string, []Cookie, error) {
	var all []Cookie
	for i := 0; i < 10; i++ {
		var rb io.Reader
		if body != "" && method != "GET" {
			rb = strings.NewReader(body)
		}
		req, err := http.NewRequest(method, u, rb)
		if err != nil {
			return 0, "", u, all, err
		}
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		if req.Header.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36")
		}
		if ch, _ := execution.CookieHeader(hs.cookies, u); ch != "" {
			req.Header.Set("Cookie", ch)
		}
		resp, err := hs.client.Do(req)
		if err != nil {
			return 0, "", u, all, err
		}
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
		resp.Body.Close()
		all = append(all, hs.absorb(resp)...)
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && resp.Header.Get("Location") != "" {
			next, err := resp.Request.URL.Parse(resp.Header.Get("Location"))
			if err != nil {
				return resp.StatusCode, string(data), u, all, nil
			}
			u = next.String()
			if resp.StatusCode != 307 && resp.StatusCode != 308 {
				method, body = "GET", ""
				h2 := map[string]string{}
				for k, v := range headers {
					if !strings.EqualFold(k, "content-type") {
						h2[k] = v
					}
				}
				headers = h2
			}
			continue
		}
		return resp.StatusCode, string(data), u, all, nil
	}
	return 0, "", u, all, errors.New("重定向次数过多")
}

var (
	csrfInputRe1 = regexp.MustCompile(`(?is)<input[^>]*name\s*=\s*["']([^"']+)["'][^>]*value\s*=\s*["']([^"']*)["']`)
	csrfInputRe2 = regexp.MustCompile(`(?is)<input[^>]*value\s*=\s*["']([^"']*)["'][^>]*name\s*=\s*["']([^"']+)["']`)
	csrfMetaRe   = regexp.MustCompile(`(?is)<meta[^>]*name\s*=\s*["'](csrf[-_]?token|_csrf|xsrf[-_]?token)["'][^>]*content\s*=\s*["']([^"']+)["']`)
	csrfJSRe     = regexp.MustCompile(`(?i)["']?(csrf[_-]?token|_csrf|xsrf[_-]?token|_token)["']?\s*[:=]\s*["']([^"']{6,})["']`)
)

func extractCSRF(html, field string) (string, string) {
	match := func(n string) bool {
		if field != "" {
			return strings.EqualFold(n, field)
		}
		return csrfNameRe.MatchString(n)
	}
	for _, m := range csrfInputRe1.FindAllStringSubmatch(html, -1) {
		if match(m[1]) {
			return m[1], m[2]
		}
	}
	for _, m := range csrfInputRe2.FindAllStringSubmatch(html, -1) {
		if match(m[2]) {
			return m[2], m[1]
		}
	}
	if m := csrfMetaRe.FindStringSubmatch(html); m != nil {
		return m[1], m[2]
	}
	if m := csrfJSRe.FindStringSubmatch(html); m != nil {
		return m[1], m[2]
	}
	return "", ""
}

func (a *Service) replayLogin(site *sitecfg.Site) error {
	fl := site.Form
	lr := fl.Request
	hs := newHTTPSession(a.repo.AllCookies())
	client, closeIdle := (execution.HTTPGuard{ConsolePort: a.options.ConsolePort()}).Client(a.options.HTTPClient())
	defer closeIdle()
	client.Timeout = 30 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	hs.client = &client
	// drop the stale session cookies of this host so the login starts clean? keep them: most sites
	// simply overwrite them, and some need e.g. a device cookie.
	t := &Tool{Method: lr.Method, URL: lr.URL, Headers: lr.Headers, Body: lr.Body, CredHeaders: lr.CredHeaders}
	for _, r := range t.RenderRefs() {
		if _, err := a.vault.Resolve(r); err != nil {
			return &needUser{url: site.Entry(), reason: "nocreds", detail: err.Error()}
		}
	}
	needCSRF := strings.Contains(lr.Body+lr.URL, "{{csrf}}") || fl.CSRFField != ""
	for _, h := range lr.CredHeaders {
		if strings.Contains(h, "csrf") || strings.Contains(h, "xsrf") {
			needCSRF = true
		}
	}
	token := ""
	page := fl.LoginURL
	if page == "" {
		page = site.Entry()
	}
	if needCSRF || true {
		st, body, _, _, err := hs.do("GET", page, map[string]string{"Accept": "text/html,application/xhtml+xml,*/*"}, "")
		if err != nil {
			return fmt.Errorf("打开登录页 %s 失败：%v", page, err)
		}
		if st < 400 {
			_, token = extractCSRF(body, fl.CSRFField)
		}
	}
	if token == "" {
		for _, c := range hs.cookies {
			ln := strings.ToLower(c.Name)
			if (strings.Contains(ln, "csrf") || strings.Contains(ln, "xsrf")) && hostMatch(c, lr.URL) {
				token, _ = url.QueryUnescape(c.Value)
			}
		}
	}
	if needCSRF && token == "" && strings.Contains(lr.Body+lr.URL, "{{csrf}}") {
		return fmt.Errorf("没能从登录页 %s 取到 CSRF 令牌", page)
	}
	method, u, headers, body, err := t.RenderWith(nil, a.vault.Resolve, map[string]any{"csrf": token})
	if err != nil {
		return &needUser{url: site.Entry(), reason: "nocreds", detail: err.Error()}
	}
	for _, h := range lr.CredHeaders {
		if strings.Contains(h, "csrf") || strings.Contains(h, "xsrf") {
			v := token
			for _, c := range hs.cookies {
				ln := strings.ToLower(c.Name)
				if (strings.Contains(ln, "csrf") || strings.Contains(ln, "xsrf")) && hostMatch(c, u) {
					v, _ = url.QueryUnescape(c.Value)
				}
			}
			if v != "" {
				headers[h] = v
			}
		}
	}
	if execution.HeaderGet(headers, "Referer") == "" {
		headers["Referer"] = page
	}
	if execution.HeaderGet(headers, "Origin") == "" && method != "GET" {
		headers["Origin"] = credential.Origin(u)
	}
	status, rbody, final, got, err := hs.do(method, u, headers, body)
	if err != nil {
		return fmt.Errorf("登录请求发送失败：%v", err)
	}
	short := rbody
	if len(short) > 6000 {
		short = short[:6000]
	}
	plain := htmlText(short)
	creds := a.credsFor(site)
	ref := creds.passRef
	if r := fl.PasswordRef; r != "" {
		ref = r
	}
	if captchaRe.MatchString(plain) && (status >= 400 || loginFailRe.MatchString(plain)) {
		return &needUser{url: site.Entry(), reason: "captcha"}
	}
	if status >= 400 || loginFailRe.MatchString(plain) || (sitecfg.ContainsPasswordInput(rbody) && !site.IsLoginURL(u) && site.IsLoginURL(final)) ||
		(sitecfg.ContainsPasswordInput(rbody) && len(got) == 0) {
		hint := failSnippet(a.vault.Scrub(plain))
		if status >= 400 && !loginFailRe.MatchString(plain) {
			hint = fmt.Sprintf("登录接口返回 HTTP %d", status)
		}
		return &credFail{fmt.Sprintf("「%s」自动登录失败：%s。请在控制台「配置管理」里检查 %s 的账号密码是否正确", site.DisplayName(), hint, refName(ref))}
	}
	if len(got) == 0 {
		return errors.New("登录请求没有返回任何新的 Cookie")
	}
	a.browsers.ApplyCookies(hs.cookies)
	return nil
}

func hostMatch(c Cookie, u string) bool {
	h, _ := execution.CookieHeader([]Cookie{c}, u)
	return h != ""
}

var tagRe = regexp.MustCompile(`(?s)<script.*?</script>|<style.*?</style>|<[^>]+>`)

func htmlText(s string) string {
	if strings.Contains(s, "<") {
		s = tagRe.ReplaceAllString(s, "\n")
	}
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.Join(strings.Fields(l), " "); l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// ---------- status check & keepalive ----------

// CheckSite tells whether the saved login state is still valid (no re-login).
func (a *Service) CheckSite(site *sitecfg.Site) (bool, string) {
	u := site.CheckURL
	if u == "" {
		u = site.Origin + "/"
	}
	cs, _ := a.browsers.CookiesFor(u)
	t := &Tool{Method: "GET", Headers: map[string]string{"Accept": "text/html,application/json,*/*"}}
	res, err := a.options.Probe(t, "GET", u, t.Headers, "", cs, "")
	if err != nil || res.Error != "" {
		msg := "请求失败"
		if err != nil {
			msg += "：" + err.Error()
		} else {
			msg += "：" + res.Error
		}
		return false, msg
	}
	bad, why := site.NotLoggedIn(res.Status, res.Body, execution.HeaderGet(res.Headers, "Content-Type"), res.Redirects(), u)
	if bad {
		a.repo.SetSiteStatus(site.ID, "invalid", why, false)
		return false, why
	}
	a.repo.SetSiteStatus(site.ID, "valid", "", false)
	return true, ""
}

func (a *Service) KeepaliveLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	last := map[int64]time.Time{}
	for {
		select {
		case <-a.options.Quit:
			return
		case <-t.C:
		}
		for _, s := range a.repo.ListSites() {
			if s.KeepaliveMin <= 0 {
				continue
			}
			if time.Since(last[s.ID]) < time.Duration(s.KeepaliveMin)*time.Minute {
				continue
			}
			last[s.ID] = time.Now()
			st := a.state(s.Origin)
			gen := a.siteGen(st)
			if ok, _ := a.CheckSite(s); !ok {
				if err := a.Relogin(s, gen, false, false); err != nil {
					debugf("保活：%s 自动登录失败：%v", s.Origin, err)
				}
			}
		}
	}
}

// OpenLoginWindow opens the site's login entry in a visible window; once the user is logged in
// the cookies are saved and the site is marked 有效.
func (a *Service) OpenLoginWindow(site *sitecfg.Site) error {
	return a.popLogin(site, a.state(site.Origin), &needUser{reason: "manual"}, false)
}
