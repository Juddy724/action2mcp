package main

import (
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

// LoginErr is a login problem explained in Chinese for the AI / user.
type LoginErr struct{ Msg string }

func (e *LoginErr) Error() string { return e.Msg }

func loginErr(f string, a ...any) error { return &LoginErr{fmt.Sprintf(f, a...)} }

const (
	formFailCooldown = 10 * time.Minute
	pendingMax       = 10 * time.Minute
	browserLoginMax  = 35 * time.Second
	ssoStuckAfter    = 4 * time.Second
)

var (
	loginFailRe = regexp.MustCompile(`(?i)(密码错误|密码不正确|密码有误|用户名或密码|账号或密码|帐号或密码|用户名不存在|账号不存在|帐号不存在|用户不存在|登录失败|登陆失败|认证失败|验证码|invalid\s*(user\s*name|username|password|credentials?|login)|incorrect|wrong\s*password|bad\s*credentials|authentication\s*failed|login\s*failed)`)
	captchaRe   = regexp.MustCompile(`(?i)(验证码|captcha|短信|sms\s*code)`)
	csrfNameRe  = regexp.MustCompile(`(?i)^(.*csrf.*|.*xsrf.*|_token|authenticity_token|__requestverificationtoken|formhash|verifycode_token)$`)
)

// ---------- per-site state helpers ----------

func (a *App) siteGen(st *siteState) int64 {
	a.smu.Lock()
	defer a.smu.Unlock()
	return st.gen
}

func (a *App) bumpGen(st *siteState) {
	a.smu.Lock()
	st.gen++
	st.relogins++
	st.failUntil = time.Time{}
	st.failMsg = ""
	a.smu.Unlock()
}

// ResetSiteFailures clears the wrong-password cooldown (after editing the site or the vault).
func (a *App) ResetSiteFailures() {
	a.smu.Lock()
	for _, st := range a.sstates {
		st.failUntil = time.Time{}
		st.failMsg = ""
	}
	a.smu.Unlock()
}

func (a *App) ReloginCount(origin string) int {
	st := a.state(normalizeOrigin(origin))
	a.smu.Lock()
	defer a.smu.Unlock()
	return st.relogins
}

func (a *App) pendingErr(site *Site, st *siteState) error {
	a.smu.Lock()
	defer a.smu.Unlock()
	if st.pending && time.Since(st.pendingAt) < pendingMax {
		return loginErr("「%s」正在等待你在弹出的浏览器窗口中完成登录（%s），登录完成后再重试即可", site.DisplayName(), st.pendingMsg)
	}
	st.pending = false
	return nil
}

func (a *App) markValid(site *Site, loggedIn bool) {
	if loggedIn || site.Status != "valid" {
		a.store.SetSiteStatus(site.ID, "valid", "", loggedIn)
		site.Status = "valid"
	}
}

// ---------- re-login entry point ----------

// Relogin logs in to the site again. Calls for the same site are serialised; when another call
// already re-logged in since seenGen the call returns immediately so the caller just retries.
func (a *App) Relogin(site *Site, seenGen int64, force, interactive bool) error {
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
		return &LoginErr{msg}
	}
	a.smu.Unlock()
	if fresh, err := a.store.GetSite(site.ID); err == nil {
		site = fresh
	}
	start := time.Now()
	how, err := a.doRelogin(site, st, interactive)
	if err == nil {
		a.bumpGen(st)
		a.store.SetSiteStatus(site.ID, "valid", "", true)
		log.Printf("自动登录成功：%s（%s，用时 %.1f 秒）", site.Origin, how, time.Since(start).Seconds())
		return nil
	}
	msg := a.vault.Scrub(err.Error())
	a.store.SetSiteStatus(site.ID, "invalid", msg, false)
	log.Printf("自动登录失败：%s：%s", site.Origin, msg)
	return &LoginErr{msg}
}

type needUser struct {
	url    string
	reason string // sso | page | nocreds | captcha | manual
	detail string
}

func (n *needUser) Error() string { return "需要用户登录: " + n.reason }

type credFail struct{ msg string }

func (c *credFail) Error() string { return c.msg }

func (a *App) doRelogin(site *Site, st *siteState, interactive bool) (string, error) {
	var err error
	how := ""
	switch site.Method {
	case MethodManual:
		err = &needUser{url: site.Entry(), reason: "manual"}
	case MethodForm:
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
		if nu.reason == "sso" && a.ssoWindowOpen(hostOf(nu.url)) {
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

func (a *App) needUserMsg(site *Site, nu *needUser) string {
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

func (a *App) credsFor(site *Site) siteCreds {
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
		if c.pass == "" && e.typ == "secret" && passNameRe.MatchString(n) {
			c.pass, c.passRef = e.value, n
		}
	}
	for n, e := range items {
		if c.user == "" && n != c.passRef && userNameRe.MatchString(n) && !passNameRe.MatchString(n) {
			c.user, c.userRef = e.value, n
		}
	}
	return c
}

// ---------- browser based login (WeCom SSO / form fill) ----------

type pageInfo struct {
	Href  string `json:"h"`
	Ready string `json:"r"`
	Pass  bool   `json:"p"`
	Text  string `json:"t"`
}

const pageInfoJS = `(function(){var p=null;var ps=document.querySelectorAll('input[type=password]');for(var i=0;i<ps.length;i++){var e=ps[i];if(e.offsetParent!==null||e.getClientRects().length){p=e;break}}
var t='';try{t=(document.body&&document.body.innerText||'').slice(0,3000)}catch(e){}
return JSON.stringify({h:location.href,r:document.readyState,p:!!p,t:t})})()`

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

func (s *Site) loggedInPage(pi pageInfo) bool {
	if s.SuccessURL != "" {
		if re, err := regexp.Compile(s.SuccessURL); err == nil && re.MatchString(pi.Href) && pi.Ready == "complete" {
			return true
		}
		return false
	}
	h := hostOf(pi.Href)
	if h == "" || !sameSite("http://"+h, s.Origin) {
		return false
	}
	if s.isLoginURL(pi.Href) || pi.Pass || pi.Ready != "complete" {
		return false
	}
	if !s.Detect.NoDefaults && len(pi.Text) < 300 && shortNotLoginRe.MatchString(pi.Text) {
		return false
	}
	return true
}

func (a *App) browserLogin(site *Site, fill bool) error {
	bs, err := a.acquireBrowser()
	if err != nil {
		return err
	}
	defer a.releaseBrowser(bs)
	tab, err := bs.openTab(site.Entry(), true)
	if err != nil {
		return fmt.Errorf("打开登录入口失败：%v", err)
	}
	defer tab.close()
	creds := a.credsFor(site)
	var (
		clickedSSO, filled, clickedQuick bool
		ssoSince, loginSince, filledAt   time.Time
		stableHref                       string
		stableSince                      time.Time
		lastErr                          string
		deadline                         = time.Now().Add(browserLoginMax)
	)
	for time.Now().Before(deadline) {
		time.Sleep(300 * time.Millisecond)
		pi, err := tab.info()
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
		h := hostOf(pi.Href)
		if pi.Href == "about:blank" || h == "" {
			continue
		}
		if site.loggedInPage(pi) {
			if stableHref != pi.Href {
				stableHref, stableSince = pi.Href, time.Now()
				continue
			}
			if time.Since(stableSince) >= 800*time.Millisecond {
				cs, err := bs.Cookies()
				if err == nil && len(cs) > 0 {
					a.store.ReplaceCookies(cs)
				}
				return nil
			}
			continue
		}
		stableHref = ""
		onSite := sameSite("http://"+h, site.Origin)
		if !onSite {
			loginSince = time.Time{}
			if ssoSince.IsZero() {
				ssoSince = time.Now()
			}
			// 企业微信网页登录页上的「快速登录」（本机企业微信客户端已登录时可用）
			if !clickedQuick && pi.Ready == "complete" && site.isWeComHost(h) && time.Since(ssoSince) > 800*time.Millisecond {
				clickedQuick = true
				var ok bool
				if tab.eval(clickQuickJS, &ok) == nil && ok {
					debugf("%s：点击了企业微信快速登录", site.Origin)
					ssoSince = time.Now()
					continue
				}
			}
			stuck := ssoStuckAfter
			if !site.isSSOHost(h) {
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
			if tab.eval(clickSSOJS, &ok) == nil && ok {
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
			tab.eval(fillJS(creds.user, creds.pass, site.Form.UserSelector, site.Form.PassSelector, site.Form.SubmitSelector), &r)
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
func (a *App) ssoWindowOpen(host string) bool {
	if host == "" {
		return false
	}
	a.smu.Lock()
	defer a.smu.Unlock()
	for _, st := range a.sstates {
		if st.pending && st.ssoHost == host && time.Since(st.pendingAt) < pendingMax {
			return true
		}
	}
	return false
}

func (a *App) popLogin(site *Site, st *siteState, nu *needUser, block bool) error {
	target := nu.url
	if target == "" || nu.reason == "manual" || nu.reason == "nocreds" {
		target = site.Entry()
	}
	bs, tab, err := a.openVisibleTab(target)
	if err != nil {
		return err
	}
	short := "等待扫码"
	if nu.reason != "sso" {
		short = "等待登录"
	}
	if block {
		a.smu.Lock()
		st.pending, st.pendingAt, st.pendingMsg = true, time.Now(), short
		st.ssoHost = ""
		if nu.reason == "sso" {
			st.ssoHost = hostOf(nu.url)
		}
		a.smu.Unlock()
	}
	go func() {
		if block {
			defer func() {
				a.smu.Lock()
				st.pending = false
				a.smu.Unlock()
			}()
		}
		var stableHref string
		var stableSince time.Time
		fails := 0
		end := time.Now().Add(pendingMax)
		for time.Now().Before(end) {
			time.Sleep(700 * time.Millisecond)
			if !bs.Alive() {
				return
			}
			pi, err := tab.info()
			if err != nil {
				fails++
				if fails > 5 {
					return // tab closed by the user
				}
				continue
			}
			fails = 0
			if !site.loggedInPage(pi) {
				stableHref = ""
				continue
			}
			if stableHref != pi.Href {
				stableHref, stableSince = pi.Href, time.Now()
				continue
			}
			if time.Since(stableSince) < 1200*time.Millisecond {
				continue
			}
			if cs, err := bs.Cookies(); err == nil && len(cs) > 0 {
				a.store.ReplaceCookies(cs)
			}
			a.bumpGen(st)
			a.store.SetSiteStatus(site.ID, "valid", "", true)
			log.Printf("已在弹出的窗口中完成登录：%s", site.Origin)
			tab.close()
			return
		}
	}()
	return nil
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
		if ch, _ := CookieHeader(hs.cookies, u); ch != "" {
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

func (a *App) replayLogin(site *Site) error {
	fl := site.Form
	lr := fl.Request
	hs := newHTTPSession(a.store.AllCookies())
	client, closeIdle := a.toolHTTPClient()
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
	if headerGet(headers, "Referer") == "" {
		headers["Referer"] = page
	}
	if headerGet(headers, "Origin") == "" && method != "GET" {
		headers["Origin"] = originOf(u)
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
	if status >= 400 || loginFailRe.MatchString(plain) || (passwordInputRe.MatchString(rbody) && !site.isLoginURL(u) && site.isLoginURL(final)) ||
		(passwordInputRe.MatchString(rbody) && len(got) == 0) {
		hint := failSnippet(a.vault.Scrub(plain))
		if status >= 400 && !loginFailRe.MatchString(plain) {
			hint = fmt.Sprintf("登录接口返回 HTTP %d", status)
		}
		return &credFail{fmt.Sprintf("「%s」自动登录失败：%s。请在控制台「配置管理」里检查 %s 的账号密码是否正确", site.DisplayName(), hint, refName(ref))}
	}
	if len(got) == 0 {
		return errors.New("登录请求没有返回任何新的 Cookie")
	}
	a.applyCookies(hs.cookies)
	return nil
}

func hostMatch(c Cookie, u string) bool {
	h, _ := CookieHeader([]Cookie{c}, u)
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

// applyCookies stores cookies obtained over HTTP and pushes them into a running browser so the
// periodic browser→jar sync does not drop them.
func (a *App) applyCookies(cs []Cookie) {
	a.store.SaveCookies(cs)
	a.mu.Lock()
	bs := a.browser
	a.mu.Unlock()
	if bs != nil && bs.Alive() {
		bs.setCookies(cs)
	}
}

// ---------- status check & keepalive ----------

// CheckSite tells whether the saved login state is still valid (no re-login).
func (a *App) CheckSite(site *Site) (bool, string) {
	u := site.CheckURL
	if u == "" {
		u = site.Origin + "/"
	}
	cs, _ := a.CookiesFor(u)
	t := &Tool{Method: "GET", Headers: map[string]string{"Accept": "text/html,application/json,*/*"}}
	res, err := a.doCall(t, "GET", u, t.Headers, "", cs, "")
	if err != nil || res.Error != "" {
		msg := "请求失败"
		if err != nil {
			msg += "：" + err.Error()
		} else {
			msg += "：" + res.Error
		}
		return false, msg
	}
	bad, why := site.NotLoggedIn(res.Status, res.Body, headerGet(res.Headers, "Content-Type"), res.hops, u)
	if bad {
		a.store.SetSiteStatus(site.ID, "invalid", why, false)
		return false, why
	}
	a.store.SetSiteStatus(site.ID, "valid", "", false)
	return true, ""
}

func (a *App) keepaliveLoop() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
	last := map[int64]time.Time{}
	for {
		select {
		case <-a.quit:
			return
		case <-t.C:
		}
		for _, s := range a.store.ListSites() {
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
func (a *App) OpenLoginWindow(site *Site) error {
	return a.popLogin(site, a.state(site.Origin), &needUser{reason: "manual"}, false)
}
