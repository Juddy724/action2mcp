package main

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// loginTab is a page opened by Action2MCP itself (background re-login or a login window).
type loginTab struct {
	bs       *BrowserSession
	targetID string
	session  string
}

func (bs *BrowserSession) userAgent() string {
	var v struct {
		UserAgent string `json:"userAgent"`
	}
	bs.call("", "Browser.getVersion", nil, &v)
	return strings.ReplaceAll(v.UserAgent, "HeadlessChrome", "Chrome")
}

// openTab opens u in a new tab (in the background when possible) and attaches to it.
func (bs *BrowserSession) openTab(u string, background bool) (*loginTab, error) {
	var r struct {
		TargetID string `json:"targetId"`
	}
	p := map[string]any{"url": "about:blank"}
	if background {
		p["background"] = true
	}
	if err := bs.call("", "Target.createTarget", p, &r); err != nil {
		return nil, err
	}
	bs.mu.Lock()
	if bs.ignore == nil {
		bs.ignore = map[string]bool{}
	}
	bs.ignore[r.TargetID] = true
	bs.mu.Unlock()
	var at struct {
		SessionID string `json:"sessionId"`
	}
	if err := bs.call("", "Target.attachToTarget", map[string]any{"targetId": r.TargetID, "flatten": true}, &at); err != nil {
		bs.call("", "Target.closeTarget", map[string]any{"targetId": r.TargetID}, nil)
		return nil, err
	}
	t := &loginTab{bs: bs, targetID: r.TargetID, session: at.SessionID}
	if bs.headless {
		if ua := bs.userAgent(); ua != "" {
			bs.call(t.session, "Emulation.setUserAgentOverride", map[string]any{"userAgent": ua, "acceptLanguage": "zh-CN,zh;q=0.9,en;q=0.8"}, nil)
		}
	}
	bs.call(t.session, "Runtime.runIfWaitingForDebugger", nil, nil)
	if err := bs.call(t.session, "Page.navigate", map[string]any{"url": u}, nil); err != nil {
		debugf("navigate %s: %v", u, err)
	}
	return t, nil
}

func (t *loginTab) eval(expr string, out any) error {
	var r struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text string `json:"text"`
		} `json:"exceptionDetails"`
	}
	if err := t.bs.call(t.session, "Runtime.evaluate", map[string]any{"expression": expr, "returnByValue": true}, &r); err != nil {
		return err
	}
	if r.ExceptionDetails != nil {
		return errors.New(r.ExceptionDetails.Text)
	}
	if out != nil && len(r.Result.Value) > 0 {
		return json.Unmarshal(r.Result.Value, out)
	}
	return nil
}

func (t *loginTab) info() (pageInfo, error) {
	var s string
	var pi pageInfo
	if err := t.eval(pageInfoJS, &s); err != nil {
		return pi, err
	}
	err := json.Unmarshal([]byte(s), &pi)
	return pi, err
}

func (t *loginTab) close() {
	if t == nil || t.bs == nil {
		return
	}
	t.bs.call("", "Target.closeTarget", map[string]any{"targetId": t.targetID}, nil)
}

func (t *loginTab) navigate(u string) error {
	if t == nil || t.bs == nil {
		return errors.New("登录窗口不可用")
	}
	return t.bs.call(t.session, "Page.navigate", map[string]any{"url": u}, nil)
}

func (t *loginTab) reload() error {
	if t == nil || t.bs == nil {
		return errors.New("登录窗口不可用")
	}
	return t.bs.call(t.session, "Page.reload", map[string]any{"ignoreCache": true}, nil)
}

func (t *loginTab) activate() {
	t.bs.call("", "Target.activateTarget", map[string]any{"targetId": t.targetID}, nil)
	t.bs.call(t.session, "Page.bringToFront", nil, nil)
}

// setCookies writes cookies into the browser (host-only cookies via url, domain cookies via domain).
func (bs *BrowserSession) setCookies(cs []Cookie) error {
	params := []map[string]any{}
	nowS := float64(time.Now().Unix())
	for _, c := range cs {
		if !c.Session && c.Expires > 0 && c.Expires < nowS {
			continue
		}
		p := map[string]any{"name": c.Name, "value": c.Value, "path": c.Path, "secure": c.Secure, "httpOnly": c.HTTPOnly}
		if c.Path == "" {
			p["path"] = "/"
		}
		if strings.HasPrefix(c.Domain, ".") {
			p["domain"] = c.Domain
		} else {
			scheme := "http"
			if c.Secure {
				scheme = "https"
			}
			p["url"] = scheme + "://" + c.Domain + p["path"].(string)
		}
		if !c.Session && c.Expires > 0 {
			p["expires"] = c.Expires
		}
		params = append(params, p)
	}
	if len(params) == 0 {
		return nil
	}
	return bs.call("", "Storage.setCookies", map[string]any{"cookies": params}, nil)
}

// restoreCookies puts saved cookies the browser does not have (typically session cookies that
// were lost when the browser was closed) back into a freshly started browser.
func (a *App) restoreCookies(bs *BrowserSession) {
	have, err := bs.Cookies()
	if err != nil {
		return
	}
	k := func(c Cookie) string { return c.Name + "|" + strings.ToLower(c.Domain) + "|" + c.Path }
	seen := map[string]bool{}
	for _, c := range have {
		seen[k(c)] = true
	}
	var miss []Cookie
	for _, c := range a.store.AllCookies() {
		if !seen[k(c)] {
			miss = append(miss, c)
		}
	}
	if len(miss) > 0 {
		err := bs.setCookies(miss)
		debugf("restored %d saved cookies into browser: %v", len(miss), err)
	}
}

// ---------- shared browser acquisition ----------

// acquireBrowser returns the running dedicated browser or starts a headless one. Every call
// must be paired with releaseBrowser.
func (a *App) acquireBrowser() (*BrowserSession, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.browser != nil && a.browser.Alive() {
		a.browser.users++
		return a.browser, nil
	}
	hb, err := a.LaunchBrowser(true)
	if err != nil {
		return nil, err
	}
	a.browser = hb
	hb.users = 1
	return hb, nil
}

func (a *App) releaseBrowser(bs *BrowserSession) {
	a.mu.Lock()
	bs.users--
	if bs.users < 0 {
		bs.users = 0
	}
	idle := bs.users == 0 && bs.headless
	a.mu.Unlock()
	if !idle {
		return
	}
	time.AfterFunc(15*time.Second, func() {
		a.mu.Lock()
		if a.browser == bs && bs.users == 0 {
			a.browser = nil
			a.mu.Unlock()
			bs.Close()
			return
		}
		a.mu.Unlock()
	})
}

// evictHeadless closes a background (headless) browser once nobody uses it, so a visible
// window can be started on the same profile.
func (a *App) evictHeadless(wait time.Duration) {
	end := time.Now().Add(wait)
	for {
		a.mu.Lock()
		bs := a.browser
		if bs == nil || !bs.Alive() || !bs.headless {
			a.mu.Unlock()
			return
		}
		if bs.users == 0 || time.Now().After(end) {
			a.browser = nil
			a.mu.Unlock()
			if cs, err := bs.Cookies(); err == nil && len(cs) > 0 {
				a.store.ReplaceCookies(cs)
			}
			bs.Close()
			return
		}
		a.mu.Unlock()
		time.Sleep(200 * time.Millisecond)
	}
}

// openVisibleTab shows u in a visible window of the dedicated browser and brings it to front.
func (a *App) openVisibleTab(u string) (*BrowserSession, *loginTab, error) {
	a.evictHeadless(30 * time.Second)
	a.mu.Lock()
	bs := a.browser
	if bs != nil && bs.Alive() && !bs.headless {
		a.mu.Unlock()
		t, err := bs.openTab(u, false)
		if err != nil {
			return nil, nil, err
		}
		t.activate()
		return bs, t, nil
	}
	nb, err := a.LaunchBrowser(false)
	if err != nil {
		a.mu.Unlock()
		return nil, nil, err
	}
	a.browser = nb
	a.mu.Unlock()
	// use the initial window's tab
	var sess string
	select {
	case sess = <-nb.firstPg:
	case <-time.After(10 * time.Second):
	}
	if sess == "" {
		t, err := nb.openTab(u, false)
		return nb, t, err
	}
	nb.mu.Lock()
	tid := nb.pages[sess]
	nb.mu.Unlock()
	t := &loginTab{bs: nb, targetID: tid, session: sess}
	nb.call(sess, "Page.navigate", map[string]any{"url": u}, nil)
	t.activate()
	return nb, t, nil
}
