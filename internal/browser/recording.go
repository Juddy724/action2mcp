package browser

import (
	"action2mcp/internal/execution"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"
)

type StopInfo struct {
	RecordingID    int64                 `json:"recording_id"`
	Name           string                `json:"name"`
	Count          int                   `json:"count"`
	Useful         int                   `json:"useful"`
	Reason         string                `json:"reason"`
	At             string                `json:"at"`
	LoginDetection *RecordingLoginResult `json:"login_detection,omitempty"`
}

func (a *Manager) StartRecording(name, startURL string) (int64, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		name = "录制 " + time.Now().Format("01-02 15:04")
	}
	startURL = strings.TrimSpace(startURL)
	if startURL != "" && !strings.Contains(startURL, "://") {
		startURL = "https://" + startURL
	}
	if startURL != "" {
		if _, err := url.Parse(startURL); err != nil {
			return 0, errors.New("起始网址格式不正确")
		}
	}
	a.EvictHeadless(30 * time.Second)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.recID != 0 {
		return 0, fmt.Errorf("已经有一个录制在进行中（%s），请先结束它", a.recName)
	}
	bs := a.browser
	fresh := false
	if bs != nil && (!bs.Alive() || bs.headless) {
		if bs.Alive() {
			bs.Close()
		}
		bs = nil
		a.browser = nil
	}
	if bs == nil {
		var err error
		bs, err = a.Launch(false)
		if err != nil {
			return 0, err
		}
		a.browser = bs
		fresh = true
	}
	id, err := a.repo.CreateRecording(name, startURL)
	if err != nil {
		return 0, err
	}
	if err := bs.StartRecordingOn(id, name, startURL, fresh); err != nil {
		log.Printf("打开起始页面失败: %v", err)
	}
	a.recID, a.recName, a.recStart = id, name, time.Now()
	log.Printf("开始录制 #%d %s", id, name)
	return id, nil
}

// StopRecording finishes the active recording. reason: overlay|command|console|browser-closed
func (a *Manager) StopRecording(reason string) (*StopInfo, error) {
	a.mu.Lock()
	if a.recID == 0 {
		last := copyStopInfo(a.lastStop)
		a.mu.Unlock()
		if last != nil && reason != "overlay" {
			return last, errors.New("当前没有正在进行的录制")
		}
		return nil, errors.New("当前没有正在进行的录制")
	}
	id, name, bs := a.recID, a.recName, a.browser
	a.recID, a.recName = 0, ""
	a.mu.Unlock()
	info := &StopInfo{RecordingID: id, Name: name, Reason: reason, At: time.Now().Format("2006-01-02 15:04:05")}
	if bs != nil {
		if rec := bs.FinishRecording(); rec != nil {
			info.Count, info.Useful = rec.Count, rec.Useful
		}
		if bs.Alive() {
			if cs, err := bs.Cookies(); err == nil {
				a.repo.ReplaceCookies(cs)
			}
			bs.removeOverlays()
			if reason != "browser-closed" {
				go func() {
					time.Sleep(1200 * time.Millisecond) // let the overlay show "已结束"
					bs.Close()
				}()
			}
		}
	}
	a.repo.FinishRecording(id)
	rec, detectErr := a.repo.GetRecording(id)
	if detectErr == nil {
		info.LoginDetection, detectErr = a.options.DetectRecordingLogin(*rec)
	}
	if detectErr != nil {
		log.Printf("录制 #%d 自动识别企业微信登录失败", id)
		info.LoginDetection = &RecordingLoginResult{Action: "error", Message: "自动识别登录失败，可在录制详情页点击「加入登录中心」重试"}
	}
	a.mu.Lock()
	a.lastStop = copyStopInfo(info)
	a.mu.Unlock()
	log.Printf("结束录制 #%d %s：共 %d 个请求，其中 %d 个可能有用（%s）", id, name, info.Count, info.Useful, reason)
	return info, nil
}

func (a *Manager) onBrowserClosed(bs *Session) {
	a.mu.Lock()
	same := a.browser == bs
	recording := a.recID != 0
	a.mu.Unlock()
	if !same {
		return
	}
	if recording {
		a.StopRecording("browser-closed")
	}
	a.mu.Lock()
	if a.browser == bs {
		a.browser = nil
	}
	a.mu.Unlock()
}

// OpenBrowser opens the dedicated browser (for logging in) without recording.
func (a *Manager) OpenBrowser(u string) error {
	a.EvictHeadless(30 * time.Second)
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.browser != nil && a.browser.Alive() && !a.browser.headless {
		if u == "" {
			u = "about:blank"
		}
		return a.browser.call("", "Target.createTarget", map[string]any{"url": u}, nil)
	}
	if a.browser != nil && a.browser.Alive() {
		a.browser.Close()
	}
	bs, err := a.Launch(false)
	if err != nil {
		return err
	}
	a.browser = bs
	if u != "" {
		select {
		case s := <-bs.firstPg:
			bs.call(s, "Page.navigate", map[string]any{"url": u}, nil)
		case <-time.After(10 * time.Second):
		}
	}
	return nil
}

func (a *Manager) CookieSyncLoop() {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-a.options.Quit:
			return
		case <-t.C:
		}
		a.mu.Lock()
		bs := a.browser
		a.mu.Unlock()
		if bs != nil && bs.Alive() && !bs.headless {
			if cs, err := bs.Cookies(); err == nil {
				a.repo.ReplaceCookies(cs)
			}
		}
	}
}

// CookiesFor returns the cookie set to use for a call and where it came from.
func (a *Manager) CookiesFor(u string) ([]Cookie, string) {
	a.mu.Lock()
	bs := a.browser
	a.mu.Unlock()
	if bs != nil && bs.Alive() {
		if cs, err := bs.Cookies(); err == nil {
			if !bs.headless {
				a.repo.ReplaceCookies(cs)
				return cs, "专用浏览器（实时）"
			}
			return cs, "专用浏览器（后台）"
		}
	}
	cs := a.repo.AllCookies()
	if h, _ := execution.CookieHeader(cs, u); h != "" {
		return cs, "本地登录态快照"
	}
	// nothing cached for this site: read the persistent cookies from the profile headlessly
	hcs, err := a.ReadProfileCookies()
	if err != nil {
		if !errors.Is(err, errBrowserBusy) {
			log.Printf("后台读取浏览器登录态失败: %v", err)
		}
		return cs, "无"
	}
	if len(hcs) > 0 {
		a.repo.SaveCookies(hcs)
		return a.repo.AllCookies(), "浏览器配置（后台读取）"
	}
	return cs, "无"
}

var errBrowserBusy = errors.New("浏览器正在使用中")

// readProfileCookies returns all cookies of the dedicated profile, starting it headlessly when
// no browser is open.
func (a *Manager) ReadProfileCookies() ([]Cookie, error) {
	bs, err := a.AcquireBrowser()
	if err != nil {
		return nil, err
	}
	defer a.ReleaseBrowser(bs)
	return bs.Cookies()
}
