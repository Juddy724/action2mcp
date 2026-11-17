package site

import (
	"action2mcp/internal/credential"
	"action2mcp/internal/domain"
	"action2mcp/internal/recording"
	"log"
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var recordedSSOPathRe = regexp.MustCompile(`(?i)(oauth2?|(^|[/._-])sso([/._-]|login|$)|callback|loginandauthorize)`)

var wecomLoginPathRe = regexp.MustCompile(`(?i)(^|/)(wwlogin|qrconnect|oauth2/authorize)(/|$)`)

// cleanLoginURL deliberately keeps only scheme, host and path. OAuth query strings,
// fragments and URL credentials must never become a login configuration or notice.
func cleanLoginURL(raw string) *url.URL {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil
	}
	u.User, u.RawQuery, u.Fragment, u.RawFragment, u.ForceQuery = nil, "", "", "", false
	u.Host = strings.ToLower(u.Host)
	if u.Path == "" {
		u.Path = "/"
	}
	return u
}

func recordedWeComHost(h string) bool {
	switch strings.TrimSuffix(strings.ToLower(h), ".") {
	case "login.work.weixin.qq.com", "open.work.weixin.qq.com", "work.weixin.qq.com":
		return true
	}
	return false
}

func recordedWeComLogin(u *url.URL) bool {
	switch strings.TrimSuffix(strings.ToLower(u.Hostname()), ".") {
	case "login.work.weixin.qq.com":
		return true
	case "open.work.weixin.qq.com":
		return wecomLoginPathRe.MatchString(u.Path)
	case "work.weixin.qq.com":
		p := strings.ToLower(u.Path)
		return p == "/wework_admin" || strings.HasPrefix(p, "/wework_admin/")
	}
	return false
}

func recordedLoginRequest(q recording.Request, u *url.URL) bool {
	if q.Method == "OPTIONS" || q.Method == "HEAD" || recording.IsStaticAssetPath(u.Path) {
		return false
	}
	switch strings.ToLower(q.ResourceType) {
	case "", "document", "xhr", "fetch", "other":
	default:
		return false
	}
	mime := strings.ToLower(q.RespMime)
	return !strings.HasPrefix(mime, "image/") && !strings.HasPrefix(mime, "font/") &&
		!strings.HasPrefix(mime, "audio/") && !strings.HasPrefix(mime, "video/") &&
		!strings.Contains(mime, "javascript") && !strings.HasPrefix(mime, "text/css")
}

// detectWeComLogin is pure: it reads URL/resource metadata only, never headers or
// bodies, and neither changes the recording nor retains OAuth parameters.
func detectWeComLogin(rec recording.Recording, requests []recording.Request) *Site {
	ordered := append([]recording.Request(nil), requests...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Seq < ordered[j].Seq })
	type visit struct {
		u        *url.URL
		document bool
		status   int
	}
	var visits []visit
	var anchors []int
	counts, ssoHosts, businessDocs := map[string]int{}, map[string]bool{}, map[string]bool{}
	for _, q := range ordered {
		u := cleanLoginURL(q.URL)
		if u == nil {
			continue
		}
		counts[credential.Origin(u.String())]++
		if !recordedLoginRequest(q, u) {
			continue
		}
		if recordedWeComLogin(u) {
			anchors = append(anchors, len(visits))
		}
		if recordedSSOPathRe.MatchString(u.Path) {
			ssoHosts[u.Host] = true
		} else if strings.EqualFold(q.ResourceType, "Document") && !recordedWeComHost(u.Hostname()) {
			businessDocs[u.Host] = true
		}
		visits = append(visits, visit{u, strings.EqualFold(q.ResourceType, "Document"), q.Status})
	}
	if len(anchors) == 0 {
		return nil // OAuth-looking callbacks alone are not evidence of WeCom login.
	}
	var fallback *url.URL
	best := 0
	for _, v := range visits {
		if v.document && businessDocs[v.u.Host] && !recordedSSOPathRe.MatchString(v.u.Path) {
			if n := counts[credential.Origin(v.u.String())]; n > best {
				fallback, best = v.u, n
			}
		}
	}
	entry := cleanLoginURL(rec.StartURL)
	if entry == nil || recordedWeComHost(entry.Hostname()) || (ssoHosts[entry.Host] && !businessDocs[entry.Host] && fallback != nil) {
		entry = fallback
	}
	if entry == nil {
		return nil // There is no safe business origin to associate with this login.
	}
	origin := credential.Origin(entry.String())
	hosts := map[string]bool{}
	for _, anchor := range anchors {
		// Limit each login episode to the surrounding business-page navigations.
		lo, hi := 0, len(visits)
		for i := anchor - 1; i >= 0; i-- {
			if visits[i].document && visits[i].u.Host == entry.Host {
				lo = i + 1
				break
			}
		}
		for i := anchor + 1; i < len(visits); i++ {
			if visits[i].document && visits[i].u.Host == entry.Host {
				hi = i
				break
			}
		}
		for _, v := range visits[lo:hi] {
			if v.u.Host == entry.Host || recordedWeComHost(v.u.Hostname()) {
				continue
			}
			if recordedSSOPathRe.MatchString(v.u.Path) || (v.document && v.status >= 300 && v.status < 400) {
				hosts[v.u.Host] = true
			}
		}
	}
	name := strings.TrimSpace(rec.Name)
	if nameURL := cleanLoginURL(name); nameURL != nil {
		name = nameURL.String()
	}
	if name == "" {
		name = entry.Host
	}
	return &Site{Origin: origin, Name: name, Method: MethodSSO, EntryURL: entry.String(),
		SSOHosts: sortedLoginHosts(hosts), Status: "unknown"}
}

func sortedLoginHosts(hosts map[string]bool) string {
	out := make([]string, 0, len(hosts))
	for h := range hosts {
		out = append(out, h)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// mergeWeComSite is also pure. Only SSOHosts may change on an existing SSO site;
// explicit form/manual choices are suggestions and are never replaced.
func mergeWeComSite(detected, existing *Site) (*Site, string) {
	if existing == nil {
		c := *detected
		return &c, "created"
	}
	if existing.Method != MethodSSO {
		return nil, "suggestion"
	}
	c := *existing
	hosts := map[string]bool{}
	for _, raw := range strings.Split(existing.SSOHosts+","+detected.SSOHosts, ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		if u := cleanLoginURL(raw); u != nil && u.Host != detected.Host() {
			hosts[u.Host] = true
		}
	}
	c.SSOHosts = sortedLoginHosts(hosts)
	if c.SSOHosts == existing.SSOHosts {
		return &c, "unchanged"
	}
	return &c, "updated"
}

// RecordingLoginResult intentionally contains no Site or request payload: even an
// existing form configuration must not be copied into status/API responses here.
type RecordingLoginResult = domain.RecordingLoginResult

func (a *RecordingDetector) Detect(rec recording.Recording) (*RecordingLoginResult, error) {
	requests, err := a.repository.ListRequests(rec.ID)
	if err != nil {
		return nil, err
	}
	detected := detectWeComLogin(rec, requests)
	if detected == nil {
		return &RecordingLoginResult{Action: "none", Message: "未检测到企业微信登录，请确认录制中包含扫码登录过程"}, nil
	}
	// Share the site writer lock with manual edits, so detection cannot overwrite
	// a form/manual configuration saved concurrently from the console.
	var action string
	site, err := a.repository.UpdateSite(detected.Origin, func(existing *Site) (*Site, bool, error) {
		merged, result := mergeWeComSite(detected, existing)
		action = result
		if action == "suggestion" {
			merged = existing
		}
		return merged, action == "created" || action == "updated", nil
	})
	if err != nil {
		return nil, err
	}
	res := &RecordingLoginResult{Detected: true, Action: action, SiteID: site.ID, Origin: detected.Origin}
	switch action {
	case "created":
		res.Message = "检测到企业微信登录，已自动加入登录中心"
		log.Printf("录制 #%d 检测到企业微信扫码登录，已在登录中心添加网站 %s", rec.ID, detected.Host())
	case "updated":
		res.Message = "检测到企业微信登录，已合并登录中心的单点登录地址"
		log.Printf("录制 #%d 检测到企业微信扫码登录，已在登录中心更新网站 %s 的单点登录地址", rec.ID, detected.Host())
	case "unchanged":
		res.Message = "检测到企业微信登录，登录中心已包含该网站"
		log.Printf("录制 #%d 检测到企业微信扫码登录，登录中心已有网站 %s", rec.ID, detected.Host())
	case "suggestion":
		res.Message = "检测到企业微信登录；该网站已有账号密码或手动登录配置，建议在登录中心检查登录方式（保留现有配置）"
		log.Printf("录制 #%d 检测到企业微信扫码登录，网站 %s 已有其他登录方式，建议在登录中心检查", rec.ID, detected.Host())
	}
	return res, nil
}

// RecordingRepository shares the synchronized site writer with manual updates.
type RecordingRepository interface {
	ListRequests(int64) ([]recording.Request, error)
	UpdateSite(string, func(*Site) (*Site, bool, error)) (*Site, error)
}
type RecordingDetector struct{ repository RecordingRepository }

func NewRecordingDetector(r RecordingRepository) *RecordingDetector {
	return &RecordingDetector{repository: r}
}
