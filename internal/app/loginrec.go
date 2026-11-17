package app

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var (
	passKeyRe = regexp.MustCompile(`(?i)(passw|passwd|pwd|^pass$|^pin$|^passcode$|password|^secret$|mima)`)
	userKeyRe = regexp.MustCompile(`(?i)^(user|username|user_name|user-name|userid|user_id|usercode|user_code|login|loginname|login_name|loginid|login_id|logincode|account|account_name|accountname|acct|email|mail|mobile|phone|tel|j_username|uid|name|staffno|empno|workno|ldap|domain_account)$`)
	formKVRe  = regexp.MustCompile(`(^|&)([^=&]+)=([^&]*)`)
	jsonKVRe  = regexp.MustCompile(`"([^"\\]{1,64})"\s*:\s*"((?:[^"\\]|\\.)*)"`)
)

func lastKey(p string) string {
	if i := strings.LastIndexAny(p, ".]"); i >= 0 && i < len(p)-1 {
		return p[i+1:]
	}
	return strings.TrimRight(idxRe.ReplaceAllString(p, "$1"), "]")
}

func isPassKey(k string) bool { return passKeyRe.MatchString(lastKey(k)) }

// MaskSecrets hides password-like values in a request body / URL query, keeping the format.
func MaskSecrets(s string) string {
	if s == "" {
		return s
	}
	t := strings.TrimSpace(s)
	if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		return jsonKVRe.ReplaceAllStringFunc(s, func(m string) string {
			sm := jsonKVRe.FindStringSubmatch(m)
			if isPassKey(sm[1]) && sm[2] != "" {
				return `"` + sm[1] + `":"` + secretMask + `"`
			}
			return m
		})
	}
	return formKVRe.ReplaceAllStringFunc(s, func(m string) string {
		sm := formKVRe.FindStringSubmatch(m)
		k, _ := url.QueryUnescape(sm[2])
		if isPassKey(k) && sm[3] != "" {
			return sm[1] + sm[2] + "=" + secretMask
		}
		return m
	})
}

func maskURL(u string) string {
	i := strings.Index(u, "?")
	if i < 0 {
		return u
	}
	return u[:i+1] + MaskSecrets(u[i+1:])
}

type loginFields struct {
	userKey, userVal string
	passKey, passVal string
	csrfKey          string
	isJSON           bool
}

// parseLogin finds username / password / csrf fields in a recorded request body.
func parseLogin(q *ReqRecord) *loginFields {
	if q.Method == "GET" || q.Method == "HEAD" || strings.TrimSpace(q.ReqBody) == "" {
		return nil
	}
	lf := &loginFields{}
	body := strings.TrimSpace(q.ReqBody)
	if strings.HasPrefix(body, "{") {
		var j map[string]any
		if json.Unmarshal([]byte(body), &j) != nil {
			return nil
		}
		lf.isJSON = true
		var walk func(m map[string]any)
		walk = func(m map[string]any) {
			for k, v := range m {
				switch x := v.(type) {
				case string:
					if lf.passKey == "" && isPassKey(k) && x != "" && x != secretMask {
						lf.passKey, lf.passVal = k, x
					} else if lf.userKey == "" && userKeyRe.MatchString(k) && x != "" {
						lf.userKey, lf.userVal = k, x
					} else if lf.csrfKey == "" && csrfNameRe.MatchString(k) {
						lf.csrfKey = k
					}
				case map[string]any:
					walk(x)
				}
			}
		}
		walk(j)
	} else {
		vals, err := url.ParseQuery(body)
		if err != nil {
			return nil
		}
		for _, m := range formKVRe.FindAllStringSubmatch(body, -1) {
			k, _ := url.QueryUnescape(m[2])
			v := vals.Get(k)
			if lf.passKey == "" && isPassKey(k) && v != "" && v != secretMask {
				lf.passKey, lf.passVal = k, v
			} else if lf.userKey == "" && userKeyRe.MatchString(k) && v != "" {
				lf.userKey, lf.userVal = k, v
			} else if lf.csrfKey == "" && csrfNameRe.MatchString(k) {
				lf.csrfKey = k
			}
		}
	}
	if lf.passKey == "" {
		return nil
	}
	return lf
}

func isLoginRequest(q *ReqRecord) bool { return parseLogin(q) != nil }

var nonWordRe = regexp.MustCompile(`[^A-Za-z0-9]+`)

// hostKey turns a URL into a short vault name prefix, e.g. zentao.dc.x.com -> zentao.
func hostKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "site"
	}
	h := u.Hostname()
	if net.ParseIP(h) != nil || h == "localhost" {
		return strings.Trim(nonWordRe.ReplaceAllString(u.Host, "_"), "_")
	}
	parts := strings.Split(strings.ToLower(h), ".")
	for _, p := range parts {
		if p != "www" && p != "" {
			return strings.Trim(nonWordRe.ReplaceAllString(p, "_"), "_")
		}
	}
	return "site"
}

// vaultNameFor picks name (or name_2, ...) that is free or already bound to this site.
func (a *App) vaultNameFor(base, origin string) string {
	n := base
	for i := 2; i < 50; i++ {
		found := false
		for _, it := range a.vault.List() {
			if it.Name == n {
				found = true
				if it.Site == "" || sameSite(it.Site, origin) {
					return n
				}
			}
		}
		if !found {
			return n
		}
		n = fmt.Sprintf("%s_%d", base, i)
	}
	return n
}

type SaveLoginResult struct {
	Site         *Site  `json:"site"`
	UsernameName string `json:"username_name"`
	PasswordName string `json:"password_name"`
	CSRFField    string `json:"csrf_field"`
	LoginPage    string `json:"login_page"`
}

// SaveLogin stores the credentials of a recorded login request in the vault and turns the request
// into the site's 账号密码 login (replayed with {{cfg.*}} / {{secret.*}}).
func (a *App) SaveLogin(q *ReqRecord, userName, passName string) (*SaveLoginResult, error) {
	lf := parseLogin(q)
	if lf == nil {
		return nil, errors.New("这个请求里没有找到密码字段（可能已经保存过了），不像是登录请求")
	}
	origin := originOf(q.URL)
	key := hostKey(q.URL)
	// re-recording a site's login: keep the vault names the site (and its tools) already use
	if prev := a.store.SiteByOrigin(origin); prev != nil {
		if u := strings.TrimPrefix(prev.Form.UsernameRef, "cfg."); userName == "" && u != "" && vaultNameRe.MatchString(u) {
			userName = u
		}
		if p := strings.TrimPrefix(prev.Form.PasswordRef, "secret."); passName == "" && p != "" && vaultNameRe.MatchString(p) {
			passName = p
		}
	}
	if userName == "" {
		userName = a.vaultNameFor(key+"_username", origin)
	}
	if passName == "" {
		passName = a.vaultNameFor(key+"_password", origin)
	}
	if !vaultNameRe.MatchString(userName) || !vaultNameRe.MatchString(passName) {
		return nil, errors.New("配置名只能包含英文字母、数字和下划线")
	}
	if lf.userKey != "" {
		if err := a.vault.Upsert(userName, "plain", lf.userVal, origin, "登录用户名（录制时保存）"); err != nil {
			return nil, err
		}
	}
	if err := a.vault.Upsert(passName, "secret", lf.passVal, origin, "登录密码（录制时保存）"); err != nil {
		return nil, err
	}
	// template body
	body := q.ReqBody
	if lf.isJSON {
		body = jsonKVRe.ReplaceAllStringFunc(body, func(m string) string {
			sm := jsonKVRe.FindStringSubmatch(m)
			switch {
			case sm[1] == lf.passKey:
				return `"` + sm[1] + `":"{{secret.` + passName + `}}"`
			case lf.userKey != "" && sm[1] == lf.userKey:
				return `"` + sm[1] + `":"{{cfg.` + userName + `}}"`
			case lf.csrfKey != "" && sm[1] == lf.csrfKey:
				return `"` + sm[1] + `":"{{csrf}}"`
			}
			return m
		})
	} else {
		body = formKVRe.ReplaceAllStringFunc(body, func(m string) string {
			sm := formKVRe.FindStringSubmatch(m)
			k, _ := url.QueryUnescape(sm[2])
			switch {
			case k == lf.passKey:
				return sm[1] + sm[2] + "={{secret." + passName + "}}"
			case lf.userKey != "" && k == lf.userKey:
				return sm[1] + sm[2] + "={{cfg." + userName + "}}"
			case lf.csrfKey != "" && k == lf.csrfKey:
				return sm[1] + sm[2] + "={{csrf}}"
			}
			return m
		})
	}
	headers, creds := SanitizeHeaders(q.ReqHeaders)
	for k := range headers {
		lk := strings.ToLower(k)
		if lk == "referer" || lk == "origin" {
			delete(headers, k)
		}
	}
	// the page the login form lives on (for a fresh CSRF token)
	page := headerGet(q.ReqHeaders, "Referer")
	if page == "" || !sameSite(originOf(page), origin) {
		page = ""
		if reqs, err := a.store.ListRequests(q.RecordingID); err == nil {
			for _, r := range reqs {
				if r.Seq < q.Seq && r.ResourceType == "Document" && r.Method == "GET" && sameSite(originOf(r.URL), origin) {
					page = r.URL
				}
			}
		}
	}
	site := a.store.EnsureSite(q.URL)
	if site == nil {
		return nil, errors.New("登录请求的地址不正确")
	}
	site.Method = MethodForm
	site.Form.Mode = "replay"
	site.Form.Request = &LoginRequest{Method: q.Method, URL: maskURL(q.URL), Headers: headers, Body: body, CredHeaders: creds}
	if lf.userKey != "" {
		site.Form.UsernameRef = "cfg." + userName
	}
	site.Form.PasswordRef = "secret." + passName
	site.Form.CSRFField = lf.csrfKey
	if page != "" {
		site.Form.LoginURL = page
	}
	if err := a.store.SaveSite(site); err != nil {
		return nil, err
	}
	// the recorded password must not stay in the database
	a.store.RedactRequestBody(q.ID, MaskSecrets(q.ReqBody))
	a.ResetSiteFailures()
	return &SaveLoginResult{Site: site, UsernameName: userName, PasswordName: passName, CSRFField: lf.csrfKey, LoginPage: page}, nil
}

// ---------- tool builder: secrets as {{secret.X}} instead of AI params ----------

// annotateCandidates marks password-like / vault-matching fields and masks their examples.
func (a *App) annotateCandidates(q *ReqRecord, cs []Candidate) []Candidate {
	origin := originOf(q.URL)
	for i := range cs {
		c := &cs[i]
		c.raw = c.Example
		if name := a.vault.FindByValue(c.Example); name != "" && len(c.Example) >= 3 && a.vault.TypeOf(name) == "secret" {
			c.Secret, c.Ref, c.RefExists = true, name, true
		} else if isPassKey(c.Path) && c.Example != "" {
			c.Secret = true
			c.Ref = a.vaultNameFor(hostKey(q.URL)+"_password", origin)
			_, c.RefExists = a.vault.Lookup(c.Ref)
		}
		if c.Secret {
			c.Example = secretMask
			c.Suggest = true
		}
	}
	return cs
}

// prepareDraft makes sure secret fields never become plain template text or AI-visible params.
func (a *App) prepareDraft(q *ReqRecord, chosen []Candidate) []Candidate {
	all := a.annotateCandidates(q, SuggestParams(q))
	byKey := map[string]Candidate{}
	for _, c := range all {
		byKey[c.Loc+"|"+c.Path] = c
	}
	seen := map[string]bool{}
	out := []Candidate{}
	for _, c := range chosen {
		orig, ok := byKey[c.Loc+"|"+c.Path]
		if !ok {
			continue
		}
		seen[c.Loc+"|"+c.Path] = true
		c.Secret = orig.Secret
		c.raw = orig.raw
		if c.Secret {
			c.Example = ""
		} else {
			c.Ref = ""
		}
		out = append(out, c)
	}
	// unselected secret fields are still taken from 配置管理
	for _, c := range all {
		if c.Secret && !seen[c.Loc+"|"+c.Path] {
			c.Example = ""
			out = append(out, c)
		}
	}
	for i, c := range out {
		if c.Ref == "" {
			continue
		}
		if !vaultNameRe.MatchString(c.Ref) {
			out[i].Ref = a.vaultNameFor(hostKey(q.URL)+"_password", originOf(q.URL))
			c.Ref = out[i].Ref
		}
		if _, ok := a.vault.Lookup(c.Ref); !ok && c.raw != "" && c.raw != secretMask {
			a.vault.Upsert(c.Ref, "secret", c.raw, originOf(q.URL), "录制时自动保存")
		}
	}
	return out
}

// scrubRequest prepares a recorded request for the console: passwords masked, secrets scrubbed.
func (a *App) scrubRequest(q *ReqRecord) *ReqRecord {
	c := *q
	c.IsLogin = isLoginRequest(q)
	c.URL = a.vault.Scrub(maskURL(q.URL))
	c.ReqBody = a.vault.Scrub(MaskSecrets(q.ReqBody))
	c.RespBody = a.vault.Scrub(q.RespBody)
	if q.ReqHeaders != nil {
		c.ReqHeaders = map[string]string{}
		for k, v := range q.ReqHeaders {
			c.ReqHeaders[k] = a.vault.Scrub(v)
		}
	}
	return &c
}
