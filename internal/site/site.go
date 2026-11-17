package site

import (
	"action2mcp/internal/credential"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ---------- 登录中心：每个网站一份登录配置 ----------

const (
	MethodSSO    = "wecom_sso" // 企业微信 / 单点登录：打开入口地址，自动跳转完成登录
	MethodForm   = "form"      // 账号密码（来自配置管理）
	MethodManual = "manual"    // 只弹出窗口，由用户自己登录
)

type Detect struct {
	Statuses     []int    `json:"statuses"`      // 视为未登录的状态码，默认 401、403
	URLPatterns  []string `json:"url_patterns"`  // 被重定向到这些地址（正则）视为未登录
	BodyPatterns []string `json:"body_patterns"` // 响应内容匹配这些正则视为未登录
	NoDefaults   bool     `json:"no_defaults"`   // 关闭内置识别规则（登录页 HTML、“未登录”提示等）
}

type LoginRequest struct {
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	CredHeaders []string          `json:"cred_headers"`
}

type FormLogin struct {
	Mode           string        `json:"mode"` // replay（重放录制到的登录请求）| fill（在浏览器里自动填表）
	UsernameRef    string        `json:"username_ref"`
	PasswordRef    string        `json:"password_ref"`
	LoginURL       string        `json:"login_url"` // 登录页面地址（填表 / 取 CSRF 用）
	UserSelector   string        `json:"user_selector"`
	PassSelector   string        `json:"pass_selector"`
	SubmitSelector string        `json:"submit_selector"`
	CSRFField      string        `json:"csrf_field"` // 登录页里的 CSRF 字段名，自动填进 {{csrf}}
	Request        *LoginRequest `json:"request,omitempty"`
}

type Site struct {
	ID           int64     `json:"id"`
	Origin       string    `json:"origin"`
	Name         string    `json:"name"`
	Method       string    `json:"method"`
	EntryURL     string    `json:"entry_url"`   // 登录入口
	CheckURL     string    `json:"check_url"`   // 检测登录状态用的地址（可选，GET）
	SuccessURL   string    `json:"success_url"` // 浏览器到达匹配此正则的地址即视为登录成功（可选）
	SSOHosts     string    `json:"sso_hosts"`   // 额外的单点登录服务地址（逗号分隔，如 sso.company.com）
	Detect       Detect    `json:"detect"`
	Form         FormLogin `json:"form"`
	KeepaliveMin int       `json:"keepalive_min"` // 定时保活间隔（分钟），0 = 关闭
	Status       string    `json:"status"`        // unknown | valid | invalid
	LastLoginAt  string    `json:"last_login_at"`
	LastCheckAt  string    `json:"last_check_at"`
	LastError    string    `json:"last_error"`
	LoginCount   int       `json:"login_count"`
	CreatedAt    string    `json:"created_at"`
	UpdatedAt    string    `json:"updated_at"`
}

func (s *Site) Host() string {
	u, _ := url.Parse(s.Origin)
	if u == nil {
		return ""
	}
	return strings.ToLower(u.Host)
}

func (s *Site) Entry() string {
	if s.EntryURL != "" {
		return s.EntryURL
	}
	if s.Method == MethodForm && s.Form.LoginURL != "" {
		return s.Form.LoginURL
	}
	return s.Origin + "/"
}

func (s *Site) DisplayName() string {
	if s.Name != "" {
		return s.Name
	}
	return s.Host()
}

// ---------- store ----------

type Config struct {
	Name         string    `json:"name"`
	Method       string    `json:"method"`
	EntryURL     string    `json:"entry_url"`
	CheckURL     string    `json:"check_url"`
	SuccessURL   string    `json:"success_url"`
	SSOHosts     string    `json:"sso_hosts"`
	Detect       Detect    `json:"detect"`
	Form         FormLogin `json:"form"`
	KeepaliveMin int       `json:"keepalive_min"`
}

func (s *Site) SnapshotConfig() Config {
	return Config{s.Name, s.Method, s.EntryURL, s.CheckURL, s.SuccessURL, s.SSOHosts, s.Detect, s.Form, s.KeepaliveMin}
}

func (s *Site) ApplyConfig(c Config) {
	s.Name, s.Method, s.EntryURL, s.CheckURL, s.SuccessURL, s.SSOHosts, s.Detect, s.Form, s.KeepaliveMin =
		c.Name, c.Method, c.EntryURL, c.CheckURL, c.SuccessURL, c.SSOHosts, c.Detect, c.Form, c.KeepaliveMin
}

const siteCols = `id,origin,config,status,last_login_at,last_check_at,last_error,login_count,created_at,updated_at`

func scanSite(sc interface{ Scan(...any) error }) (*Site, error) {
	var s Site
	var cfg string
	if err := sc.Scan(&s.ID, &s.Origin, &cfg, &s.Status, &s.LastLoginAt, &s.LastCheckAt, &s.LastError, &s.LoginCount, &s.CreatedAt, &s.UpdatedAt); err != nil {
		return nil, err
	}
	var c Config
	json.Unmarshal([]byte(cfg), &c)
	s.ApplyConfig(c)
	if s.Method == "" {
		s.Method = MethodSSO
	}
	return &s, nil
}

func (st *Repository) ListSites() []*Site {
	rows, err := st.db.Query(`SELECT ` + siteCols + ` FROM sites ORDER BY origin`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	out := []*Site{}
	for rows.Next() {
		if s, err := scanSite(rows); err == nil {
			out = append(out, s)
		}
	}
	return out
}

func (st *Repository) GetSite(id int64) (*Site, error) {
	return scanSite(st.db.QueryRow(`SELECT `+siteCols+` FROM sites WHERE id=?`, id))
}

func (st *Repository) SiteByOrigin(origin string) *Site {
	origin = credential.NormalizeOrigin(origin)
	s, err := scanSite(st.db.QueryRow(`SELECT `+siteCols+` FROM sites WHERE origin=?`, origin))
	if err == nil {
		return s
	}
	// same host, other scheme
	for _, x := range st.ListSites() {
		if credential.SameSite(x.Origin, origin) {
			return x
		}
	}
	return nil
}

func (st *Repository) SaveSite(s *Site) error {
	st.siteMu.Lock()
	defer st.siteMu.Unlock()
	return st.saveSite(s)
}

func (st *Repository) saveSite(s *Site) error {
	s.Origin = credential.NormalizeOrigin(s.Origin)
	if s.Origin == "" {
		return errors.New("网站地址不能为空")
	}
	if err := ValidateHTTPOrigin(s.Origin, "网站地址"); err != nil {
		return err
	}
	if err := ValidateHTTPLoginURL(s.EntryURL, "登录入口"); err != nil {
		return err
	}
	if err := ValidateHTTPLoginURL(s.CheckURL, "检测地址"); err != nil {
		return err
	}
	if err := ValidateHTTPLoginURL(s.Form.LoginURL, "登录页"); err != nil {
		return err
	}
	switch s.Method {
	case MethodSSO, MethodForm, MethodManual:
	default:
		s.Method = MethodSSO
	}
	for _, p := range append(append([]string{s.SuccessURL}, s.Detect.URLPatterns...), s.Detect.BodyPatterns...) {
		if p == "" {
			continue
		}
		if _, err := regexp.Compile(p); err != nil {
			return errors.New("正则表达式格式不正确: " + p)
		}
	}
	if s.Status == "" {
		s.Status = "unknown"
	}
	ts := siteNow()
	cfg := siteJSON(s.SnapshotConfig())
	if s.ID == 0 {
		s.CreatedAt = ts
		r, err := st.db.Exec(`INSERT INTO sites(origin,config,status,last_login_at,last_check_at,last_error,login_count,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`,
			s.Origin, cfg, s.Status, s.LastLoginAt, s.LastCheckAt, s.LastError, s.LoginCount, ts, ts)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return errors.New("这个网站已经有登录配置了")
			}
			return err
		}
		s.ID, _ = r.LastInsertId()
	} else {
		if _, err := st.db.Exec(`UPDATE sites SET origin=?,config=?,updated_at=? WHERE id=?`, s.Origin, cfg, ts, s.ID); err != nil {
			return err
		}
	}
	s.UpdatedAt = ts
	return nil
}

func (st *Repository) SetSiteStatus(id int64, status, lastErr string, loggedIn bool) {
	ts := siteNow()
	if loggedIn {
		st.db.Exec(`UPDATE sites SET status=?,last_error='',last_login_at=?,last_check_at=?,login_count=login_count+1 WHERE id=?`, status, ts, ts, id)
		return
	}
	st.db.Exec(`UPDATE sites SET status=?,last_error=?,last_check_at=? WHERE id=?`, status, lastErr, ts, id)
}

// SetSiteError records a message without changing the current validity status
// (used when the user cancels a wait or closes the login window).
func (st *Repository) SetSiteError(id int64, lastErr string) {
	st.db.Exec(`UPDATE sites SET last_error=?,last_check_at=? WHERE id=?`, lastErr, siteNow(), id)
}

func (st *Repository) DeleteSite(id int64) {
	st.siteMu.Lock()
	defer st.siteMu.Unlock()
	st.db.Exec(`DELETE FROM sites WHERE id=?`, id)
}

// requireHTTPOrigin checks that origin is already an http(s) site origin
// (ws/wss must have been mapped by normalizeOrigin / credOrigin first).
func ValidateHTTPOrigin(origin, field string) error {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New(field + "必须是 http:// 或 https:// 地址（WebSocket 的 wss:// 会按 https:// 保存，ws:// 按 http:// 保存）")
	}
	return nil
}

// requireHTTPLoginURL validates a user-editable login-related URL. Empty is allowed.
// Unlike site origin, ws/wss is not silently remapped: the login page itself must be http(s).
func ValidateHTTPLoginURL(raw, field string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New(field + "格式不正确，请填写 http:// 或 https:// 地址")
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return nil
	case "ws", "wss":
		return errors.New(field + "必须是 http:// 或 https:// 地址，不能使用 " + u.Scheme + "://")
	default:
		return errors.New(field + "必须是 http:// 或 https:// 地址")
	}
}

// mapWSToHTTPURL rewrites ws:// → http:// and wss:// → https://, leaving other URLs unchanged.
func MapWSToHTTPURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	switch strings.ToLower(u.Scheme) {
	case "wss":
		u.Scheme = "https"
	case "ws":
		u.Scheme = "http"
	default:
		return raw
	}
	return u.String()
}

func remapSiteLoginURLs(s *Site) bool {
	changed := false
	if v := MapWSToHTTPURL(s.EntryURL); v != s.EntryURL {
		s.EntryURL, changed = v, true
	}
	if v := MapWSToHTTPURL(s.CheckURL); v != s.CheckURL {
		s.CheckURL, changed = v, true
	}
	if v := MapWSToHTTPURL(s.Form.LoginURL); v != s.Form.LoginURL {
		s.Form.LoginURL, changed = v, true
	}
	return changed
}

// migrateWSSiteOrigins remaps login-center origins stored as ws:// or wss://
// to the matching http:// or https:// origin. Idempotent.
func (st *Repository) MigrateWSSiteOrigins() error {
	st.siteMu.Lock()
	defer st.siteMu.Unlock()
	for _, s := range st.ListSites() {
		mapped := credential.Origin(s.Origin)
		urlsChanged := remapSiteLoginURLs(s)
		if mapped == "" || mapped == s.Origin {
			if urlsChanged {
				if err := st.saveSite(s); err != nil {
					return err
				}
			}
			continue
		}
		other, err := scanSite(st.db.QueryRow(`SELECT `+siteCols+` FROM sites WHERE origin=?`, mapped))
		if err == nil && other != nil && other.ID != s.ID {
			// Keep the already-correct http(s) row; drop the ws/wss duplicate.
			if _, err := st.db.Exec(`DELETE FROM sites WHERE id=?`, s.ID); err != nil {
				return err
			}
			continue
		}
		s.Origin = mapped
		if err := st.saveSite(s); err != nil {
			return err
		}
	}
	return nil
}

// EnsureSite returns the site for a URL, creating a default entry for a new host.
// WebSocket addresses are stored under their http(s) origin (wss→https, ws→http).
func (st *Repository) EnsureSite(rawURL string) *Site {
	o := credential.Origin(rawURL)
	if o == "" {
		return nil
	}
	if s := st.SiteByOrigin(o); s != nil {
		return s
	}
	s := &Site{Origin: o, Method: MethodSSO, Status: "unknown"}
	if err := st.SaveSite(s); err != nil {
		return st.SiteByOrigin(o)
	}
	return s
}

// ---------- not-logged-in detection ----------

var (
	defaultLoginURLRe = regexp.MustCompile(`(?i)(login|signin|sign-in|sign_in|logon|passport|/sso/|/sso\?|/cas/|oauth|authorize|qrconnect|work\.weixin\.qq\.com|open\.weixin\.qq\.com)`)
	passwordInputRe   = regexp.MustCompile(`(?is)<input[^>]*type\s*=\s*["']?password`)
	scriptLoginRe     = regexp.MustCompile(`(?i)(location(\.href)?\s*=|location\.(replace|assign)\s*\()\s*['"][^'"]*(login|signin|passport|sso|oauth)`)
	shortNotLoginRe   = regexp.MustCompile(`(?i)(未登录|请先登录|请登录|重新登录|登录已过期|登录超时|登录失效|登录状态已失效|会话已过期|会话超时|session\s*(has\s*)?(expired|timeout)|not\s*logged\s*in|login\s*required|need[_\s-]?login|NOT_LOGIN|NOLOGIN|unauthori[sz]ed)`)
	wecomHostRe       = regexp.MustCompile(`(?i)(work\.weixin\.qq\.com|open\.weixin\.qq\.com|weixin\.qq\.com|wework)`)
)

func (s *Site) statuses() []int {
	if len(s.Detect.Statuses) > 0 {
		return s.Detect.Statuses
	}
	return []int{401, 403}
}

func (s *Site) IsLoginURL(u string) bool {
	for _, p := range s.Detect.URLPatterns {
		if p != "" {
			if re, err := regexp.Compile(p); err == nil && re.MatchString(u) {
				return true
			}
		}
	}
	if s.IsSSOHost(HostOf(u)) {
		return true
	}
	if s.Detect.NoDefaults {
		return false
	}
	pu, err := url.Parse(u)
	if err != nil {
		return false
	}
	return defaultLoginURLRe.MatchString(pu.Path + "?" + pu.RawQuery + "#" + pu.Fragment)
}

func HostOf(u string) string {
	pu, err := url.Parse(u)
	if err != nil {
		return ""
	}
	return strings.ToLower(pu.Host)
}

func (s *Site) ssoHosts() []string {
	out := []string{}
	for _, h := range strings.Split(s.SSOHosts, ",") {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			continue
		}
		if strings.Contains(h, "://") {
			h = HostOf(h)
		}
		out = append(out, h)
	}
	return out
}

func (s *Site) IsSSOHost(h string) bool {
	if h == "" || strings.EqualFold(h, s.Host()) {
		return false
	}
	for _, x := range s.ssoHosts() {
		if h == x || strings.HasSuffix(h, "."+x) {
			return true
		}
	}
	return wecomHostRe.MatchString(h)
}

func (s *Site) IsWeComHost(h string) bool {
	if wecomHostRe.MatchString(h) {
		return true
	}
	return s.Method == MethodSSO && s.IsSSOHost(h)
}

// NotLoggedIn decides whether a call result means the session is gone. hops are redirect targets.
func (s *Site) NotLoggedIn(status int, body, ctype string, hops []string, toolURL string) (bool, string) {
	for _, c := range s.statuses() {
		if status == c {
			return true, "接口返回 HTTP " + itoa(status)
		}
	}
	toolIsLogin := s.IsLoginURL(toolURL)
	if !toolIsLogin {
		for _, h := range hops {
			if s.IsLoginURL(h) {
				return true, "接口被重定向到登录页"
			}
		}
	}
	for _, p := range s.Detect.BodyPatterns {
		if p == "" {
			continue
		}
		if re, err := regexp.Compile(p); err == nil && re.MatchString(body) {
			return true, "响应内容匹配了未登录规则"
		}
	}
	if s.Detect.NoDefaults || toolIsLogin {
		return false, ""
	}
	isHTML := strings.Contains(strings.ToLower(ctype), "html") || strings.HasPrefix(strings.TrimSpace(body), "<")
	if isHTML && passwordInputRe.MatchString(body) {
		return true, "接口返回了登录页面"
	}
	if len(body) < 8192 && scriptLoginRe.MatchString(body) {
		return true, "接口返回了跳转到登录页的脚本"
	}
	if len(body) < 1500 && shortNotLoginRe.MatchString(body) {
		return true, "接口返回了“未登录”提示"
	}
	return false, ""
}

func itoa(n int) string { return strconv.Itoa(n) }

// SiteRepository owns the writer lock used by manual edits and automatic detection.
type Repository struct {
	db     *sql.DB
	siteMu sync.Mutex
}

func NewRepository(db *sql.DB) *Repository { return &Repository{db: db} }

func siteNow() string { return time.Now().Format("2006-01-02 15:04:05") }

func siteJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

// UpdateSite holds the writer lock across lookup, decision and optional save.
// The change callback must not recursively call a writer on this repository.
func (st *Repository) UpdateSite(origin string, change func(*Site) (*Site, bool, error)) (*Site, error) {
	st.siteMu.Lock()
	defer st.siteMu.Unlock()
	updated, save, err := change(st.SiteByOrigin(origin))
	if err != nil {
		return nil, err
	}
	if save {
		if err := st.saveSite(updated); err != nil {
			return nil, err
		}
	}
	return updated, nil
}

func ContainsPasswordInput(body string) bool { return passwordInputRe.MatchString(body) }
