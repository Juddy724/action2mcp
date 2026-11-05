package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------- credential / header filtering ----------

var credHeaderRe = regexp.MustCompile(`(?i)^(cookie|authorization|proxy-authorization|.*csrf.*|.*xsrf.*|.*token.*|.*auth.*|.*session.*|x-api-key|api-key|apikey|x-sign.*|signature)$`)

// headers that must never be replayed verbatim
var dropHeaders = map[string]bool{"host": true, "content-length": true, "connection": true, "accept-encoding": true, "keep-alive": true,
	"transfer-encoding": true, "upgrade": true, "te": true, "trailer": true, "proxy-connection": true, "priority": true, "if-none-match": true, "if-modified-since": true}

func IsCredHeader(name string) bool {
	n := strings.ToLower(name)
	if n == "x-requested-with" {
		return false
	}
	return credHeaderRe.MatchString(n)
}

// SanitizeHeaders splits recorded headers into replayable headers and credential header names.
func SanitizeHeaders(h map[string]string) (map[string]string, []string) {
	out := map[string]string{}
	var creds []string
	for k, v := range h {
		lk := strings.ToLower(k)
		if strings.HasPrefix(k, ":") || dropHeaders[lk] || strings.HasPrefix(lk, "sec-") && lk != "sec-ch-ua" {
			continue
		}
		if IsCredHeader(k) {
			creds = append(creds, lk)
			continue
		}
		out[k] = v
	}
	sort.Strings(creds)
	return out, creds
}

// ---------- parameter suggestions ----------

// optionalParam: pagination/sorting fields default to the recorded value instead of being required.
var optionalParam = regexp.MustCompile(`(?i)^(page|pageno|pagenum|page_no|page_num|pageindex|current|pagesize|page_size|size|limit|offset|rows|per_page|perpage|sort|sortby|sort_by|order|orderby|order_by)$`)

type Candidate struct {
	Loc     string `json:"loc"`  // query | body | form
	Path    string `json:"path"` // dotted path for JSON body, key for query/form
	Name    string `json:"name"`
	Type    string `json:"type"`
	Example string `json:"example"`
	Suggest bool   `json:"suggest"`
	// Secret: looks like a password / matches a saved secret. Ref: use {{secret.Ref}} from 配置管理
	// instead of exposing it as an AI parameter.
	Secret    bool   `json:"secret,omitempty"`
	Ref       string `json:"ref,omitempty"`
	RefExists bool   `json:"ref_exists,omitempty"`
	raw       string
}

var noisyParam = regexp.MustCompile(`(?i)^(_|t|ts|timestamp|_t|nonce|rand|random|callback|v|ver|version|sign|signature|r)$`)

func paramName(p string) string {
	parts := strings.Split(p, ".")
	n := parts[len(parts)-1]
	n = regexp.MustCompile(`\[\d+\]`).ReplaceAllString(n, "")
	n = regexp.MustCompile(`[^A-Za-z0-9_]`).ReplaceAllString(n, "_")
	if n == "" {
		n = "param"
	}
	return n
}

func jsonType(v any) string {
	switch v.(type) {
	case float64:
		return "number"
	case bool:
		return "boolean"
	default:
		return "string"
	}
}

func SuggestParams(q *ReqRecord) []Candidate {
	out := []Candidate{}
	if u, err := url.Parse(q.URL); err == nil {
		for _, kv := range strings.Split(u.RawQuery, "&") {
			if kv == "" {
				continue
			}
			k, v, _ := strings.Cut(kv, "=")
			k, _ = url.QueryUnescape(k)
			v, _ = url.QueryUnescape(v)
			out = append(out, Candidate{Loc: "query", Path: k, Name: paramName(k), Type: "string", Example: v, Suggest: !noisyParam.MatchString(k)})
		}
	}
	body := strings.TrimSpace(q.ReqBody)
	if body == "" {
		return out
	}
	var j any
	if err := json.Unmarshal([]byte(body), &j); err == nil {
		var walk func(prefix string, v any)
		walk = func(prefix string, v any) {
			switch x := v.(type) {
			case map[string]any:
				keys := make([]string, 0, len(x))
				for k := range x {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					p := k
					if prefix != "" {
						p = prefix + "." + k
					}
					walk(p, x[k])
				}
			case []any:
				for i, e := range x {
					if i > 4 {
						break
					}
					walk(fmt.Sprintf("%s[%d]", prefix, i), e)
				}
			case nil:
				out = append(out, Candidate{Loc: "body", Path: prefix, Name: paramName(prefix), Type: "string", Example: "null", Suggest: false})
			default:
				ex := fmt.Sprint(x)
				if f, ok := x.(float64); ok {
					ex = strconv.FormatFloat(f, 'f', -1, 64)
				}
				out = append(out, Candidate{Loc: "body", Path: prefix, Name: paramName(prefix), Type: jsonType(x), Example: ex, Suggest: !noisyParam.MatchString(paramName(prefix))})
			}
		}
		walk("", j)
		return out
	}
	if vals, err := url.ParseQuery(body); err == nil && strings.Contains(body, "=") {
		for k, vs := range vals {
			v := ""
			if len(vs) > 0 {
				v = vs[0]
			}
			out = append(out, Candidate{Loc: "form", Path: k, Name: paramName(k), Type: "string", Example: v, Suggest: !noisyParam.MatchString(k)})
		}
	}
	return out
}

// BuildDraft turns a recorded request + chosen candidates into a tool template.
func BuildDraft(q *ReqRecord, chosen []Candidate) (*Tool, error) {
	t := &Tool{Method: q.Method, Params: []Param{}}
	t.Headers, t.CredHeaders = SanitizeHeaders(q.ReqHeaders)
	used := map[string]int{}
	uniq := func(n string) string {
		used[n]++
		if used[n] > 1 {
			return fmt.Sprintf("%s_%d", n, used[n])
		}
		return n
	}
	// URL
	u, err := url.Parse(q.URL)
	if err != nil {
		return nil, err
	}
	qparts := []string{}
	for _, kv := range strings.Split(u.RawQuery, "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		dk, _ := url.QueryUnescape(k)
		for i, c := range chosen {
			if c.Loc == "query" && c.Path == dk && c.Ref != "" {
				v = "{{secret." + c.Ref + "}}"
				break
			}
			if c.Loc == "query" && c.Path == dk {
				name := uniq(c.Name)
				if c.Secret {
					c.Example = ""
				}
				chosen[i].Name = name
				v = "{{" + name + "}}"
				t.Params = append(t.Params, Param{Name: name, Type: "string", Required: !optionalParam.MatchString(name), Default: c.Example, Description: "查询参数 " + dk + "，示例: " + c.Example})
				break
			}
		}
		qparts = append(qparts, k+"="+v)
	}
	u.RawQuery = ""
	t.URL = u.String()
	if len(qparts) > 0 {
		t.URL += "?" + strings.Join(qparts, "&")
	}
	// body
	t.Body = q.ReqBody
	body := strings.TrimSpace(q.ReqBody)
	var j any
	if body != "" && json.Unmarshal([]byte(body), &j) == nil {
		for i, c := range chosen {
			if c.Loc != "body" {
				continue
			}
			if c.Ref != "" {
				setJSONPath(&j, c.Path, "{{secret."+c.Ref+"}}")
				continue
			}
			if c.Secret {
				c.Example = ""
			}
			name := uniq(c.Name)
			chosen[i].Name = name
			if setJSONPath(&j, c.Path, "{{"+name+"}}") {
				t.Params = append(t.Params, Param{Name: name, Type: c.Type, Required: !optionalParam.MatchString(name), Default: c.Example, Description: "字段 " + c.Path + "，示例: " + c.Example})
			}
		}
		b, _ := json.MarshalIndent(j, "", "  ")
		t.Body = string(b)
	} else if body != "" {
		vals, _ := url.ParseQuery(body)
		changed := false
		for _, c := range chosen {
			if c.Loc == "form" && c.Ref != "" {
				if _, ok := vals[c.Path]; ok {
					vals.Set(c.Path, "{{secret."+c.Ref+"}}")
					changed = true
				}
				continue
			}
			if c.Loc == "form" {
				if _, ok := vals[c.Path]; ok {
					if c.Secret {
						c.Example = ""
					}
					name := uniq(c.Name)
					vals.Set(c.Path, "{{"+name+"}}")
					changed = true
					t.Params = append(t.Params, Param{Name: name, Type: "string", Required: !optionalParam.MatchString(name), Default: c.Example, Description: "表单字段 " + c.Path + "，示例: " + c.Example})
				}
			}
		}
		if changed {
			parts := []string{}
			keys := make([]string, 0, len(vals))
			for k := range vals {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				v := vals.Get(k)
				if !strings.HasPrefix(v, "{{") {
					v = url.QueryEscape(v)
				}
				parts = append(parts, url.QueryEscape(k)+"="+v)
			}
			t.Body = strings.Join(parts, "&")
		}
	}
	return t, nil
}

var idxRe = regexp.MustCompile(`^(.*)\[(\d+)\]$`)

func setJSONPath(root *any, p string, val any) bool {
	segs := []string{}
	for _, s := range strings.Split(p, ".") {
		// split "a[0][1]" into a, [0], [1]
		var tail []string
		for {
			m := idxRe.FindStringSubmatch(s)
			if m == nil {
				break
			}
			tail = append([]string{"[" + m[2] + "]"}, tail...)
			s = m[1]
		}
		if s != "" {
			segs = append(segs, s)
		}
		segs = append(segs, tail...)
	}
	cur := root
	for i, s := range segs {
		last := i == len(segs)-1
		if strings.HasPrefix(s, "[") {
			n, _ := strconv.Atoi(strings.Trim(s, "[]"))
			arr, ok := (*cur).([]any)
			if !ok || n >= len(arr) {
				return false
			}
			if last {
				arr[n] = val
				return true
			}
			cur = &arr[n]
		} else {
			m, ok := (*cur).(map[string]any)
			if !ok {
				return false
			}
			if _, ok := m[s]; !ok {
				return false
			}
			if last {
				m[s] = val
				return true
			}
			v := m[s]
			cur = &v
			defer func(m map[string]any, k string, p *any) { m[k] = *p }(m, s, cur)
		}
	}
	return false
}

var placeholderRe = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_\.]+)\s*\}\}`)

// Placeholders lists all {{names}} used in the template.
func (t *Tool) Placeholders() []string {
	seen := map[string]bool{}
	var out []string
	all := t.URL + "\n" + t.Body
	for _, v := range t.Headers {
		all += "\n" + v
	}
	for _, m := range placeholderRe.FindAllStringSubmatch(all, -1) {
		if isRefName(m[1]) {
			continue
		}
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// Normalize fills missing params for placeholders and validates the name.
var toolNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (t *Tool) Normalize() error {
	t.Name = strings.TrimSpace(t.Name)
	if !toolNameRe.MatchString(t.Name) {
		return errors.New("工具标识只能包含英文字母、数字、下划线和短横线（最长 64 位），例如 search_customer")
	}
	t.Method = strings.ToUpper(strings.TrimSpace(t.Method))
	if t.Method == "" {
		t.Method = "GET"
	}
	if _, err := url.Parse(t.URL); err != nil || !strings.HasPrefix(t.URL, "http") {
		return errors.New("请求地址必须以 http:// 或 https:// 开头")
	}
	have := map[string]bool{}
	ps := []Param{}
	for _, p := range t.Params {
		p.Name = strings.TrimSpace(p.Name)
		if p.Name == "" || have[p.Name] || isRefName(p.Name) {
			continue
		}
		if p.Type == "" {
			p.Type = "string"
		}
		have[p.Name] = true
		ps = append(ps, p)
	}
	for _, n := range t.Placeholders() {
		if !have[n] {
			ps = append(ps, Param{Name: n, Type: "string", Required: true})
			have[n] = true
		}
	}
	t.Params = ps
	// never keep credential headers in a tool definition
	clean := map[string]string{}
	for k, v := range t.Headers {
		// a credential header whose value comes from 配置管理 ({{secret.X}} / {{cfg.X}}) is safe to keep
		if IsCredHeader(k) && !strings.Contains(v, "{{secret.") && !strings.Contains(v, "{{cfg.") {
			lk := strings.ToLower(k)
			found := false
			for _, c := range t.CredHeaders {
				if c == lk {
					found = true
				}
			}
			if !found {
				t.CredHeaders = append(t.CredHeaders, lk)
			}
			continue
		}
		clean[k] = v
	}
	t.Headers = clean
	return nil
}

// InputSchema builds the MCP JSON schema.
func (t *Tool) InputSchema() map[string]any {
	props := map[string]any{}
	req := []string{}
	for _, p := range t.Params {
		ty := p.Type
		if ty != "number" && ty != "integer" && ty != "boolean" {
			ty = "string"
		}
		d := p.Description
		if p.Default == "@today" {
			if !strings.Contains(d, "今天") {
				d = strings.TrimSpace(d + "（不填默认今天，格式 YYYY-MM-DD）")
			}
		} else if p.Default != "" && !strings.Contains(d, p.Default) {
			d = strings.TrimSpace(d + " 示例: " + p.Default)
		}
		prop := map[string]any{"type": ty}
		if d != "" {
			prop["description"] = d
		}
		if !p.Required && p.Default != "" && p.Default != "@today" {
			var dv any = p.Default
			if ty == "number" || ty == "integer" {
				if f, err := strconv.ParseFloat(p.Default, 64); err == nil {
					dv = f
				}
			} else if ty == "boolean" {
				dv = p.Default == "true"
			}
			prop["default"] = dv
		}
		props[p.Name] = prop
		if p.Required {
			req = append(req, p.Name)
		}
	}
	s := map[string]any{"type": "object", "properties": props}
	if len(req) > 0 {
		s["required"] = req
	}
	return s
}

// ---------- execution ----------

func argString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case nil:
		return ""
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

func coerce(p Param, v any) any {
	s, isStr := v.(string)
	switch p.Type {
	case "number", "integer":
		if isStr {
			if f, err := strconv.ParseFloat(strings.TrimSpace(s), 64); err == nil {
				return f
			}
		}
	case "boolean":
		if isStr {
			return s == "true" || s == "1" || s == "是"
		}
	case "string":
		if !isStr && v != nil {
			return argString(v)
		}
	}
	return v
}

// Render fills the template with args.
func (t *Tool) Render(args map[string]any) (method, u string, headers map[string]string, body string, err error) {
	return t.RenderWith(args, nil, nil)
}

// RenderRefs lists {{cfg.X}} / {{secret.X}} references used by a template.
func (t *Tool) RenderRefs() []string {
	all := t.URL + "\n" + t.Body
	for _, v := range t.Headers {
		all += "\n" + v
	}
	seen := map[string]bool{}
	out := []string{}
	for _, m := range placeholderRe.FindAllStringSubmatch(all, -1) {
		if isRefName(m[1]) && !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// RenderWith fills the template with args; resolve serves {{cfg.X}} / {{secret.X}}, extra serves
// internal values such as {{csrf}}.
func (t *Tool) RenderWith(args map[string]any, resolve func(string) (string, error), extra map[string]any) (method, u string, headers map[string]string, body string, err error) {
	vals := map[string]any{}
	for k, v := range extra {
		vals[k] = v
	}
	for _, r := range t.RenderRefs() {
		if resolve == nil {
			return "", "", nil, "", fmt.Errorf("配置项「%s」无法读取", strings.SplitN(r, ".", 2)[1])
		}
		v, err := resolve(r)
		if err != nil {
			return "", "", nil, "", err
		}
		vals[r] = v
	}
	for _, p := range t.Params {
		v, ok := args[p.Name]
		if !ok || v == nil || (p.Default == "@today" && v == "") {
			if p.Default == "@today" {
				v = time.Now().Format("2006-01-02")
			} else if p.Default != "" && !p.Required {
				v = p.Default
			} else if p.Required {
				return "", "", nil, "", fmt.Errorf("缺少参数: %s", p.Name)
			} else {
				v = ""
			}
		}
		vals[p.Name] = coerce(p, v)
	}
	u = placeholderRe.ReplaceAllStringFunc(t.URL, func(m string) string {
		n := placeholderRe.FindStringSubmatch(m)[1]
		return url.QueryEscape(argString(vals[n]))
	})
	headers = map[string]string{}
	for k, v := range t.Headers {
		headers[k] = placeholderRe.ReplaceAllStringFunc(v, func(m string) string {
			return argString(vals[placeholderRe.FindStringSubmatch(m)[1]])
		})
	}
	ct := strings.ToLower(headerGet(t.Headers, "content-type"))
	trimmed := strings.TrimSpace(t.Body)
	isJSON := strings.Contains(ct, "json") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
	isForm := strings.Contains(ct, "x-www-form-urlencoded")
	b := t.Body
	if isJSON {
		// "{{x}}" (quoted, whole value) -> typed JSON value
		quoted := regexp.MustCompile(`"\{\{\s*([A-Za-z0-9_\.]+)\s*\}\}"`)
		b = quoted.ReplaceAllStringFunc(b, func(m string) string {
			n := quoted.FindStringSubmatch(m)[1]
			jb, _ := json.Marshal(vals[n])
			return string(jb)
		})
		b = placeholderRe.ReplaceAllStringFunc(b, func(m string) string {
			jb, _ := json.Marshal(argString(vals[placeholderRe.FindStringSubmatch(m)[1]]))
			return strings.Trim(string(jb), `"`)
		})
	} else {
		b = placeholderRe.ReplaceAllStringFunc(b, func(m string) string {
			s := argString(vals[placeholderRe.FindStringSubmatch(m)[1]])
			if isForm {
				return url.QueryEscape(s)
			}
			return s
		})
	}
	return t.Method, u, headers, b, nil
}

func headerGet(h map[string]string, name string) string {
	for k, v := range h {
		if strings.EqualFold(k, name) {
			return v
		}
	}
	return ""
}

// CookieHeader picks cookies that the browser would send to rawURL.
func CookieHeader(cs []Cookie, rawURL string) (string, []Cookie) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", nil
	}
	host := strings.ToLower(u.Hostname())
	p := u.Path
	if p == "" {
		p = "/"
	}
	nowS := float64(time.Now().Unix())
	var m []Cookie
	for _, c := range cs {
		d := strings.ToLower(c.Domain)
		ok := false
		if strings.HasPrefix(d, ".") {
			d2 := d[1:]
			ok = host == d2 || strings.HasSuffix(host, "."+d2)
		} else {
			ok = host == d
		}
		if !ok {
			continue
		}
		cp := c.Path
		if cp == "" {
			cp = "/"
		}
		if !(p == cp || strings.HasPrefix(p, strings.TrimSuffix(cp, "/")+"/") || cp == "/") {
			continue
		}
		secureURL := u.Scheme == "https" || u.Scheme == "wss"
		if c.Secure && !secureURL && host != "localhost" && host != "127.0.0.1" {
			continue
		}
		if !c.Session && c.Expires > 0 && c.Expires < nowS {
			continue
		}
		m = append(m, c)
	}
	sort.SliceStable(m, func(i, j int) bool { return len(m[i].Path) > len(m[j].Path) })
	parts := make([]string, 0, len(m))
	for _, c := range m {
		parts = append(parts, c.Name+"="+c.Value)
	}
	return strings.Join(parts, "; "), m
}

type CallResult struct {
	Status      int               `json:"status"`
	Body        string            `json:"body"`
	Headers     map[string]string `json:"headers"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	ReqBody     string            `json:"request_body"`
	CookieNames []string          `json:"cookie_names"`
	CredSource  string            `json:"cred_source"`
	DurationMs  int64             `json:"duration_ms"`
	Error       string            `json:"error,omitempty"`
	Relogged    bool              `json:"relogged,omitempty"`
	hops        []string
	finalURL    string
}

const maxResult = 60 * 1024

// Execute runs the tool, attaching credentials from the browser profile at runtime. When the
// site answers "not logged in" it logs in again automatically (per the site's 登录配置) and
// retries once. Everything returned is scrubbed of secret values.
func (a *App) Execute(t *Tool, args map[string]any) (*CallResult, error) {
	res, err := a.execute(t, args)
	if err != nil {
		return nil, errors.New(a.vault.Scrub(err.Error()))
	}
	res.Body = a.vault.Scrub(res.Body)
	res.ReqBody = a.vault.Scrub(res.ReqBody)
	res.URL = a.vault.Scrub(res.URL)
	res.Error = a.vault.Scrub(res.Error)
	for k, v := range res.Headers {
		res.Headers[k] = a.vault.Scrub(v)
	}
	return res, nil
}

func (a *App) execute(t *Tool, args map[string]any) (*CallResult, error) {
	method, u, headers, body, err := t.RenderWith(args, a.vault.Resolve, nil)
	if err != nil {
		return nil, err
	}
	site := a.store.EnsureSite(u)
	var st *siteState
	var gen int64
	if site != nil {
		st = a.state(site.Origin)
		gen = a.siteGen(st)
		if err := a.pendingErr(site, st); err != nil {
			return nil, err
		}
	}
	cookies, src := a.CookiesFor(u)
	res, err := a.doCall(t, method, u, headers, body, cookies, src)
	if err != nil {
		return nil, err
	}
	if res.Error != "" {
		return res, nil
	}
	// snapshot may be stale (e.g. user re-logged in): re-read the browser profile once and retry
	if (res.Status == 401 || res.Status == 403) && src == "本地登录态快照" {
		if fresh, err := a.readProfileCookies(); err == nil && len(fresh) > 0 {
			oldH, _ := CookieHeader(cookies, u)
			newH, _ := CookieHeader(fresh, u)
			if newH != "" && newH != oldH {
				a.store.ReplaceCookies(fresh)
				if r2, err := a.doCall(t, method, u, headers, body, fresh, "浏览器配置（后台读取）"); err == nil {
					res = r2
				}
			}
		}
	}
	if site == nil {
		return res, nil
	}
	bad, why := site.NotLoggedIn(res.Status, res.Body, headerGet(res.Headers, "Content-Type"), res.hops, u)
	if !bad {
		a.markValid(site, false)
		return res, nil
	}
	debugf("%s 未登录（%s），尝试自动登录", site.Origin, why)
	if err := a.Relogin(site, gen, false, true); err != nil {
		return nil, err
	}
	cookies, src = a.CookiesFor(u)
	r2, err := a.doCall(t, method, u, headers, body, cookies, src+"，已自动重新登录")
	if err != nil {
		return nil, err
	}
	if r2.Error != "" {
		return r2, nil
	}
	if bad2, why2 := site.NotLoggedIn(r2.Status, r2.Body, headerGet(r2.Headers, "Content-Type"), r2.hops, u); bad2 && !(r2.Status == 403 && why2 == "接口返回 HTTP 403") {
		msg := fmt.Sprintf("「%s」自动登录后接口仍然显示未登录（%s）。请在控制台「登录中心」检查这个网站的登录配置，或点击「打开浏览器登录」手动登录后重试", site.DisplayName(), why2)
		a.store.SetSiteStatus(site.ID, "invalid", msg, false)
		return nil, &LoginErr{msg}
	}
	r2.Relogged = true
	return r2, nil
}

func (a *App) doCall(t *Tool, method, u string, headers map[string]string, body string, cookies []Cookie, src string) (*CallResult, error) {
	ch, matched := CookieHeader(cookies, u)
	res := &CallResult{URL: u, Method: method, ReqBody: body, CredSource: src}
	for _, c := range matched {
		res.CookieNames = append(res.CookieNames, c.Name)
	}
	var rb io.Reader
	if body != "" && method != "GET" && method != "HEAD" {
		rb = bytes.NewBufferString(body)
	}
	req, err := http.NewRequest(method, u, rb)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if ch != "" {
		req.Header.Set("Cookie", ch)
	}
	// re-create CSRF-style headers from cookies with similar names
	for _, h := range t.CredHeaders {
		if h == "cookie" {
			continue
		}
		if strings.Contains(h, "csrf") || strings.Contains(h, "xsrf") {
			for _, c := range matched {
				ln := strings.ToLower(c.Name)
				if strings.Contains(ln, "csrf") || strings.Contains(ln, "xsrf") {
					v, _ := url.QueryUnescape(c.Value)
					req.Header.Set(h, v)
					break
				}
			}
		}
	}
	start := time.Now()
	client := *a.httpClient
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		res.hops = append(res.hops, r.URL.String())
		if len(via) >= 10 {
			return errors.New("重定向次数过多")
		}
		return nil
	}
	resp, err := client.Do(req)
	res.DurationMs = time.Since(start).Milliseconds()
	if err != nil {
		res.Error = err.Error()
		return res, nil
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	res.Status = resp.StatusCode
	if resp.Request != nil && resp.Request.URL != nil {
		res.finalURL = resp.Request.URL.String()
	}
	res.Headers = map[string]string{}
	for k := range resp.Header {
		if strings.EqualFold(k, "Set-Cookie") {
			continue
		}
		res.Headers[k] = resp.Header.Get(k)
	}
	res.Body = truncate(string(data), maxResult)
	return res, nil
}
