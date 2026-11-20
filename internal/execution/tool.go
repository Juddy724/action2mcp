package execution

import (
	"action2mcp/internal/credential"
	"action2mcp/internal/domain"
	"action2mcp/internal/recording"
	"action2mcp/internal/result"
	"action2mcp/internal/vault"
	"bytes"
	"context"
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

func ParamName(p string) string {
	parts := strings.Split(p, ".")
	n := parts[len(parts)-1]
	n = regexp.MustCompile(`\[\d+\]`).ReplaceAllString(n, "")
	n = regexp.MustCompile(`[^A-Za-z0-9_]`).ReplaceAllString(n, "_")
	if n == "" {
		n = "param"
	}
	return n
}

func JsonType(v any) string {
	switch v.(type) {
	case float64:
		return "number"
	case bool:
		return "boolean"
	default:
		return "string"
	}
}

func SuggestParams(q *recording.Request) []Candidate {
	if IsWSMethod(q.Method) {
		return suggestWSParams(q)
	}
	out := []Candidate{}
	if u, err := url.Parse(q.URL); err == nil {
		for _, kv := range strings.Split(u.RawQuery, "&") {
			if kv == "" {
				continue
			}
			k, v, _ := strings.Cut(kv, "=")
			k, _ = url.QueryUnescape(k)
			v, _ = url.QueryUnescape(v)
			out = append(out, Candidate{Loc: "query", Path: k, Name: ParamName(k), Type: "string", Example: v, Suggest: !noisyParam.MatchString(k)})
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
				out = append(out, Candidate{Loc: "body", Path: prefix, Name: ParamName(prefix), Type: "string", Example: "null", Suggest: false})
			default:
				ex := fmt.Sprint(x)
				if f, ok := x.(float64); ok {
					ex = strconv.FormatFloat(f, 'f', -1, 64)
				}
				out = append(out, Candidate{Loc: "body", Path: prefix, Name: ParamName(prefix), Type: JsonType(x), Example: ex, Suggest: !noisyParam.MatchString(ParamName(prefix))})
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
			out = append(out, Candidate{Loc: "form", Path: k, Name: ParamName(k), Type: "string", Example: v, Suggest: !noisyParam.MatchString(k)})
		}
	}
	return out
}

// BuildDraft turns a recorded request + chosen candidates into a tool template.
func BuildDraft(q *recording.Request, chosen []Candidate) (*Tool, error) {
	if IsWSMethod(q.Method) {
		return BuildWSDraft(q, chosen)
	}
	t := &Tool{Method: q.Method, Params: []domain.Param{}}
	t.Headers, t.CredHeaders = credential.SanitizeHeaders(q.ReqHeaders)
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
				desc := "查询参数 " + dk + "，示例: " + c.Example
				reqd := !optionalParam.MatchString(name)
				if c.Secret {
					desc = RemovedSecretDescription
					reqd = true
				}
				t.Params = append(t.Params, domain.Param{Name: name, Type: "string", Required: reqd, Default: c.Example, Description: desc, Secret: c.Secret})
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
				SetJSONPath(&j, c.Path, "{{secret."+c.Ref+"}}")
				continue
			}
			if c.Secret {
				c.Example = ""
			}
			name := uniq(c.Name)
			chosen[i].Name = name
			if SetJSONPath(&j, c.Path, "{{"+name+"}}") {
				desc := "字段 " + c.Path + "，示例: " + c.Example
				reqd := !optionalParam.MatchString(name)
				if c.Secret {
					c.Example = ""
					desc = RemovedSecretDescription
					reqd = true
				}
				t.Params = append(t.Params, domain.Param{Name: name, Type: c.Type, Required: reqd, Default: c.Example, Description: desc, Secret: c.Secret})
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
					desc := "表单字段 " + c.Path + "，示例: " + c.Example
					reqd := !optionalParam.MatchString(name)
					if c.Secret {
						desc = RemovedSecretDescription
						reqd = true
					}
					t.Params = append(t.Params, domain.Param{Name: name, Type: "string", Required: reqd, Default: c.Example, Description: desc, Secret: c.Secret})
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

func SetJSONPath(root *any, p string, val any) bool {
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

var placeholderRe = regexp.MustCompile(`\{\{\s*((?:header|cookie)\.[A-Za-z0-9][A-Za-z0-9_-]*|[A-Za-z0-9_\.]+)\s*\}\}`)

var flowInputPlaceholderRe = regexp.MustCompile(`\{\{\s*input\.([A-Za-z0-9_]+)(?:\.[^}]*)?\s*\}\}`)

// Placeholders lists all {{names}} used in the template.
func (t *Tool) Placeholders() []string {
	seen := map[string]bool{}
	var out []string
	all := strings.Join(configTemplateTexts(t), "\n")
	if IsFlowMethod(t.Method) {
		for _, m := range flowInputPlaceholderRe.FindAllStringSubmatch(all, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
		return out
	}
	for _, m := range placeholderRe.FindAllStringSubmatch(all, -1) {
		if credential.IsServerRef(m[1], IsWSMethod(t.Method)) {
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
	switch {
	case IsFlowMethod(t.Method):
		t.URL = strings.TrimSpace(t.URL)
		if t.URL == "" {
			t.URL = "flow://custom"
		}
		if t.Config.Flow != nil {
			for i := range t.Config.Flow.Steps {
				s := &t.Config.Flow.Steps[i]
				s.ID = strings.TrimSpace(s.ID)
				if s.ID == "" {
					s.ID = fmt.Sprintf("step_%d", i+1)
				}
				s.Name = strings.TrimSpace(s.Name)
				s.Kind = strings.ToLower(strings.TrimSpace(s.Kind))
				s.ToolName = strings.TrimSpace(s.ToolName)
				s.Runtime = strings.ToLower(strings.TrimSpace(s.Runtime))
				if s.Kind == "script" && s.Runtime == "" {
					s.Runtime = "builtin_js"
				}
			}
			t.Config.Flow.Output.Mode = strings.ToLower(strings.TrimSpace(t.Config.Flow.Output.Mode))
			if t.Config.Flow.Output.Mode == "" {
				t.Config.Flow.Output.Mode = "last"
			}
			if err := ValidateFlowConfig(t.Config.Flow); err != nil {
				return err
			}
		}
	case IsWSMethod(t.Method):
		u, err := url.Parse(t.URL)
		if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") {
			return errors.New("WebSocket 工具地址必须以 ws:// 或 wss:// 开头")
		}
	default:
		if _, err := url.Parse(t.URL); err != nil || !strings.HasPrefix(t.URL, "http") {
			return errors.New("请求地址必须以 http:// 或 https:// 开头")
		}
	}
	have := map[string]bool{}
	ps := []domain.Param{}
	for _, p := range t.Params {
		p.Name = strings.TrimSpace(p.Name)
		if p.Name == "" || have[p.Name] || credential.IsServerRef(p.Name, IsWSMethod(t.Method)) {
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
			ps = append(ps, domain.Param{Name: n, Type: "string", Required: true})
			have[n] = true
		}
	}
	t.Params = ps
	// never keep credential headers in a tool definition
	clean := map[string]string{}
	for k, v := range t.Headers {
		// a credential header whose value comes from 配置管理 ({{secret.X}} / {{cfg.X}}) is safe to keep
		if credential.IsCredHeader(k) && !strings.Contains(v, "{{secret.") && !strings.Contains(v, "{{cfg.") && !strings.Contains(v, "{{header.") && !strings.Contains(v, "{{cookie.") {
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
		secret := ParamIsSecret(t, p)
		if p.Default == "@today" {
			if !strings.Contains(d, "今天") {
				d = strings.TrimSpace(d + "（不填默认今天，格式 YYYY-MM-DD）")
			}
		} else if !secret && p.Default != "" && !strings.Contains(d, p.Default) {
			d = strings.TrimSpace(d + " 示例: " + p.Default)
		}
		if secret && p.Default != "" && p.Default != "@today" {
			d = strings.ReplaceAll(d, p.Default, vault.Mask)
		}
		prop := map[string]any{"type": ty}
		if d != "" {
			prop["description"] = d
		}
		if !secret && !p.Required && p.Default != "" && p.Default != "@today" {
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

func coerce(p domain.Param, v any) any {
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
			return domain.ArgumentText(v)
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
	all := strings.Join(configTemplateTexts(t), "\n")
	seen := map[string]bool{}
	out := []string{}
	for _, m := range placeholderRe.FindAllStringSubmatch(all, -1) {
		if credential.IsRefName(m[1]) && !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

// RenderWith fills the template with args; resolve serves {{cfg.X}} / {{secret.X}}, extra serves
// internal values such as {{csrf}}.
func (t *Tool) RenderWith(args map[string]any, resolve func(string) (string, error), extra map[string]any) (method, u string, headers map[string]string, body string, err error) {
	vals, err := t.bindValues(args, resolve, extra, false, time.Now())
	if err != nil {
		return "", "", nil, "", err
	}
	return t.renderValues(vals, nil)
}

// BindInputArgs binds and validates top-level tool parameters against args with defaults applied.
func (t *Tool) BindInputArgs(args map[string]any) (map[string]any, error) {
	return t.bindValues(args, nil, nil, true, time.Now())
}

func (t *Tool) bindValues(args map[string]any, resolve func(string) (string, error), extra map[string]any, deferRefs bool, at time.Time) (map[string]any, error) {
	vals := map[string]any{}
	for k, v := range extra {
		vals[k] = v
	}
	for _, r := range t.RenderRefs() {
		if deferRefs {
			continue
		}
		if resolve == nil {
			return nil, fmt.Errorf("配置项「%s」无法读取", strings.SplitN(r, ".", 2)[1])
		}
		v, err := resolve(r)
		if err != nil {
			return nil, err
		}
		vals[r] = v
	}
	var missing []string
	for _, p := range t.Params {
		v, ok := args[p.Name]
		if !ok || v == nil || (p.Default == "@today" && v == "") {
			if p.Default == "@today" {
				v = at.Format("2006-01-02")
			} else if p.Default != "" && !p.Required {
				v = p.Default
			} else if p.Required {
				missing = append(missing, p.Name)
				continue
			} else {
				v = ""
			}
		}
		vals[p.Name] = coerce(p, v)
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("缺少参数: %s", strings.Join(missing, "、"))
	}
	return vals, nil
}

func (t *Tool) renderValues(vals map[string]any, deferred *deferredCredentials) (method, u string, headers map[string]string, body string, err error) {
	u = placeholderRe.ReplaceAllStringFunc(t.URL, func(m string) string {
		n := placeholderRe.FindStringSubmatch(m)[1]
		return url.QueryEscape(domain.ArgumentText(renderValue(vals, n, deferred, credentialEncoding{query: true})))
	})
	headers = map[string]string{}
	keys := make([]string, 0, len(t.Headers))
	for k := range t.Headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := t.Headers[k]
		headers[k] = placeholderRe.ReplaceAllStringFunc(v, func(m string) string {
			return domain.ArgumentText(renderValue(vals, placeholderRe.FindStringSubmatch(m)[1], deferred, credentialEncoding{}))
		})
	}
	ct := strings.ToLower(HeaderGet(t.Headers, "content-type"))
	trimmed := strings.TrimSpace(t.Body)
	isJSON := strings.Contains(ct, "json") || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[")
	isForm := strings.Contains(ct, "x-www-form-urlencoded")
	b := t.Body
	if isJSON {
		if strings.Contains(b, "{{") {
			dec := json.NewDecoder(strings.NewReader(b))
			dec.UseNumber()
			var v any
			if err := dec.Decode(&v); err == nil && hasNestedPlaceholder(v, 0) {
				// Walk each decoded layer so a placeholder inside a JSON string
				// is escaped for that layer, then again for the outer document.
				b = string(CompactJSON(renderJSONPlaceholders(v, vals, 0, deferred, 1)))
			} else {
				b = legacyRenderJSONPlaceholders(b, vals, deferred)
			}
		}
	} else {
		b = placeholderRe.ReplaceAllStringFunc(b, func(m string) string {
			s := domain.ArgumentText(renderValue(vals, placeholderRe.FindStringSubmatch(m)[1], deferred, credentialEncoding{query: isForm}))
			if isForm {
				return url.QueryEscape(s)
			}
			return s
		})
	}
	return t.Method, u, headers, b, nil
}

func wholePlaceholderName(s string) (string, bool) {
	t := strings.TrimSpace(s)
	m := placeholderRe.FindStringSubmatch(t)
	if m == nil || strings.TrimSpace(m[0]) != t {
		return "", false
	}
	return m[1], true
}

func renderJSONPlaceholders(v any, vals map[string]any, depth int, deferred *deferredCredentials, layers int) any {
	if depth > 8 {
		return v
	}
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			x[k] = renderJSONPlaceholders(x[k], vals, depth+1, deferred, layers)
		}
		return x
	case []any:
		for i := range x {
			x[i] = renderJSONPlaceholders(x[i], vals, depth+1, deferred, layers)
		}
		return x
	case string:
		if name, ok := wholePlaceholderName(x); ok {
			deferrable := deferred != nil && (deferred.deferName != nil && deferred.deferName(name) || deferred.deferName == nil && credential.IsRefName(name))
			if _, exists := vals[name]; exists || deferrable {
				return renderValue(vals, name, deferred, credentialEncoding{jsonLayers: layers})
			}
			return x
		}
		if !strings.Contains(x, "{{") {
			return x
		}
		if pre, tail, ok := SplitCommandJSON(x); ok {
			if inner, err := ParseRecJSON(tail); err == nil {
				rendered := renderJSONPlaceholders(inner, vals, depth+1, deferred, layers+1)
				return pre + string(CompactJSON(rendered))
			}
		}
		trimmed := strings.TrimSpace(x)
		if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			if inner, err := ParseRecJSON(trimmed); err == nil {
				rendered := renderJSONPlaceholders(inner, vals, depth+1, deferred, layers+1)
				return string(CompactJSON(rendered))
			}
		}
		return placeholderRe.ReplaceAllStringFunc(x, func(m string) string {
			return domain.ArgumentText(renderValue(vals, placeholderRe.FindStringSubmatch(m)[1], deferred, credentialEncoding{jsonLayers: layers}))
		})
	default:
		return v
	}
}

// hasNestedPlaceholder reports whether a placeholder sits inside a string that is
// itself JSON (or command-prefixed JSON). Only those bodies need layer-aware
// rendering; everything else keeps the legacy byte-preserving path.
func hasNestedPlaceholder(v any, depth int) bool {
	if depth > 8 {
		return false
	}
	switch x := v.(type) {
	case map[string]any:
		for _, val := range x {
			if hasNestedPlaceholder(val, depth+1) {
				return true
			}
		}
	case []any:
		for _, val := range x {
			if hasNestedPlaceholder(val, depth+1) {
				return true
			}
		}
	case string:
		if !strings.Contains(x, "{{") {
			return false
		}
		if _, ok := wholePlaceholderName(x); ok {
			return false
		}
		if _, tail, ok := SplitCommandJSON(x); ok {
			if _, err := ParseRecJSON(tail); err == nil {
				return true
			}
		}
		t := strings.TrimSpace(x)
		if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
			if _, err := ParseRecJSON(t); err == nil {
				return true
			}
		}
	}
	return false
}

func legacyRenderJSONPlaceholders(b string, vals map[string]any, deferred *deferredCredentials) string {
	if deferred != nil && deferred.preview {
		b = quotePreviewJSONMasks(b, deferred.maskedParams)
	}
	// One pass: argument text is never interpreted as another template reference.
	quotedOrInline := regexp.MustCompile(`"\{\{\s*([A-Za-z0-9_\.]+)\s*\}\}"|\{\{\s*([A-Za-z0-9_\.]+)\s*\}\}`)
	return quotedOrInline.ReplaceAllStringFunc(b, func(m string) string {
		n := placeholderRe.FindStringSubmatch(m)[1]
		v := renderValue(vals, n, deferred, credentialEncoding{jsonLayers: 1, escapeHTML: true})
		if strings.HasPrefix(m, `"`) {
			jb, _ := json.Marshal(v)
			return string(jb)
		}
		jb, _ := json.Marshal(domain.ArgumentText(v))
		return string(jb[1 : len(jb)-1])
	})
}

func HeaderGet(h map[string]string, name string) string {
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
	Outcome     string            `json:"outcome,omitempty"`
	Truncated   bool              `json:"truncated,omitempty"`
	RowCount    int               `json:"row_count,omitempty"`
	hops        []string
	finalURL    string
}

const MaxResult = result.MaxHTTPBytes

// Execute runs the tool, attaching credentials from the browser profile at runtime. When the
// site answers "not logged in" it logs in again automatically (per the site's 登录配置) and
// retries once. Everything returned is scrubbed of secret values.
func (a *Engine) Execute(t *Tool, args map[string]any) (*CallResult, error) {
	p, err := a.Prepare(t, args)
	if err != nil {
		return nil, errors.New(a.vault.Scrub(err.Error()))
	}
	return a.Send(p)
}

func (a *Engine) Send(p *PreparedCall) (*CallResult, error) {
	secrets := append([]string{}, p.secretValues...)
	res, err := a.send(p, &secrets)
	if err != nil {
		return nil, errors.New(a.ScrubApprovalText(err.Error(), secrets))
	}
	view := result.Response{Status: res.Status, Body: res.Body, Headers: res.Headers, Error: res.Error, Outcome: res.Outcome, Truncated: res.Truncated}
	result.Present(result.Config{ResultFormat: p.presentCfg.ResultFormat, ResultSelector: p.presentCfg.ResultSelector, DetectFailure: p.presentCfg.DetectFailure, WebSocket: p.ws, SQLGuard: p.wsConfig.SqlGuardEnabled()}, &view)
	res.Body, res.Error, res.Outcome, res.Truncated = view.Body, view.Error, view.Outcome, view.Truncated
	if !(p.ws && p.wsConfig.SqlGuardEnabled() && res.Outcome == OutcomeSuccess) {
		res.Body = a.ScrubApprovalText(res.Body, secrets)
	}
	res.ReqBody = a.ScrubApprovalText(res.ReqBody, secrets)
	res.URL = a.ScrubApprovalText(res.URL, secrets)
	res.Error = a.ScrubApprovalText(res.Error, secrets)
	for k, v := range res.Headers {
		res.Headers[k] = a.ScrubApprovalText(v, secrets)
	}
	return res, nil
}

func (a *Engine) send(p *PreparedCall, secrets *[]string) (*CallResult, error) {
	if p.isWS() {
		return a.sendWS(p, secrets)
	}
	r, err := p.resolve(func(ref string) (string, error) {
		value, err := a.vault.Resolve(ref)
		if err == nil {
			*secrets = append(*secrets, value)
		}
		return value, err
	})
	method, u, headers, body := r.Method, r.URL, r.Headers, r.Body
	t := &Tool{CredHeaders: p.credHeaders}
	if err != nil {
		return nil, err
	}
	if err := a.guard.CheckDestination(context.Background(), u); err != nil {
		return nil, err
	}
	session, err := a.sessions.Begin(u)
	if err != nil {
		return nil, err
	}
	cookies, src := a.cookies(u)
	res, err := a.Call(t, method, u, headers, body, cookies, src)
	if err != nil {
		return nil, err
	}
	if res.Error != "" {
		return res, nil
	}
	// snapshot may be stale (e.g. user re-logged in): re-read the browser profile once and retry
	if (res.Status == 401 || res.Status == 403) && src == "本地登录态快照" {
		if fresh, err := a.profileCookies(); err == nil && len(fresh) > 0 {
			oldH, _ := CookieHeader(cookies, u)
			newH, _ := CookieHeader(fresh, u)
			if newH != "" && newH != oldH {
				a.replaceCookies(fresh)
				if r2, err := a.Call(t, method, u, headers, body, fresh, "浏览器配置（后台读取）"); err == nil {
					res = r2
				}
			}
		}
	}
	if session == nil {
		return res, nil
	}
	bad, why := session.NotLoggedIn(res.Status, res.Body, HeaderGet(res.Headers, "Content-Type"), res.hops, u)
	if !bad {
		session.MarkValid()
		return res, nil
	}
	if a.debug != nil {
		a.debug("%s 未登录（%s），尝试自动登录", session.Origin(), why)
	}
	if err := session.Relogin(); err != nil {
		return nil, err
	}
	cookies, src = a.cookies(u)
	r2, err := a.Call(t, method, u, headers, body, cookies, src+"，已自动重新登录")
	if err != nil {
		return nil, err
	}
	if r2.Error != "" {
		return r2, nil
	}
	if bad2, why2 := session.NotLoggedIn(r2.Status, r2.Body, HeaderGet(r2.Headers, "Content-Type"), r2.hops, u); bad2 && !(r2.Status == 403 && why2 == "接口返回 HTTP 403") {
		msg := fmt.Sprintf("「%s」自动登录后接口仍然显示未登录（%s）。请在控制台「登录中心」检查这个网站的登录配置，或点击「打开浏览器登录」手动登录后重试", session.DisplayName(), why2)
		return nil, session.Invalid(msg)
	}
	r2.Relogged = true
	return r2, nil
}

func (a *Engine) Call(t *Tool, method, u string, headers map[string]string, body string, cookies []Cookie, src string) (*CallResult, error) {
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
	client, closeIdle := a.guard.Client(a.httpClient)
	defer closeIdle()
	client.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if err := a.guard.CheckDestination(r.Context(), r.URL.String()); err != nil {
			return err
		}
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
	res.Body = string(data)
	return res, nil
}

// PlaceholderPattern returns an independent matcher; callers cannot mutate the owner grammar.
func PlaceholderPattern() *regexp.Regexp { return placeholderRe.Copy() }

// Redirects returns a copy for login-result classification.
func (r *CallResult) Redirects() []string { return append([]string(nil), r.hops...) }

// CapturedValue is builder-only input and is never serialized as an example.
func (c Candidate) CapturedValue() string      { return c.raw }
func (c *Candidate) SetCapturedValue(v string) { c.raw = v }

func NoisyParameter(name string) bool    { return noisyParam.MatchString(name) }
func OptionalParameter(name string) bool { return optionalParam.MatchString(name) }
func ValidToolName(name string) bool     { return toolNameRe.MatchString(name) }

func SuggestToolName(q *recording.Request) string {
	u, err := url.Parse(q.URL)
	if err != nil {
		return "tool"
	}
	segs := []string{}
	for _, s := range strings.Split(u.Path, "/") {
		s = strings.ToLower(s)
		if s == "" || s == "api" || s == "v1" || s == "v2" || s == "v3" || s == "rest" {
			continue
		}
		if _, err := strconv.Atoi(s); err == nil {
			continue
		}
		s = strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' {
				return r
			}
			return '_'
		}, s)
		segs = append(segs, s)
	}
	if len(segs) > 3 {
		segs = segs[len(segs)-3:]
	}
	n := strings.Trim(strings.Join(segs, "_"), "_")
	if n == "" {
		n = strings.ToLower(q.Method) + "_request"
	}
	if len(n) > 60 {
		n = n[:60]
	}
	return n
}
