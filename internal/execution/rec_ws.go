package execution

import (
	"action2mcp/internal/credential"
	"action2mcp/internal/domain"
	"action2mcp/internal/recording"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

func parseWSEnvelope(body string) (recording.Envelope, error) {
	var env recording.Envelope
	if strings.TrimSpace(body) == "" {
		return env, errors.New("WebSocket 信封为空")
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		return env, errors.New("WebSocket 信封不是合法 JSON")
	}
	if env.V != 1 {
		return env, errors.New("WebSocket 信封版本不受支持")
	}
	if env.Frames == nil {
		env.Frames = []recording.Frame{}
	}
	return env, nil
}

func outboundWSTexts(env recording.Envelope) []string {
	var out []string
	for _, f := range env.Frames {
		if f.Op == 1 && strings.TrimSpace(f.Text) != "" {
			out = append(out, f.Text)
		}
	}
	return out
}

func isCredJSONKey(path string) bool {
	name := path
	if i := strings.LastIndex(path, ":"); i >= 0 {
		name = path[i+1:]
	}
	if j := strings.LastIndex(name, "."); j >= 0 {
		name = name[j+1:]
	}
	return PathSensitive(name) || credential.IsCredHeader(name)
}

func BindingPlaceholder(s string) bool {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{{") || !strings.HasSuffix(s, "}}") {
		return false
	}
	ref := strings.TrimSpace(s[2 : len(s)-2])
	return credential.IsHeaderCookieRef(ref) || strings.HasPrefix(ref, "secret.") || strings.HasPrefix(ref, "cfg.")
}

func suggestWSParams(q *recording.Request) []Candidate {
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
	env, err := parseWSEnvelope(q.ReqBody)
	if err != nil || env.Truncated {
		return out
	}
	for i, text := range outboundWSTexts(env) {
		_, tail, ok := SplitCommandJSON(text)
		if !ok {
			continue
		}
		var j any
		if json.Unmarshal([]byte(tail), &j) != nil {
			continue
		}
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
				for n, e := range x {
					if n > 4 {
						break
					}
					walk(fmt.Sprintf("%s[%d]", prefix, n), e)
				}
			case nil:
				out = append(out, Candidate{Loc: "ws", Path: fmt.Sprintf("%d:%s", i, prefix), Name: ParamName(prefix), Type: "string", Example: "null", Suggest: false})
			default:
				ex := fmt.Sprint(x)
				if f, ok := x.(float64); ok {
					ex = strconv.FormatFloat(f, 'f', -1, 64)
				}
				secret := isCredJSONKey(prefix)
				if secret {
					ex = ""
				}
				out = append(out, Candidate{Loc: "ws", Path: fmt.Sprintf("%d:%s", i, prefix), Name: ParamName(prefix), Type: JsonType(x), Example: ex, Suggest: !secret && !noisyParam.MatchString(ParamName(prefix)), Secret: secret})
			}
		}
		walk("", j)
	}
	return out
}

func splitWSPath(path string) (int, string, bool) {
	idx, rest, ok := strings.Cut(path, ":")
	if !ok {
		return 0, path, false
	}
	n, err := strconv.Atoi(idx)
	if err != nil || n < 0 {
		return 0, path, false
	}
	return n, rest, true
}

func BuildWSDraft(q *recording.Request, chosen []Candidate) (*Tool, error) {
	env, err := parseWSEnvelope(q.ReqBody)
	if err != nil {
		return nil, err
	}
	if env.Truncated {
		return nil, errors.New("WebSocket 信封已截断，无法安全保存为工具")
	}
	texts := outboundWSTexts(env)
	if len(texts) == 0 {
		return nil, errors.New("没有可保存的出站文本帧")
	}
	t := &Tool{Method: "WS", Params: []domain.Param{}}
	t.Headers, t.CredHeaders = credential.SanitizeHeaders(q.ReqHeaders)
	for _, name := range t.CredHeaders {
		if t.Headers == nil {
			t.Headers = map[string]string{}
		}
		// Handshake credential headers become server-side bindings, not literals.
		t.Headers[name] = "{{header." + name + "}}"
	}
	u, err := url.Parse(q.URL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		return nil, errors.New("WebSocket 工具地址必须是 ws:// 或 wss://")
	}
	t.URL = u.String()

	used := map[string]int{}
	uniq := func(n string) string {
		used[n]++
		if used[n] > 1 {
			return fmt.Sprintf("%s_%d", n, used[n])
		}
		return n
	}
	byPath := map[string]Candidate{}
	for _, c := range chosen {
		byPath[c.Loc+":"+c.Path] = c
	}

	messages := make([]string, len(texts))
	sqlParam, sqlPath := "", ""
	for i, text := range texts {
		msg, err := renderChosenWSMessage(text, i, byPath, uniq, t)
		if err != nil {
			return nil, err
		}
		messages[i] = msg
		if sqlParam == "" {
			if s, err := ExtractJSONString(msg, "data.sql"); err == nil && s != "" {
				sqlPath = "data.sql"
				if strings.Contains(s, "{{") {
					ref := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, "{{"), "}}"))
					if ref != "" && !credential.IsHeaderCookieRef(ref) && !strings.Contains(ref, ".") {
						sqlParam = ref
					}
				}
			}
		}
	}
	t.Config.Messages = messages
	if sqlPath != "" {
		if sqlParam == "" {
			sqlParam = "sql"
			if !hasParam(t, "sql") {
				t.Params = append(t.Params, domain.Param{Name: "sql", Type: "string", Required: true, Description: "要执行的只读 SQL，必须带 LIMIT"})
			}
			// Ensure the template references {{sql}} at data.sql if it is still a literal.
			for i, msg := range t.Config.Messages {
				if s, err := ExtractJSONString(msg, "data.sql"); err == nil && !strings.Contains(s, "{{") {
					if next, err := replaceJSONString(msg, "data.sql", "{{sql}}"); err == nil {
						t.Config.Messages[i] = next
					}
				}
			}
		}
		t.Config.SQLGuard = &SQLGuardConfig{Enabled: true, Param: sqlParam, Path: sqlPath, MaxRows: SQLGuardMaxRowsCap}
	}
	recv, _ := parseWSEnvelope(q.RespBody)
	resultCmd, closeCmd := "execResult", "close"
	for _, f := range recv.Frames {
		if f.Op != 1 {
			continue
		}
		cmd, _, ok := SplitCommandJSON(f.Text)
		if !ok {
			continue
		}
		switch strings.TrimSpace(cmd) {
		case "execResult":
			resultCmd = "execResult"
		case "close":
			closeCmd = "close"
		}
	}
	t.Config.Collect = &WSCollectConfig{ResultCmd: resultCmd, CloseCmds: []string{closeCmd}, SuccessPath: "data.success", DonePath: "data.done", MessagePath: "data.message", TimeoutMS: 15000, MaxBytes: 65536}
	t.Config.Auth = &WSAuthConfig{RetryRelogin: true, FailMessageMatch: defaultAuthKeywords}
	t.Body = ""
	return t, nil
}

func hasParam(t *Tool, name string) bool {
	for _, p := range t.Params {
		if p.Name == name {
			return true
		}
	}
	return false
}

func renderChosenWSMessage(text string, frame int, byPath map[string]Candidate, uniq func(string) string, t *Tool) (string, error) {
	prefix, tail, ok := SplitCommandJSON(text)
	if !ok {
		return text, nil
	}
	if hasDuplicateJSONKeys(tail) {
		return "", errors.New("消息 JSON 含有重复键，已拒绝")
	}
	var v any
	if err := json.Unmarshal([]byte(tail), &v); err != nil {
		return "", errors.New("出站消息不是合法 JSON")
	}
	var walk func(prefix string, node *any) error
	walk = func(p string, node *any) error {
		switch x := (*node).(type) {
		case map[string]any:
			for k := range x {
				child := x[k]
				path := k
				if p != "" {
					path = p + "." + k
				}
				if err := walk(path, &child); err != nil {
					return err
				}
				x[k] = child
			}
		case []any:
			for i := range x {
				child := x[i]
				if err := walk(fmt.Sprintf("%s[%d]", p, i), &child); err != nil {
					return err
				}
				x[i] = child
			}
		default:
			key := "ws:" + fmt.Sprintf("%d:%s", frame, p)
			c, ok := byPath[key]
			if isCredJSONKey(p) {
				name := p
				if j := strings.LastIndex(p, "."); j >= 0 {
					name = p[j+1:]
				}
				bind := "header." + strings.ToLower(name)
				if name == "token" || strings.EqualFold(name, "sso-epctoken") || strings.Contains(strings.ToLower(name), "token") {
					bind = "header.sso-epctoken"
				}
				*node = "{{" + bind + "}}"
				return nil
			}
			if !ok {
				return nil
			}
			if c.Ref != "" {
				*node = "{{secret." + c.Ref + "}}"
				return nil
			}
			name := uniq(c.Name)
			*node = "{{" + name + "}}"
			if !hasParam(t, name) {
				desc := "字段 " + p
				if c.Example != "" && !c.Secret {
					desc += "，示例: " + c.Example
				}
				def := c.Example
				if c.Secret {
					def = ""
					desc = RemovedSecretDescription
				}
				t.Params = append(t.Params, domain.Param{Name: name, Type: c.Type, Required: true, Default: def, Description: desc, Secret: c.Secret})
			}
		}
		return nil
	}
	if err := walk("", &v); err != nil {
		return "", err
	}
	return strings.TrimRight(prefix, " ") + " " + string(CompactJSON(v)), nil
}

func ValidateWSCredentialBindings(t *Tool) error {
	if !IsWSMethod(t.Method) {
		return nil
	}
	for k, v := range t.Headers {
		if credential.IsCredHeader(k) && !BindingPlaceholder(v) {
			return fmt.Errorf("请求头 %s 只能使用 {{header.*}} / {{cookie.*}} / {{secret.*}} / {{cfg.*}} 绑定，不能保存字面值", k)
		}
	}
	for _, msg := range t.Config.Messages {
		_, tail, ok := SplitCommandJSON(msg)
		if !ok {
			continue
		}
		var v any
		if json.Unmarshal([]byte(tail), &v) != nil {
			continue
		}
		if err := rejectLiteralCreds(v, ""); err != nil {
			return err
		}
	}
	return nil
}

func rejectLiteralCreds(v any, path string) error {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if err := rejectLiteralCreds(x[k], p); err != nil {
				return err
			}
		}
	case []any:
		for i, e := range x {
			if err := rejectLiteralCreds(e, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case string:
		if isCredJSONKey(path) && !BindingPlaceholder(x) {
			return fmt.Errorf("敏感字段 %s 必须绑定为服务端引用，不能保存字面值或改为 AI 参数", path)
		}
	}
	return nil
}
