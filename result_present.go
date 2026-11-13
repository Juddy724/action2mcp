package main

import (
	"encoding/json"
	"html"
	"regexp"
	"strconv"
	"strings"
)

const (
	writeOpPrefix            = "【写操作，仅在用户明确要求时调用】"
	presentFallbackEmpty     = "[提示] 页面内容过少或主要由脚本生成，已返回原始 HTML。"
	presentFallbackMiss      = "[提示] 指定区域未匹配到内容，已返回原始 HTML。"
	presentFallbackBadSel    = "[提示] CSS 选择器无效，已返回原始 HTML。"
	presentVisibleMin        = 200
	presentRawMinBytes       = 2048
	presentAlertRemainMax    = 80
	presentMaxScriptForAlert = 2048
)

// presentToolResult cleans HTML, detects business failures, and truncates
// HTTP results. It runs after login retry and before secret scrub. WS tools
// with an SQL guard, and results that already carry a non-success Outcome,
// are left alone. HTTP tools are truncated to maxResult; WS tools are not.
func presentToolResult(p *PreparedCall, res *CallResult) {
	if p == nil || res == nil {
		return
	}
	if p.ws && p.wsConfig.sqlGuardEnabled() {
		return
	}
	if res.Outcome != "" && res.Outcome != outcomeSuccess {
		return
	}
	if res.Error != "" && res.Outcome == "" && res.Body == "" {
		return
	}
	raw := res.Body
	ct := ""
	if res.Headers != nil {
		ct = headerGet(res.Headers, "Content-Type")
	}
	cfg := p.presentCfg
	kind := classifyToolResult(ct, raw)
	format := cfg.resultFormat()
	detect := cfg.detectFailureEnabled()
	httpStatusOK := res.Status < 400

	var view HTMLView
	var cleanErr error
	cleaned := false
	if kind == ResultHTML && (format != resultFormatRaw || detect) {
		sel := ""
		if format == resultFormatSelector {
			sel = strings.TrimSpace(cfg.ResultSelector)
		}
		view, cleanErr = cleanHTMLToMarkdown(raw, sel)
		cleaned = cleanErr == nil
	}

	if detect && httpStatusOK {
		if kind == ResultHTML {
			// Alert "is this the whole page?" must use the full document.
			// A short selector excerpt would otherwise look like a failure
			// even when the rest of the page has real content.
			judgeView, judgeOK := view, cleaned
			if format == resultFormatSelector && strings.TrimSpace(cfg.ResultSelector) != "" {
				if full, err := cleanHTMLToMarkdown(raw, ""); err == nil {
					judgeView, judgeOK = full, true
				}
			}
			if msg, fail := detectHTMLAlertFailure(raw, judgeView, judgeOK); fail {
				res.Body = "业务失败：" + msg
				res.Error = ""
				res.Outcome = outcomeBusinessError
				return
			}
		}
		if kind == ResultJSON {
			if text, fail := detectJSONBusinessFailure(raw); fail {
				res.Body = text
				res.Error = ""
				res.Outcome = outcomeBusinessError
				if !p.ws {
					res.Body = truncatePresented(res.Body, res)
				}
				return
			}
		}
	}

	presented := raw
	note := ""
	if kind == ResultHTML && format != resultFormatRaw {
		sel := strings.TrimSpace(cfg.ResultSelector)
		if cleanErr != nil && format == resultFormatSelector {
			note = presentFallbackBadSel
			presented = raw
		} else if cleaned && format == resultFormatSelector && sel != "" && !view.SelectorHit {
			note = presentFallbackMiss
			presented = raw
		} else if cleaned && format != resultFormatSelector && view.VisibleChars < presentVisibleMin && len(raw) > presentRawMinBytes {
			note = presentFallbackEmpty
			presented = raw
		} else if cleaned {
			presented = view.Markdown
		}
	}
	if note != "" {
		presented = note + "\n" + presented
	}
	if !p.ws {
		presented = truncatePresented(presented, res)
	}
	res.Body = presented
}

func truncatePresented(s string, res *CallResult) string {
	if len(s) > maxResult {
		res.Truncated = true
	}
	return truncate(s, maxResult)
}

// ---------- HTML alert failure ----------

var (
	scriptBlockRe = regexp.MustCompile(`(?is)<script\b[^>]*>(.*?)</script>`)
	alertCallRe   = regexp.MustCompile(`(?i)(?:window\s*\.\s*)?alert\s*\(\s*(?:'((?:\\.|[^'\\])*)'|"((?:\\.|[^"\\])*)"|` + "`" + `((?:\\.|[^\\` + "`" + `])*)` + "`" + `)\s*\)`)
	locationRe    = regexp.MustCompile(`(?i)(?:window\s*\.\s*)?location(?:\s*\.\s*href)?`)
	redirectNoise = regexp.MustCompile(`(?i)^(跳转|返回|redirect|window\.?location|location\.href|please\s*wait|正在跳转|请稍候)*$`)
)

func detectHTMLAlertFailure(raw string, view HTMLView, haveView bool) (string, bool) {
	msg := pickAlertMessage(raw)
	if msg == "" {
		return "", false
	}
	if !haveView {
		v, err := cleanHTMLToMarkdown(raw, "")
		if err != nil {
			// Unparseable HTML with an alert: treat as failure only if the
			// visible remainder would be tiny; be conservative and fail.
			return msg, true
		}
		view = v
	}
	remain := remainingVisibleAfterAlert(view.VisibleChars, view.Markdown, msg)
	if remain >= presentAlertRemainMax {
		return "", false
	}
	return msg, true
}

func pickAlertMessage(raw string) string {
	var preferred, first string
	preferredDist := int(^uint(0) >> 1)
	for _, m := range scriptBlockRe.FindAllStringSubmatch(raw, -1) {
		body := m[1]
		if len(body) > presentMaxScriptForAlert {
			continue
		}
		locs := locationRe.FindAllStringIndex(body, -1)
		for _, am := range alertCallRe.FindAllStringSubmatchIndex(body, -1) {
			text := unescapeAlertText(alertTextAt(body, am))
			if strings.TrimSpace(text) == "" {
				continue
			}
			if first == "" {
				first = text
			}
			if len(locs) == 0 {
				continue
			}
			dist := alertLocationDist(am[0], am[1], locs)
			if preferred == "" || dist < preferredDist {
				preferred = text
				preferredDist = dist
			}
		}
	}
	return firstNonEmpty(preferred, first)
}

func alertTextAt(body string, am []int) string {
	for g := 1; g <= 3; g++ {
		lo, hi := am[g*2], am[g*2+1]
		if lo >= 0 && hi >= lo && hi <= len(body) {
			return body[lo:hi]
		}
	}
	return ""
}

func alertLocationDist(start, end int, locs [][]int) int {
	best := int(^uint(0) >> 1)
	for _, loc := range locs {
		var d int
		if end <= loc[0] {
			d = loc[0] - end
		} else if loc[1] <= start {
			d = start - loc[1]
		} else {
			d = 0
		}
		if d < best {
			best = d
		}
	}
	return best
}

func unescapeAlertText(s string) string {
	s = strings.NewReplacer(
		`\n`, "\n",
		`\r`, "\r",
		`\t`, "\t",
		`\'`, "'",
		`\"`, `"`,
		"\\`", "`",
		`\\`, `\`,
	).Replace(s)
	return strings.TrimSpace(html.UnescapeString(s))
}

func remainingVisibleAfterAlert(visible int, md, alert string) int {
	if strings.TrimSpace(alert) == "" {
		return visible
	}
	// Same visible-character definition as the empty-page fallback.
	// Link URLs are not content; a long href must not hide a real alert,
	// and 80 or more remaining characters are never a failure.
	stripped := strings.ReplaceAll(md, alert, "")
	n := countVisibleMarkdown(stripped)
	if n >= presentAlertRemainMax {
		return n
	}
	plain := strings.TrimSpace(regexp.MustCompile(`[#*_\x60[\]()|>-]+`).ReplaceAllString(stripped, " "))
	plain = strings.Join(strings.Fields(plain), "")
	if plain == "" || redirectNoise.MatchString(plain) {
		return 0
	}
	return n
}

// ---------- JSON business failure ----------

var (
	jsonSuccessCodes = map[string]bool{
		"0": true, "00": true, "0000": true, "000000": true,
		"200": true, "204": true,
		"ok": true, "success": true, "succ": true, "succeed": true, "succeeded": true,
		"true": true,
	}
	jsonFailStrings = map[string]bool{
		"fail": true, "failed": true, "failure": true,
		"error": true, "err": true, "no": true, "false": true,
	}
	jsonEnterpriseCodeRe = regexp.MustCompile(`^[A-Za-z]{2,}[A-Za-z0-9_-]*[0-9]{4,}$`)
	jsonMsgKeys          = []string{"message", "msg", "errMsg", "errmsg", "errorMessage", "error_message", "error"}
	jsonCodeKeys         = []string{"code", "errcode", "errorCode", "errCode"}
)

func detectJSONBusinessFailure(raw string) (string, bool) {
	trim := strings.TrimSpace(strings.TrimPrefix(raw, "\ufeff"))
	var v any
	if err := json.Unmarshal([]byte(trim), &v); err != nil {
		return "", false
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return "", false
	}
	suc, hasSuc := jsonBoolField(obj, "success")
	okv, hasOK := jsonBoolField(obj, "ok")
	if (hasSuc && suc) || (hasOK && okv) {
		return "", false
	}
	if (hasSuc && !suc) || (hasOK && !okv) {
		return formatBusinessFailure(jsonMessage(obj), jsonCodeString(obj), raw), true
	}

	codeVal, codeKey := jsonFirstCode(obj)
	statusVal, hasStatus := obj["status"]
	if codeKey == "" && hasStatus {
		if s, isStr := jsonStringish(statusVal); isStr && isFailString(s) {
			codeVal = s
			codeKey = "status"
		}
	}
	if codeKey == "" {
		return "", false
	}
	if isSuccessCode(codeVal) {
		return "", false
	}
	msg := jsonMessage(obj)
	if s, isStr := jsonStringish(codeVal); isStr {
		if isFailString(s) || isFailPrefix(s) || jsonEnterpriseCodeRe.MatchString(s) {
			return formatBusinessFailure(msg, s, raw), true
		}
		// Numeric strings such as "500" fall through to the integer rule.
	}
	if n, isInt := jsonIntish(codeVal); isInt {
		if (n < 0 || (n >= 400 && n <= 599)) && strings.TrimSpace(msg) != "" {
			return formatBusinessFailure(msg, strconv.FormatInt(n, 10), raw), true
		}
	}
	return "", false
}

func formatBusinessFailure(msg, code, raw string) string {
	text := strings.TrimSpace(msg)
	if text == "" {
		text = strings.TrimSpace(code)
	}
	if text == "" {
		return "业务失败\n" + raw
	}
	return "业务失败：" + text + "\n" + raw
}

func jsonBoolField(obj map[string]any, key string) (value, ok bool) {
	v, exists := obj[key]
	if !exists || v == nil {
		return false, false
	}
	b, is := v.(bool)
	if !is {
		return false, false
	}
	return b, true
}

func jsonMessage(obj map[string]any) string {
	for _, k := range jsonMsgKeys {
		v, ok := obj[k]
		if !ok || v == nil {
			continue
		}
		if s, is := v.(string); is && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}

func jsonFirstCode(obj map[string]any) (any, string) {
	for _, k := range jsonCodeKeys {
		if v, ok := obj[k]; ok && v != nil {
			return v, k
		}
	}
	return nil, ""
}

func jsonCodeString(obj map[string]any) string {
	v, key := jsonFirstCode(obj)
	if key == "" {
		return ""
	}
	if s, ok := jsonStringish(v); ok {
		return s
	}
	if n, ok := jsonIntish(v); ok {
		return strconv.FormatInt(n, 10)
	}
	return strings.TrimSpace(argString(v))
}

func jsonStringish(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return s, true
}

func jsonIntish(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		if n == float64(int64(n)) {
			return int64(n), true
		}
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	case int:
		return int64(n), true
	case int64:
		return n, true
	case string:
		if i, err := strconv.ParseInt(strings.TrimSpace(n), 10, 64); err == nil {
			return i, true
		}
	}
	return 0, false
}

func isSuccessCode(v any) bool {
	if s, ok := jsonStringish(v); ok {
		return jsonSuccessCodes[strings.ToLower(strings.TrimSpace(s))]
	}
	if n, ok := jsonIntish(v); ok {
		return n == 0 || n == 200 || n == 204
	}
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func isFailString(s string) bool {
	return jsonFailStrings[strings.ToLower(strings.TrimSpace(s))]
}

func isFailPrefix(s string) bool {
	u := strings.ToUpper(strings.TrimSpace(s))
	return strings.HasPrefix(u, "ERR") || strings.HasPrefix(u, "FAIL") || strings.HasPrefix(u, "ERROR")
}

// ---------- annotations ----------

func applyWritePrefix(desc string) string {
	desc = strings.TrimSpace(desc)
	if strings.HasPrefix(desc, writeOpPrefix) {
		return desc
	}
	if desc == "" {
		return writeOpPrefix
	}
	return writeOpPrefix + " " + desc
}

// toolOpKind reports whether a recorded (or WS) tool is a write, plus MCP annotations.
func toolOpKind(t *Tool) (write bool, ann map[string]any) {
	method := ""
	if t != nil {
		method = strings.ToUpper(strings.TrimSpace(t.Method))
	}
	write = isWriteMethod(method)
	if t != nil && t.Config.sqlGuardEnabled() {
		write = false
	}
	if t != nil {
		switch t.Config.opKind() {
		case opKindRead:
			write = false
		case opKindWrite:
			write = true
		}
	}
	ann = map[string]any{
		"readOnlyHint":    !write,
		"destructiveHint": false,
		"idempotentHint":  !write,
	}
	if write {
		ann["idempotentHint"] = method == "PUT" || method == "DELETE"
		ann["destructiveHint"] = method == "DELETE"
		if isWSMethod(method) {
			ann["idempotentHint"] = false
			ann["destructiveHint"] = false
		}
	}
	return write, ann
}

func mwToolAnnotations(name string) (write bool, destructive, idempotent bool) {
	switch name {
	case "db_list_tables", "db_describe_table", "redis_scan",
		"mq_peek", "mq_list_topics", "pod_read_log", wsSQLQueryTool:
		return false, false, true
	case "db_query":
		return true, true, false
	case "redis_command":
		return true, true, false
	case "mq_send":
		return true, false, false
	case "mq_create_topic":
		return true, true, false
	case "pod_exec":
		return true, true, false
	default:
		return false, false, false
	}
}

func mcpAnnotations(readOnly, destructive, idempotent bool) map[string]any {
	return map[string]any{
		"readOnlyHint":    readOnly,
		"destructiveHint": destructive,
		"idempotentHint":  idempotent,
	}
}
