package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"path"
	"regexp"
	"strings"
	"unicode"
)

// crossFieldLiteral reports whether a captured secret may be replaced wherever
// it appears. Short, boolean, numeric and version-like values are masked only
// in place, under a sensitive key, so they cannot chew up user agents or
// server-authored words such as create_pack=true.
func crossFieldLiteral(s string) bool {
	s = strings.TrimSpace(s)
	// A generated reference is only a value that is entirely placeholders.
	// Recorded text that merely contains "{{...}}" is still a secret.
	if len(s) < 6 || s == secretMask || isWholePlaceholder(s) {
		return false
	}
	switch strings.ToLower(s) {
	case "true", "false", "yes", "no", "on", "off":
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			goto notDigits
		}
	}
	return false
notDigits:
	for _, r := range s {
		if (r < '0' || r > '9') && r != '.' && r != ':' && r != '-' {
			return true
		}
	}
	return false
}

func sensitiveExcluded(low string, words []string) bool {
	if len(words) == 0 {
		return false
	}
	switch words[len(words)-1] {
	case "count", "length", "strength", "policy", "type", "hint":
		return true
	}
	switch strings.Join(words, "") {
	case "keeplogin", "rememberme", "editor", "expiresin", "login", "loginname", "account", "username":
		return true
	}
	switch low {
	case "keep_login", "remember_me", "expires_in", "login_name", "user_name":
		return true
	}
	return false
}

func splitKeyWords(s string) []string {
	var parts []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			parts = append(parts, strings.ToLower(string(cur)))
			cur = nil
		}
	}
	runes := []rune(s)
	var prev rune
	for i, r := range runes {
		if r == '_' || r == '-' || r == ' ' || r == '.' {
			flush()
			prev = 0
			continue
		}
		if unicode.IsUpper(r) && prev != 0 {
			// authToken: lower-to-upper. AUTHToken / HTTPResponse: acronym then a new word.
			if !unicode.IsUpper(prev) || (i+1 < len(runes) && unicode.IsLower(runes[i+1])) {
				flush()
			}
		}
		cur = append(cur, unicode.ToLower(r))
		prev = r
	}
	flush()
	return parts
}

func hasExclusionSuffix(joined string) bool {
	for _, suf := range []string{"count", "length", "strength", "policy", "type", "hint"} {
		if len(joined) > len(suf) && strings.HasSuffix(joined, suf) {
			return true
		}
	}
	return false
}

// isSensitiveKey matches the last path segment, case-insensitively, after
// splitting camelCase, snake_case and kebab-case into words.
func isSensitiveKey(k string) bool {
	seg := lastKey(strings.TrimSpace(k))
	seg = strings.Trim(seg, "\"'` ")
	if i := strings.IndexAny(seg, "[]"); i >= 0 {
		seg = seg[:i]
	}
	if seg == "" {
		return false
	}
	low := strings.ToLower(seg)
	words := splitKeyWords(seg)
	if len(words) == 0 || sensitiveExcluded(low, words) {
		return false
	}
	joined := strings.Join(words, "")
	// ACCESSTOKEN and PASSWORDSTRENGTH have no camel boundary. Match the
	// normalized compound, and keep exclusion suffixes case-insensitive.
	if hasExclusionSuffix(joined) {
		return false
	}
	switch joined {
	case "password", "passwd", "pwd", "passcode", "pass", "secret", "clientsecret",
		"token", "cookie", "setcookie", "authorization", "apikey", "xapikey",
		"session", "sessionid", "sid", "jsessionid", "csrf", "xsrf", "csrftoken", "xsrftoken",
		"bearer", "credential", "credentials", "jwt", "privatekey", "accesskey", "secretkey",
		"pin", "otp", "signature", "sign", "mima":
		return true
	}
	if words[len(words)-1] == "token" || strings.HasSuffix(joined, "token") {
		return true
	}
	for _, w := range words {
		switch w {
		case "password", "passwd", "pwd", "passcode", "secret", "cookie", "authorization",
			"session", "sessionid", "sid", "jsessionid", "csrf", "xsrf", "bearer",
			"credential", "credentials", "jwt", "otp", "signature", "mima":
			return true
		case "pass", "pin", "sign":
			if len(words) == 1 {
				return true
			}
		}
	}
	if strings.HasSuffix(joined, "apikey") || strings.Contains(joined, "privatekey") ||
		strings.HasSuffix(joined, "accesskey") || strings.HasSuffix(joined, "secretkey") {
		return true
	}
	return false
}

// pathSensitive is true when any segment of a dotted path is sensitive, so
// children such as credentials.value stay secret.
func pathSensitive(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	sens := false
	for _, part := range strings.FieldsFunc(p, func(r rune) bool { return r == '.' || r == '[' || r == ']' }) {
		if part == "" {
			continue
		}
		allNum := true
		for _, r := range part {
			if r < '0' || r > '9' {
				allNum = false
				break
			}
		}
		if allNum {
			continue
		}
		if isSensitiveKey(part) {
			sens = true
		}
	}
	return sens
}

var cookieNameRe = regexp.MustCompile(`(?i)(sess|sid|token|auth|jwt|csrf|xsrf)`)

func cookieNameSensitive(name string) bool {
	return cookieNameRe.MatchString(name)
}

var (
	commandJSONRe = regexp.MustCompile(`(?s)^(\s*[A-Za-z_][\w.:-]{0,40}\s+)([\[{].*)$`)
	jwtRe         = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)
	bearerRe      = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{4,})`)
	uuidPathRe    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	uuidSpanRe    = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	digitsPathRe  = regexp.MustCompile(`^[0-9]{3,}$`)
	hexPathRe     = regexp.MustCompile(`(?i)^[0-9a-f]{12,}$`)
)

func splitCommandJSON(s string) (prefix, tail string, ok bool) {
	m := commandJSONRe.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

const captureTruncMarker = "…[已截断]"
const maxSanitizeDepth = 6

// Structured text that cannot be fully parsed is replaced with this marker.
// Callers must never fall back to the original bytes.
const structuredOmitted = "[structured value omitted]"
const omittedFileValue = "[file omitted]"

func bodyWasTruncated(body string) bool {
	return strings.Contains(body, captureTruncMarker)
}

// cutAtTruncMarker drops the marker and everything after it. Capture stores the
// prefix plus the marker; text after the marker must not be shown raw.
func cutAtTruncMarker(s string) string {
	i := strings.Index(s, captureTruncMarker)
	if i < 0 {
		return s
	}
	if i > 0 && s[i-1] == '\n' {
		i--
	}
	return s[:i]
}

func maskJWT(s string) string {
	return jwtRe.ReplaceAllString(s, secretMask)
}

func maskBearer(s string) string {
	return bearerRe.ReplaceAllString(s, "${1} "+secretMask)
}

func formHasSensitive(s string) bool {
	if !strings.Contains(s, "=") || strings.ContainsAny(s, " \n\t{}<>") || strings.Contains(s, "://") || strings.ContainsAny(s, "?#") {
		return false
	}
	for k := range tolerantForm(s) {
		if isSensitiveKey(k) {
			return true
		}
	}
	return false
}

func (a *App) maskFormString(s string, lits []string, depth int) string {
	if depth >= maxSanitizeDepth {
		return a.scrubRecText(maskBearer(maskJWT(s)), lits)
	}
	vals := tolerantForm(s)
	for k, vs := range vals {
		for i, v := range vs {
			if isSensitiveKey(k) && strings.TrimSpace(v) != "" {
				vs[i] = secretMask
			} else {
				vs[i] = a.sanitizeString(v, false, depth+1, lits)
			}
		}
	}
	return encodeRecForm(vals)
}

// sanitizeValue walks a decoded JSON value. Sensitive keys become "******".
// String values that are themselves JSON, command-prefixed JSON, form bodies,
// bearer credentials or JWTs are sanitized too.
func (a *App) sanitizeValue(v any, sensitive bool, depth int, lits []string) any {
	if sensitive && v != nil {
		return secretMask
	}
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if isSensitiveKey(k) {
				if val != nil {
					out[k] = secretMask
				} else {
					out[k] = nil
				}
				continue
			}
			out[k] = a.sanitizeValue(val, false, depth, lits)
		}
		return out
	case []any:
		for i := range x {
			x[i] = a.sanitizeValue(x[i], false, depth, lits)
		}
		return x
	case string:
		return a.sanitizeString(x, false, depth, lits)
	case json.Number:
		if a.scrubRecText(x.String(), lits) != x.String() {
			return secretMask
		}
		return x
	default:
		return v
	}
}

func structuredKind(s string) string {
	if _, _, ok := splitCommandJSON(s); ok {
		return "command"
	}
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return "json"
	}
	return ""
}

// trySanitizeStructured returns sanitized JSON or a sanitized partial structure.
// ok is false when s looks structured but cannot be parsed even partially.
func (a *App) trySanitizeStructured(s string, depth int, lits []string) (string, bool) {
	if depth >= maxSanitizeDepth {
		return "", false
	}
	render := func(body string) (string, bool) {
		if j, err := parseRecJSON(body); err == nil {
			return string(compactJSON(a.sanitizeValue(j, false, depth+1, lits))), true
		}
		j, ok := decodePartialJSON(body)
		if !ok || j == nil {
			return "", false
		}
		switch j.(type) {
		case map[string]any, []any:
			return string(compactJSON(a.sanitizeValue(j, false, depth+1, lits))), true
		default:
			return string(compactJSON(jsonOutline(j, 0))), true
		}
	}
	if pre, tail, ok := splitCommandJSON(s); ok {
		safe, ok := render(tail)
		if !ok {
			return "", false
		}
		return pre + safe, true
	}
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return render(trimmed)
	}
	return "", false
}

func (a *App) sanitizeString(s string, sensitive bool, depth int, lits []string) string {
	if sensitive {
		if strings.TrimSpace(s) == "" {
			return s
		}
		return secretMask
	}
	// Markers we already produced must survive a second pass. "[file omitted]"
	// starts with '[' and would otherwise be parsed as a broken JSON array.
	if s == structuredOmitted || s == omittedFileValue || s == secretMask {
		return s
	}
	if kind := structuredKind(s); kind != "" {
		if safe, ok := a.trySanitizeStructured(s, depth, lits); ok {
			return safe
		}
		// Fail closed: never return unparsed JSON, command-prefixed JSON, or a
		// truncated fragment of either.
		return structuredOmitted
	}
	if formHasSensitive(s) {
		s = a.maskFormString(s, lits, depth)
	}
	s = maskBearer(maskJWT(s))
	return a.scrubRecText(s, lits)
}

func collectSecretsFromValue(v any, sensitive bool, depth int, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			collectSecretsFromValue(val, sensitive || isSensitiveKey(k), depth, out)
		}
	case []any:
		for _, val := range x {
			collectSecretsFromValue(val, sensitive, depth, out)
		}
	case string:
		if sensitive {
			addSecret(out, x)
		}
		if depth < maxSanitizeDepth {
			collectSecretsFromString(x, depth+1, out)
		}
	case json.Number:
		if sensitive {
			addSecret(out, x.String())
		}
	default:
		if sensitive && v != nil {
			s := fmt.Sprint(v)
			if s != "" && s != "true" && s != "false" {
				addSecret(out, s)
			}
		}
	}
}

func collectSecretsFromString(s string, depth int, out *[]string) {
	if depth >= maxSanitizeDepth {
		return
	}
	if pre, tail, ok := splitCommandJSON(s); ok && pre != "" {
		if j, err := parseRecJSON(tail); err == nil {
			collectSecretsFromValue(j, false, depth+1, out)
			return
		}
	}
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		if j, err := parseRecJSON(trimmed); err == nil {
			collectSecretsFromValue(j, false, depth+1, out)
			return
		}
		if j, ok := decodePartialJSON(s); ok {
			collectSecretsFromValue(j, false, depth+1, out)
		}
		return
	}
	if formHasSensitive(s) {
		for k, vs := range tolerantForm(s) {
			if isSensitiveKey(k) {
				for _, v := range vs {
					addSecret(out, v)
				}
			}
		}
	}
}

func decodePartialValue(d *json.Decoder) (any, error) {
	tok, err := d.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := tok.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				keyTok, err := d.Token()
				if err != nil {
					return m, err
				}
				key, ok := keyTok.(string)
				if !ok {
					return m, fmt.Errorf("invalid JSON key")
				}
				val, err := decodePartialValue(d)
				if err != nil {
					if val != nil {
						m[key] = val
					}
					return m, err
				}
				m[key] = val
			}
			_, err := d.Token()
			return m, err
		case '[':
			arr := []any{}
			for d.More() {
				val, err := decodePartialValue(d)
				if err != nil {
					if val != nil {
						arr = append(arr, val)
					}
					return arr, err
				}
				arr = append(arr, val)
			}
			_, err := d.Token()
			return arr, err
		default:
			return nil, fmt.Errorf("unexpected JSON delimiter")
		}
	}
	return tok, nil
}

func decodePartialJSON(body string) (any, bool) {
	body = cutAtTruncMarker(body)
	body = strings.TrimSpace(body)
	if body == "" {
		return nil, false
	}
	d := json.NewDecoder(strings.NewReader(body))
	d.UseNumber()
	v, err := decodePartialValue(d)
	if v == nil {
		return nil, false
	}
	if err == nil {
		var extra any
		if e := d.Decode(&extra); e == nil {
			// Trailing junk: still keep the value we decoded.
			return v, true
		}
	}
	return v, true
}

func jsonOutline(v any, depth int) any {
	if v == nil {
		return "null"
	}
	if depth >= 3 {
		return jsonKind(v)
	}
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		// stable order is not required; keep insertion via sort for tests
		sortStrings(keys)
		for _, k := range keys {
			if isSensitiveKey(k) {
				out[k] = secretMask
				continue
			}
			out[k] = jsonOutline(x[k], depth+1)
		}
		return out
	case []any:
		if len(x) == 0 {
			return []any{}
		}
		return []any{jsonOutline(x[0], depth+1)}
	default:
		return jsonKind(v)
	}
}

func jsonKind(v any) string {
	switch v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case json.Number:
		return "number"
	case float64:
		return "number"
	case bool:
		return "boolean"
	case string:
		return "string"
	case nil:
		return "null"
	default:
		return "string"
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		j := i
		for j > 0 && s[j] < s[j-1] {
			s[j], s[j-1] = s[j-1], s[j]
			j--
		}
	}
}

func isTemplatedID(part string) bool {
	if part == "" || part == "{id}" {
		return false
	}
	if digitsPathRe.MatchString(part) || uuidPathRe.MatchString(part) {
		return true
	}
	return len(part) >= 12 && hexPathRe.MatchString(part)
}

func templateSegment(seg string) (string, bool) {
	changed := false
	// A UUID spans separators. Replace the whole span before splitting, so
	// view-550e8400-e29b-41d4-a716-446655440000.html becomes view-{id}.html.
	seg = uuidSpanRe.ReplaceAllStringFunc(seg, func(string) string {
		changed = true
		return "{id}"
	})
	var b strings.Builder
	start := 0
	flush := func(end int, sep bool) {
		part := seg[start:end]
		if isTemplatedID(part) {
			b.WriteString("{id}")
			changed = true
		} else {
			b.WriteString(part)
		}
		if sep {
			b.WriteByte(seg[end])
		}
	}
	for i := 0; i <= len(seg); i++ {
		if i == len(seg) || seg[i] == '-' || seg[i] == '_' || seg[i] == '.' {
			flush(i, i < len(seg))
			start = i + 1
		}
	}
	if !changed {
		return seg, false
	}
	return b.String(), true
}

// templatePath rewrites id-like segments to {id}. The bool is true when the
// path changed.
func templatePath(p string) (string, bool) {
	if p == "" {
		return "/", false
	}
	segs := strings.Split(p, "/")
	changed := false
	for i, seg := range segs {
		if seg == "" {
			continue
		}
		ns, ch := templateSegment(seg)
		if ch {
			segs[i] = ns
			changed = true
		}
	}
	return strings.Join(segs, "/"), changed
}

func requestGroupKey(method, rawURL string) (host, templated, rawPath, key string) {
	host, rawPath = "", "/"
	if u, err := url.Parse(rawURL); err == nil && u != nil {
		host = strings.ToLower(u.Host)
		if u.Path != "" {
			rawPath = u.Path
		}
	}
	templated, _ = templatePath(rawPath)
	method = strings.ToUpper(strings.TrimSpace(method))
	key = method + "\n" + host + "\n" + templated
	return host, templated, rawPath, key
}

func isStaticAssetPath(p string) bool {
	low := strings.ToLower(p)
	return staticExt[path.Ext(low)] || strings.HasSuffix(low, "favicon.ico")
}

func isSuspectNoise(method, resource, pth, reason string, noise bool) bool {
	if !noise || reason == "跨域预检" || isStaticAssetPath(pth) {
		return false
	}
	m := strings.ToUpper(strings.TrimSpace(method))
	if m != "GET" && m != "HEAD" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(resource)) {
	case "xhr", "fetch":
		return true
	default:
		return false
	}
}

func reasonListed(list []string, reason string) bool {
	for _, r := range list {
		if r == reason {
			return true
		}
	}
	return false
}

func escapeQuotes(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

func rebuildMultipart(body, boundary string, repl map[string]string) (string, error) {
	parts, err := parseRecMultipart(body, boundary)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.SetBoundary(boundary); err != nil {
		return "", err
	}
	for _, p := range parts {
		val := p.value
		if v, ok := repl[p.name]; ok {
			val = v
		}
		h := make(textproto.MIMEHeader)
		disp := fmt.Sprintf(`form-data; name="%s"`, escapeQuotes(p.name))
		if p.filename != "" {
			disp += fmt.Sprintf(`; filename="%s"`, escapeQuotes(p.filename))
		}
		h.Set("Content-Disposition", disp)
		if p.contentType != "" {
			h.Set("Content-Type", p.contentType)
		}
		fw, err := w.CreatePart(h)
		if err != nil {
			return "", err
		}
		if _, err := ioWriteString(fw, val); err != nil {
			return "", err
		}
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func ioWriteString(w interface{ Write([]byte) (int, error) }, s string) (int, error) {
	return w.Write([]byte(s))
}

const removedSecretDesc = "敏感字段，录制到的值已移除，调用时另填。"

// secretPlaceholder turns a sensitive leaf into an existing vault reference or a
// required parameter. It does not write the vault.
func (a *App) secretPlaceholder(t *Tool, path string, v any) string {
	raw := strings.TrimSpace(fmt.Sprint(v))
	if raw == "" || raw == secretMask || isWholePlaceholder(raw) {
		return raw
	}
	if a != nil && a.vault != nil {
		if ref := a.vault.FindByValue(raw); ref != "" && a.vault.TypeOf(ref) == "secret" {
			return "{{secret." + ref + "}}"
		}
	}
	return newRecSecretParam(t, path, v)
}

// isWholePlaceholder reports a value we generated: the entire string is one or
// more {{references}} and nothing else. Recorded data that only contains a
// placeholder substring is not a reference.
func isWholePlaceholder(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" || !strings.Contains(t, "{{") {
		return false
	}
	return strings.TrimSpace(placeholderRe.ReplaceAllString(t, "")) == ""
}

func onlyPlaceholders(s string) bool { return isWholePlaceholder(s) }

// revealsSecret reports whether sanitizing s would hide a credential. JSON
// whitespace alone does not count.
func (a *App) revealsSecret(s string, lits []string) bool {
	if strings.TrimSpace(s) == "" {
		return false
	}
	if jwtRe.MatchString(s) || bearerRe.MatchString(s) {
		return true
	}
	if a.scrubRecText(s, lits) != s {
		return true
	}
	safe := a.sanitizeString(s, false, 0, lits)
	return strings.Contains(safe, secretMask) || strings.Contains(safe, structuredOmitted)
}

func (a *App) parameterizeRemainders(t *Tool, s string, lits []string) string {
	s = a.recTemplateText(s, nil)
	cp := append([]string(nil), lits...)
	sortStrings(cp)
	// longest first
	for i := 0; i < len(cp); i++ {
		for j := i + 1; j < len(cp); j++ {
			if len(cp[j]) > len(cp[i]) {
				cp[i], cp[j] = cp[j], cp[i]
			}
		}
	}
	seen := map[string]bool{}
	for _, lit := range cp {
		if !crossFieldLiteral(lit) || seen[lit] {
			continue
		}
		forms := literalForms(lit)
		outside := outsideRecRefs(s, func(part string) string { return part })
		found := false
		for _, form := range forms {
			if form != "" && (strings.Contains(outside, form) || strings.Contains(s, form)) {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		seen[lit] = true
		ph := a.secretPlaceholder(t, "value", lit)
		if strings.Contains(lit, "{{") {
			s = strings.ReplaceAll(s, lit, ph)
		}
		for _, form := range forms {
			form := form
			s = outsideRecRefs(s, func(part string) string {
				return replaceLiteral(part, form, ph, false)
			})
		}
	}
	return s
}

func (a *App) parameterizeJSONNode(t *Tool, v any, sensitive bool, lits []string, depth int) any {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, k := range keys {
			x[k] = a.parameterizeJSONNode(t, x[k], sensitive || isSensitiveKey(k), lits, depth)
		}
		return x
	case []any:
		for i := range x {
			x[i] = a.parameterizeJSONNode(t, x[i], sensitive, lits, depth)
		}
		return x
	case string:
		if sensitive && strings.TrimSpace(x) != "" && !isWholePlaceholder(x) {
			return a.secretPlaceholder(t, "value", x)
		}
		return a.parameterizeStringValue(t, x, lits, depth)
	default:
		if sensitive && v != nil {
			raw := fmt.Sprint(v)
			if raw != "" && !isWholePlaceholder(raw) {
				return newRecSecretParam(t, "value", v)
			}
		}
		return v
	}
}

func (a *App) parameterizeStringValue(t *Tool, s string, lits []string, depth int) string {
	if s == "" || onlyPlaceholders(s) || s == structuredOmitted || s == omittedFileValue || s == secretMask {
		return s
	}
	if structuredKind(s) != "" {
		if depth >= maxSanitizeDepth {
			return structuredOmitted
		}
		render := func(body string) (string, bool) {
			if j, err := parseRecJSON(body); err == nil {
				return string(compactJSON(a.parameterizeJSONNode(t, j, false, lits, depth+1))), true
			}
			j, ok := decodePartialJSON(body)
			if !ok || j == nil {
				return "", false
			}
			switch j.(type) {
			case map[string]any, []any:
				return string(compactJSON(a.parameterizeJSONNode(t, j, false, lits, depth+1))), true
			default:
				return structuredOmitted, true
			}
		}
		if pre, tail, ok := splitCommandJSON(s); ok {
			if safe, ok := render(tail); ok {
				return pre + safe
			}
			return pre + structuredOmitted
		}
		trimmed := strings.TrimSpace(s)
		if safe, ok := render(trimmed); ok {
			return safe
		}
		return structuredOmitted
	}
	if depth < maxSanitizeDepth && formHasSensitive(s) {
		vals := tolerantForm(s)
		for k, vs := range vals {
			for i, v := range vs {
				if isSensitiveKey(k) && strings.TrimSpace(v) != "" && !isWholePlaceholder(v) {
					vs[i] = a.secretPlaceholder(t, k, v)
				} else {
					vs[i] = a.parameterizeStringValue(t, v, lits, depth+1)
				}
			}
		}
		return encodeRecForm(vals)
	}
	s = jwtRe.ReplaceAllStringFunc(s, func(m string) string {
		return a.secretPlaceholder(t, "jwt", m)
	})
	s = bearerRe.ReplaceAllStringFunc(s, func(m string) string {
		sm := bearerRe.FindStringSubmatch(m)
		if len(sm) < 3 {
			return m
		}
		return sm[1] + " " + a.secretPlaceholder(t, "authorization", sm[2])
	})
	return a.parameterizeRemainders(t, s, lits)
}
