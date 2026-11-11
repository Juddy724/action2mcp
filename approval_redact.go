package main

import (
	"encoding/base64"
	"encoding/json"
	"html"
	"net/url"
	"sort"
	"strings"
	"unicode"
)

func containsParam(s, name string) bool {
	for _, m := range placeholderRe.FindAllStringSubmatch(s, -1) {
		if m[1] == name {
			return true
		}
	}
	return false
}

func secretJSONParam(v any, name string, sensitive bool, depth int) bool {
	if depth > 16 {
		return false
	}
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if secretJSONParam(val, name, sensitive || isSensitiveKey(k), depth+1) {
				return true
			}
		}
	case []any:
		for _, val := range x {
			if secretJSONParam(val, name, sensitive, depth+1) {
				return true
			}
		}
	case string:
		if sensitive && containsParam(x, name) {
			return true
		}
		if _, tail, ok := splitCommandJSON(x); ok {
			x = tail
		}
		if inner, err := parseRecJSON(x); err == nil {
			return secretJSONParam(inner, name, sensitive, depth+1)
		}
		if trimmed := strings.TrimSpace(x); strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
			return secretTemplateParam(x, name, depth+1)
		}
	}
	return false
}

// Legacy templates may put placeholders outside JSON strings. Quote only those
// lexical tokens for the JSON walk; quoted values and their contents stay intact.
func secretTemplateParam(text, name string, depth int) bool {
	if depth > 16 {
		return false
	}
	var normalized strings.Builder
	quoted, escaped, changed := false, false, false
	for i := 0; i < len(text); i++ {
		c := text[i]
		if !quoted && strings.HasPrefix(text[i:], "{{") {
			if loc := placeholderRe.FindStringIndex(text[i:]); loc != nil && loc[0] == 0 {
				normalized.Write(compactJSON(text[i : i+loc[1]]))
				i += loc[1] - 1
				changed = true
				continue
			}
		}
		normalized.WriteByte(c)
		if escaped {
			escaped = false
		} else if quoted && c == '\\' {
			escaped = true
		} else if c == '"' {
			quoted = !quoted
		}
	}
	if changed {
		if body, err := parseRecJSON(normalized.String()); err == nil {
			return secretJSONParam(body, name, false, depth+1)
		}
	}
	// JSON-like assignments and form/query text: recognize keys only at entry
	// boundaries, skipping complete quoted tokens so key-like text in a value
	// (e.g. {"note":"password={{label}}"}) is never treated as a key.
	entry := true
	for i := 0; i < len(text); {
		c := text[i]
		if unicode.IsSpace(rune(c)) {
			i++
			continue
		}
		if strings.ContainsRune("{,?&;", rune(c)) {
			entry = true
			i++
			continue
		}
		token, end := approvalTemplateToken(text, i)
		j := end
		for j < len(text) && unicode.IsSpace(rune(text[j])) {
			j++
		}
		if entry && isSensitiveKey(token) && j < len(text) && (text[j] == ':' || text[j] == '=') {
			j++
			for j < len(text) && unicode.IsSpace(rune(text[j])) {
				j++
			}
			value := text[j:]
			if j < len(text) && (text[j] == '"' || text[j] == '\'') {
				value, _ = approvalTemplateToken(text, j)
			} else if stop := strings.IndexAny(value, ",&;\r\n"); stop >= 0 {
				value = value[:stop]
			}
			if containsParam(value, name) {
				return true
			}
		}
		entry, i = false, end
	}
	return false
}

func approvalTemplateToken(text string, start int) (string, int) {
	end := start + 1
	if text[start] == '"' || text[start] == '\'' {
		quote := text[start]
		for end < len(text) {
			if text[end] == '\\' {
				end += 2
				continue
			}
			if text[end] == quote {
				end++
				break
			}
			end++
		}
		if end > len(text) {
			end = len(text)
		}
		var value string
		if json.Unmarshal([]byte(text[start:end]), &value) == nil {
			return value, end
		}
		return strings.Trim(text[start:end], string(quote)), end
	}
	for end < len(text) && !strings.ContainsRune("{}[],:=&?; \t\r\n\"'", rune(text[end])) {
		end++
	}
	return text[start:end], end
}

func paramIsSecret(t *Tool, p Param) bool {
	if p.Secret || isSensitiveKey(p.Name) || strings.Contains(p.Description, removedSecretDesc) {
		return true
	}
	for key, value := range t.Headers {
		if (isSensitiveKey(key) || IsCredHeader(key)) && containsParam(value, p.Name) {
			return true
		}
	}
	if u, err := url.Parse(t.URL); err == nil {
		for key, values := range u.Query() {
			if isSensitiveKey(key) {
				for _, value := range values {
					if containsParam(value, p.Name) {
						return true
					}
				}
			}
		}
	}
	if body, err := parseRecJSON(t.Body); err == nil {
		return secretJSONParam(body, p.Name, false, 0)
	}
	for key, values := range tolerantForm(t.Body) {
		if isSensitiveKey(key) {
			for _, value := range values {
				if containsParam(value, p.Name) {
					return true
				}
			}
		}
	}
	return secretTemplateParam(t.Body, p.Name, 0)
}

func (a *App) paramIsSecret(t *Tool, p Param, values ...any) bool {
	if paramIsSecret(t, p) {
		return true
	}
	values = append(values, p.Default)
	for _, v := range values {
		if a.vault != nil && (a.vault.FindByValue(argString(v)) != "" || a.vault.FindByValue(argString(coerce(p, v))) != "") {
			return true
		}
	}
	return false
}

func (a *App) markSecretParams(t *Tool) {
	for i := range t.Params {
		if a.paramIsSecret(t, t.Params[i]) {
			t.Params[i].Secret = true
		}
	}
}

func (a *App) scrubApprovalText(s string, values []string) string {
	s = a.vault.Scrub(s)
	variants := map[string]bool{}
	for _, value := range values {
		if value == "" || value == secretMask {
			continue
		}
		variants[value] = true
		variants[url.QueryEscape(value)] = true
		variants[url.PathEscape(value)] = true
		variants[html.EscapeString(value)] = true
		variants[base64.StdEncoding.EncodeToString([]byte(value))] = true
		for i := 0; i < 9; i++ {
			b, _ := json.Marshal(value)
			value = string(b[1 : len(b)-1])
			variants[value] = true
		}
	}
	ordered := make([]string, 0, len(variants))
	for value := range variants {
		ordered = append(ordered, value)
	}
	sort.Slice(ordered, func(i, j int) bool { return len(ordered[i]) > len(ordered[j]) })
	for _, value := range ordered {
		s = strings.ReplaceAll(s, value, secretMask)
	}
	return s
}

func (a *App) approvalArgs(t *Tool, args map[string]any, secrets []string) map[string]string {
	params := map[string]Param{}
	for _, p := range t.Params {
		params[p.Name] = p
	}
	out := map[string]string{}
	for key, value := range args {
		p, ok := params[key]
		if !ok {
			p.Name = key
		}
		if a.paramIsSecret(t, p, value) {
			out[key] = secretMask
		} else {
			out[key] = a.scrubApprovalText(argString(value), secrets)
		}
	}
	return out
}

func (a *App) approvalSecretValues(t *Tool, args map[string]any) []string {
	params := map[string]Param{}
	for _, p := range t.Params {
		params[p.Name] = p
	}
	values := []string{}
	for key, value := range args {
		p := params[key]
		p.Name = key
		if a.paramIsSecret(t, p, value) {
			values = append(values, argString(value))
		}
	}
	return values
}

func (a *App) approvalParams(t *Tool, args map[string]any, secrets []string) []Param {
	params := append([]Param{}, t.Params...)
	for i := range params {
		p := &params[i]
		p.Secret = a.paramIsSecret(t, *p, args[p.Name])
		p.Description = a.scrubApprovalText(p.Description, secrets)
		if p.Secret {
			p.Default = ""
			p.Description = removedSecretDesc
		} else {
			p.Default = a.scrubApprovalText(p.Default, secrets)
		}
	}
	return params
}

func redactDisplayValue(value string) string {
	if isWholePlaceholder(value) || value == secretMask {
		return value
	}
	if strings.HasPrefix(value, "Bearer ") && isWholePlaceholder(strings.TrimPrefix(value, "Bearer ")) {
		return value
	}
	return secretMask
}

// Invalid JSON still needs redaction. Recognize assignments only at entry
// boundaries and skip quoted tokens so key-like text inside a value stays intact.
func redactPreviewAssignments(text string) string {
	var out strings.Builder
	last, entry := 0, true
	for i := 0; i < len(text); {
		c := text[i]
		if unicode.IsSpace(rune(c)) {
			i++
			continue
		}
		if strings.ContainsRune("{[,?&;", rune(c)) {
			entry = true
			i++
			continue
		}
		token, end := approvalTemplateToken(text, i)
		name := token
		if decoded, err := url.QueryUnescape(name); err == nil {
			name = decoded
		}
		j := end
		for j < len(text) && unicode.IsSpace(rune(text[j])) {
			j++
		}
		if !entry || !isSensitiveKey(name) || j == len(text) || (text[j] != ':' && text[j] != '=') {
			// A quoted string value that itself holds JSON-like text (escaped
			// JSON inside a JSON string): redact its assignments recursively.
			if text[i] == '"' && (j == len(text) || text[j] != ':') {
				if inner := strings.TrimSpace(token); strings.HasPrefix(inner, "{") || strings.HasPrefix(inner, "[") {
					if redacted := redactPreviewAssignments(token); redacted != token {
						out.WriteString(text[last:i])
						out.WriteString(string(compactJSON(redacted)))
						last = end
					}
				}
			}
			entry, i = false, end
			continue
		}
		separator := text[j]
		start := j + 1
		for start < len(text) && unicode.IsSpace(rune(text[start])) {
			start++
		}
		end = approvalTemplateValueEnd(text, start)
		value := strings.TrimSpace(text[start:end])
		end = start + len(strings.TrimRightFunc(text[start:end], unicode.IsSpace))
		quoted := start < len(text) && (text[start] == '"' || text[start] == '\'')
		if quoted {
			value, _ = approvalTemplateToken(text, start)
		} else if separator == '=' {
			if decoded, err := url.QueryUnescape(value); err == nil {
				value = decoded
			}
		}
		masked := redactDisplayValue(value)
		if quoted && text[start] == '\'' {
			masked = "'" + masked + "'"
		} else if quoted || separator == ':' {
			masked = string(compactJSON(masked))
		}
		out.WriteString(text[last:start])
		out.WriteString(masked)
		last, i, entry = end, end, false
	}
	out.WriteString(text[last:])
	return out.String()
}

func approvalTemplateValueEnd(text string, start int) int {
	if start < len(text) && (text[start] == '"' || text[start] == '\'') {
		_, end := approvalTemplateToken(text, start)
		return end
	}
	// Keep composite values (and {{references}}) together when replacing them.
	depth := 0
	for i := start; i < len(text); i++ {
		switch text[i] {
		case '"', '\'':
			_, end := approvalTemplateToken(text, i)
			i = end - 1
		case '{', '[':
			depth++
		case '}', ']':
			if depth == 0 {
				return i
			}
			depth--
		case ',', '&', ';', '\r', '\n':
			if depth == 0 {
				return i
			}
		}
	}
	return len(text)
}

func redactPreview(p RequestPreview) RequestPreview {
	for key, value := range p.Headers {
		if isSensitiveKey(key) || IsCredHeader(key) {
			p.Headers[key] = redactDisplayValue(value)
		}
	}
	// Preserve placeholder spelling and the original query's ordering.
	redactForm := func(raw string) string {
		parts := strings.Split(raw, "&")
		for i, part := range parts {
			key, value, ok := strings.Cut(part, "=")
			name, _ := url.QueryUnescape(key)
			decoded, _ := url.QueryUnescape(value)
			if ok && isSensitiveKey(name) {
				parts[i] = key + "=" + redactDisplayValue(decoded)
			}
		}
		return strings.Join(parts, "&")
	}
	if base, query, ok := strings.Cut(p.URL, "?"); ok {
		p.URL = base + "?" + redactForm(query)
	}
	var walk func(any, bool, int) any
	walk = func(v any, sensitive bool, depth int) any {
		if depth > 16 {
			return secretMask
		}
		switch x := v.(type) {
		case map[string]any:
			for key, value := range x {
				x[key] = walk(value, sensitive || isSensitiveKey(key), depth+1)
			}
		case []any:
			for i := range x {
				x[i] = walk(x[i], sensitive, depth+1)
			}
		case string:
			if sensitive {
				return redactDisplayValue(x)
			}
			prefix, tail, command := splitCommandJSON(x)
			if !command {
				tail = x
			}
			if inner, err := parseRecJSON(tail); err == nil {
				return prefix + string(compactJSON(walk(inner, false, depth+1)))
			}
			trimmed := strings.TrimSpace(tail)
			if command || strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
				return prefix + redactPreviewAssignments(tail)
			}
		default:
			if sensitive {
				return secretMask
			}
		}
		return v
	}
	if body, err := parseRecJSON(p.Body); err == nil {
		p.Body = string(compactJSON(walk(body, false, 0)))
	} else {
		if strings.Contains(strings.ToLower(headerGet(p.Headers, "Content-Type")), "x-www-form-urlencoded") {
			p.Body = redactForm(p.Body)
		}
		p.Body = redactPreviewAssignments(p.Body)
	}
	return p
}
