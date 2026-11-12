package main

import (
	"encoding/json"
	"errors"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

// Embedded JSON may follow a command or arbitrary display text. References are
// not JSON containers, even though their spelling also starts with a brace.
func splitApprovalJSON(text string) (prefix, tail string, ok bool) {
	for start := 0; start < len(text); {
		i := strings.IndexAny(text[start:], "{[")
		if i < 0 {
			break
		}
		i += start
		if strings.HasPrefix(text[i:], "{{") {
			if loc := placeholderRe.FindStringIndex(text[i:]); loc != nil && loc[0] == 0 {
				start = i + loc[1]
				continue
			}
		}
		return text[:i], text[i:], true
	}
	return "", "", false
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
	return p.Secret || isSensitiveKey(p.Name) || strings.Contains(p.Description, removedSecretDesc) || analyzeApprovalTemplate(t).params[p.Name]
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

func (a *App) approvalArgs(t *Tool, args map[string]any, _ []string) map[string]string {
	params := map[string]Param{}
	for _, p := range t.Params {
		params[p.Name] = p
	}
	out := map[string]string{}
	for key, value := range args {
		p := params[key]
		p.Name = key
		if a.paramIsSecret(t, p, value) {
			out[key] = secretMask
		} else {
			// The caller already knows public arguments. Show their exact text.
			out[key] = argString(value)
		}
	}
	return out
}

func (a *App) approvalSecretValues(t *Tool, args map[string]any) []string {
	analysis := analyzeApprovalTemplate(t)
	argAnalysis := &approvalTemplateAnalysis{params: map[string]bool{}}
	params := map[string]Param{}
	for _, p := range t.Params {
		params[p.Name] = p
	}
	for key, value := range args {
		p := params[key]
		p.Name = key
		if a.paramIsSecret(t, p, value) {
			argAnalysis.literal(argString(value))
		}
	}
	return append(analysis.values, argAnalysis.values...)
}

func (a *App) mcpToolSecrets(t *Tool) []string {
	secrets := a.approvalSecretValues(t, nil)
	for _, p := range t.Params {
		if paramIsSecret(t, p) && p.Default != "" && p.Default != "@today" {
			secrets = append(secrets, p.Default)
		}
	}
	return secrets
}

func (a *App) mcpInputSchema(t *Tool) map[string]any {
	schema := t.InputSchema()
	raw, err := json.Marshal(schema)
	if err != nil {
		return schema
	}
	var cleaned map[string]any
	if json.Unmarshal([]byte(a.scrubApprovalText(string(raw), a.mcpToolSecrets(t))), &cleaned) != nil || cleaned == nil {
		return schema
	}
	return cleaned
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

// This grammar analyzes raw templates, never caller-supplied argument text.
// Failed parses mark every reference in that container, even if lexical recovery
// can still produce a useful preview.
type approvalPreviewRedactor struct {
	scrub    func(string) string
	analysis *approvalTemplateAnalysis
	budget   *approvalWalkBudget
}

type approvalWalkBudget struct {
	bytes, nodes int
	failed       bool
}

// A budget is shared by every recursive grammar walk in a container. If any
// child exhausts it, all enclosing containers fail closed as well.
func (r approvalPreviewRedactor) enter(text string, depth int) (approvalPreviewRedactor, bool) {
	if r.budget == nil {
		r.budget = &approvalWalkBudget{}
	}
	r.budget.bytes += len(text)
	r.budget.nodes++
	if depth > maxApprovalDepth || len(text) > maxApprovalContainerBytes || r.budget.bytes > maxApprovalWalkBytes || r.budget.nodes > maxApprovalJSONTokens {
		r.budget.failed = true
	}
	if r.budget.failed {
		r.analysis.references(text)
		return r, false
	}
	return r, true
}

func (r approvalPreviewRedactor) finish(text string, result *string) {
	r.budget.bytes += len(*result)
	if len(*result) > maxApprovalContainerBytes || r.budget.bytes > maxApprovalWalkBytes {
		r.budget.failed = true
	}
	if r.budget.failed {
		r.analysis.references(text)
		*result = secretMask
	}
}

func (r approvalPreviewRedactor) container(text string, sensitive, allowForm bool, depth int) (result string) {
	r, ok := r.enter(text, depth)
	if !ok {
		return secretMask
	}
	defer r.finish(text, &result)
	if sensitive {
		r.analysis.references(text)
		r.analysis.literal(text)
	}
	if isWholePlaceholder(text) {
		if allowForm {
			r.analysis.references(text)
		}
		return r.scrub(text)
	}
	redacted := r.walkContainer(text, sensitive, allowForm, depth)
	if sensitive {
		return r.scrub(redactDisplayValue(text))
	}
	return redacted
}

func (r approvalPreviewRedactor) walkContainer(text string, sensitive, allowForm bool, depth int) string {
	if body, err := parseApprovalJSON(text); err == nil {
		return r.jsonValue(body, sensitive, depth+1)
	} else if errors.Is(err, errApprovalStructureLimit) {
		r.budget.failed = true
		r.analysis.references(text)
		return secretMask
	}
	trimmed := strings.TrimSpace(text)
	if strings.Contains(trimmed, "://") && !strings.ContainsAny(strings.SplitN(trimmed, "://", 2)[0], " \t\r\n\"'{[") {
		return r.url(text, sensitive, depth+1)
	}
	// A scalar value is not another assignment merely because it contains '='.
	// Explicit query syntax or '&' separates an embedded form from key-like prose.
	if allowForm || strings.HasPrefix(trimmed, "?") || strings.Contains(trimmed, "&") {
		raw := strings.TrimPrefix(trimmed, "?")
		if approvalLooksLikeForm(trimmed) {
			prefix := ""
			if strings.HasPrefix(trimmed, "?") {
				prefix = "?"
			}
			return prefix + r.form(raw, sensitive, depth+1)
		}
	}
	if prefix, tail, ok := splitApprovalJSON(text); ok {
		if prefix != "" {
			return r.container(prefix, sensitive, false, depth+1) + r.container(tail, sensitive, false, depth+1)
		}
		r.analysis.references(text)
		return r.assignments(text, sensitive, depth+1)
	}
	if decoded, err := url.QueryUnescape(text); err == nil && decoded != text {
		if redacted := r.container(decoded, sensitive, allowForm, depth+1); redacted != decoded {
			return url.QueryEscape(redacted)
		}
	} else if err != nil {
		r.analysis.references(text)
	}
	if allowForm {
		// An opaque body cannot prove that its substitutions are public. Plain
		// scalar values within parsed containers, however, have no inner keys.
		r.analysis.references(text)
	}
	if sensitive {
		r.analysis.literalParts(text)
	}
	return r.scrub(r.embeddedURLs(text, sensitive, depth+1))
}

// A base64 token's trailing '=' characters are padding, not an assignment.
func approvalLooksLikeForm(text string) bool {
	explicit := strings.HasPrefix(text, "?") || strings.Contains(text, "&")
	key, value, ok := strings.Cut(strings.TrimPrefix(text, "?"), "=")
	return ok && key != "" && !strings.ContainsAny(key, "{}[]:=&? \t\r\n\"'") && (explicit || strings.Trim(value, "=") != "")
}

func (r approvalPreviewRedactor) jsonValue(v *approvalJSON, sensitive bool, depth int) (result string) {
	r, ok := r.enter("", depth)
	if !ok {
		// Retain all references if embedded container traversal overflows.
		r.jsonReferences(v)
		return string(compactJSON(secretMask))
	}
	defer r.finish("", &result)
	var out strings.Builder
	switch v.kind {
	case '{':
		for _, field := range v.fields {
			if placeholderRe.MatchString(field.key) {
				r.jsonReferences(v)
				break
			}
		}
		out.WriteByte('{')
		for i, field := range v.fields {
			if i > 0 {
				out.WriteByte(',')
			}
			out.Write(compactJSON(field.key))
			out.WriteByte(':')
			out.WriteString(r.jsonValue(field.value, sensitive || isSensitiveKey(field.key), depth+1))
		}
		out.WriteByte('}')
	case '[':
		out.WriteByte('[')
		for i, value := range v.items {
			if i > 0 {
				out.WriteByte(',')
			}
			out.WriteString(r.jsonValue(value, sensitive, depth+1))
		}
		out.WriteByte(']')
	default:
		if text, ok := v.scalar.(string); ok {
			return string(compactJSON(r.container(text, sensitive, false, depth+1)))
		}
		text := string(compactJSON(v.scalar))
		if sensitive {
			r.analysis.literal(text)
		}
		if sensitive || r.scrub(text) != text {
			return string(compactJSON(secretMask))
		}
		return text
	}
	return out.String()
}

func (r approvalPreviewRedactor) jsonReferences(v *approvalJSON) {
	if r.analysis == nil {
		return
	}
	// The parser already bounded the tree. Visit it without recursively copying
	// every descendant's text into each ancestor.
	pending := []*approvalJSON{v}
	for len(pending) != 0 {
		node := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		for _, field := range node.fields {
			r.analysis.references(field.key)
			pending = append(pending, field.value)
		}
		pending = append(pending, node.items...)
		if s, ok := node.scalar.(string); ok {
			r.analysis.references(s)
		}
	}
}

// Invalid JSON still needs redaction. Keys are recognized only at entry
// boundaries; quoted tokens and complete assignment values are consumed at once.
func (r approvalPreviewRedactor) assignments(text string, sensitive bool, depth int) (result string) {
	r, ok := r.enter(text, depth)
	if !ok {
		return secretMask
	}
	defer r.finish(text, &result)
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
		if !entry || j == len(text) || (text[j] != ':' && text[j] != '=') {
			if c == '"' || c == '\'' {
				out.WriteString(r.scrub(text[last:i]))
				out.WriteString(approvalPreviewQuoted(text[i:end], token, r.container(token, sensitive, false, depth+1)))
				last = end
			}
			entry, i = false, end
			continue
		}
		separator := text[j]
		start := j + 1
		for start < len(text) && unicode.IsSpace(rune(text[start])) {
			start++
		}
		end = approvalTemplateValueEnd(text, start, separator)
		value := strings.TrimSpace(text[start:end])
		end = start + len(strings.TrimRightFunc(text[start:end], unicode.IsSpace))
		quoted := start < len(text) && (text[start] == '"' || text[start] == '\'')
		if quoted {
			value, _ = approvalTemplateToken(text, start)
		}
		secret := sensitive || isSensitiveKey(name)
		redacted := ""
		if secret {
			// For '=' the entire field belongs to the value, including any
			// suffix after a closing quote. Commas are never form delimiters.
			whole := text[start:end]
			if decoded, err := url.QueryUnescape(whole); separator == '=' && err == nil {
				whole = decoded
			}
			r.analysis.references(whole)
			r.analysis.literal(whole)
			r.container(value, true, false, depth+1)
			redacted = r.scrub(redactDisplayValue(value))
			if quoted && text[start] == '\'' {
				redacted = "'" + redacted + "'"
			} else if quoted || separator == ':' {
				redacted = string(compactJSON(redacted))
			}
		} else if quoted {
			redacted = approvalPreviewQuoted(text[start:end], value, r.container(value, false, false, depth+1))
		} else if separator == '=' {
			redacted = r.formValue(value, false, depth+1)
		} else {
			redacted = r.container(value, false, false, depth+1)
		}
		out.WriteString(r.scrub(text[last:i]))
		out.WriteString(text[i:start])
		out.WriteString(redacted)
		last, i, entry = end, end, false
	}
	out.WriteString(r.scrub(text[last:]))
	return out.String()
}

func approvalPreviewQuoted(raw, value, redacted string) string {
	if value == redacted {
		return raw
	}
	if strings.HasPrefix(raw, "'") {
		return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(redacted) + "'"
	}
	return string(compactJSON(redacted))
}

func approvalTemplateValueEnd(text string, start int, separator byte) int {
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
		case ',':
			if depth == 0 && separator == ':' {
				return i
			}
		case '&', ';', '\r', '\n':
			if depth == 0 {
				return i
			}
		}
	}
	return len(text)
}

func (r approvalPreviewRedactor) formValue(raw string, sensitive bool, depth int) (result string) {
	r, ok := r.enter(raw, depth)
	if !ok {
		return secretMask
	}
	defer r.finish(raw, &result)
	value := raw
	if decoded, err := url.QueryUnescape(raw); err == nil {
		value = decoded
	} else {
		r.analysis.references(raw)
	}
	redacted := r.container(value, sensitive, false, depth+1)
	if redacted != value {
		if sensitive {
			return redacted
		}
		return url.QueryEscape(redacted)
	}
	return r.scrub(raw)
}

// ParseQuery is used for validation, never u.Query (which silently drops invalid
// pairs). The display walk retains ordering, duplicates and original key spelling.
func (r approvalPreviewRedactor) form(raw string, sensitive bool, depth int) (result string) {
	r, ok := r.enter(raw, depth)
	if !ok {
		return secretMask
	}
	defer r.finish(raw, &result)
	if _, err := url.ParseQuery(raw); err != nil {
		r.analysis.references(raw)
	}
	parts := strings.Split(raw, "&")
	for i, part := range parts {
		key, value, ok := strings.Cut(part, "=")
		r.analysis.references(key)
		name, err := url.QueryUnescape(key)
		if ok {
			parts[i] = key + "=" + r.formValue(value, sensitive || err != nil || isSensitiveKey(name), depth+1)
		} else {
			parts[i] = r.container(part, sensitive, false, depth+1)
		}
	}
	return strings.Join(parts, "&")
}

func (r approvalPreviewRedactor) url(raw string, sensitive bool, depth int) (result string) {
	r, ok := r.enter(raw, depth)
	if !ok {
		return secretMask
	}
	defer r.finish(raw, &result)
	trimmed := strings.TrimSpace(raw)
	start := len(raw) - len(strings.TrimLeftFunc(raw, unicode.IsSpace))
	if _, err := url.Parse(trimmed); err != nil {
		r.analysis.references(trimmed)
	}
	main, fragment, hasFragment := strings.Cut(trimmed, "#")
	base, query, hasQuery := strings.Cut(main, "?")
	base = r.urlUserinfo(base)
	if u, err := url.Parse(base); err == nil {
		path := r.container(u.Path, sensitive, false, depth+1)
		if path != u.Path {
			u.Path, u.RawPath = path, ""
			base = u.String()
		}
	}
	result = r.scrub(base)
	if hasQuery {
		result += "?" + r.form(query, sensitive, depth+1)
	}
	if hasFragment {
		if strings.Contains(fragment, "?") {
			fragment = r.url(fragment, sensitive, depth+1)
		} else {
			fragment = r.container(fragment, sensitive, true, depth+1)
		}
		result += "#" + fragment
	}
	return raw[:start] + result + raw[start+len(trimmed):]
}

// Inspect the authority separately so template references in userinfo are
// confidential even when net/url rejects their unrendered braces.
func (r approvalPreviewRedactor) urlUserinfo(raw string) string {
	trimmed := strings.TrimSpace(raw)
	scheme, rest, ok := strings.Cut(trimmed, "://")
	// Inspect visible authorities even for schemes net/url does not accept.
	if !ok || scheme == "" || strings.ContainsAny(scheme, " \t\r\n\"'{[") {
		return raw
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority := rest[:end]
	at := strings.LastIndexByte(authority, '@')
	if at < 0 {
		return raw
	}
	user, password, hasPassword := strings.Cut(authority[:at], ":")
	r.analysis.references(user)
	if !hasPassword {
		return raw
	}
	r.analysis.references(password)
	r.analysis.literalParts(password)
	if decoded, err := url.PathUnescape(password); err == nil {
		r.analysis.references(decoded)
		r.analysis.literalParts(decoded)
	}
	start := len(raw) - len(strings.TrimLeftFunc(raw, unicode.IsSpace)) + len(scheme) + len("://") + len(user) + 1
	return raw[:start] + secretMask + raw[start+len(password):]
}

var approvalEmbeddedURLRe = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+._-]*://[^\s<>"']+`)

func (r approvalPreviewRedactor) embeddedURLs(text string, sensitive bool, depth int) string {
	return approvalEmbeddedURLRe.ReplaceAllStringFunc(text, func(raw string) string {
		return r.url(raw, sensitive, depth+1)
	})
}

func (r approvalPreviewRedactor) preview(p RequestPreview) RequestPreview {
	contentType := headerGet(p.Headers, "Content-Type")
	headers := make(map[string]string, len(p.Headers))
	for key, value := range p.Headers {
		headers[key] = r.container(value, isSensitiveKey(key) || IsCredHeader(key), true, 0)
	}
	p.Headers = headers
	p.URL = r.url(p.URL, false, 0)
	p.Body = r.body(p.Body, contentType)
	return p
}

func (r approvalPreviewRedactor) body(text, contentType string) string {
	// Legacy text/plain bodies also support semicolon-separated assignments.
	// Form/query containers always use '&', including when ParseQuery fails.
	if strings.Contains(strings.ToLower(contentType), "text/plain") {
		key, _, assignment := strings.Cut(text, "=")
		if assignment && !strings.ContainsAny(key, "{}[]:\"'") {
			if _, err := url.ParseQuery(text); err != nil {
				r.analysis.references(text)
				return r.assignments(text, false, 0)
			}
		}
	}
	return r.container(text, false, true, 0)
}

func redactPreview(p RequestPreview) RequestPreview {
	return (approvalPreviewRedactor{scrub: func(s string) string { return s }}).preview(p)
}

func redactPreviewAssignments(text string) string {
	return (approvalPreviewRedactor{scrub: func(s string) string { return s }}).assignments(text, false, 0)
}

func (a *App) scrubApprovalPreview(p RequestPreview, values []string) RequestPreview {
	// Rendered text is never parsed or reprinted. Known encodings are scrubbed
	// as substrings, including base64 followed by padding, punctuation or junk.
	return replaceRequest(p, func(text string) string {
		text = approvalEmbeddedURLRe.ReplaceAllStringFunc(text, (approvalPreviewRedactor{}).urlUserinfo)
		return a.scrubApprovalTextExplicit(text, values)
	})
}
