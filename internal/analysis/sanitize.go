package analysis

import (
	"action2mcp/internal/execution"
	"action2mcp/internal/vault"
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"regexp"
	"strings"
)

var cookieNameRe = regexp.MustCompile(`(?i)(sess|sid|token|auth|jwt|csrf|xsrf)`)

func cookieNameSensitive(name string) bool {
	return cookieNameRe.MatchString(name)
}

var jwtRe = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*`)

var bearerRe = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+([A-Za-z0-9._~+/=-]{4,})`)

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
	return jwtRe.ReplaceAllString(s, vault.Mask)
}

func maskBearer(s string) string {
	return bearerRe.ReplaceAllString(s, "${1} "+vault.Mask)
}

func formHasSensitive(s string) bool {
	if !strings.Contains(s, "=") || strings.ContainsAny(s, " \n\t{}<>") || strings.Contains(s, "://") || strings.ContainsAny(s, "?#") {
		return false
	}
	for k := range tolerantForm(s) {
		if execution.IsSensitiveKey(k) {
			return true
		}
	}
	return false
}

func structuredKind(s string) string {
	if _, _, ok := execution.SplitCommandJSON(s); ok {
		return "command"
	}
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		return "json"
	}
	return ""
}

func collectSecretsFromValue(v any, sensitive bool, depth int, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			collectSecretsFromValue(val, sensitive || execution.IsSensitiveKey(k), depth, out)
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
	if pre, tail, ok := execution.SplitCommandJSON(s); ok && pre != "" {
		if j, err := execution.ParseRecJSON(tail); err == nil {
			collectSecretsFromValue(j, false, depth+1, out)
			return
		}
	}
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, "{") || strings.HasPrefix(trimmed, "[") {
		if j, err := execution.ParseRecJSON(trimmed); err == nil {
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
			if execution.IsSensitiveKey(k) {
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
			if execution.IsSensitiveKey(k) {
				out[k] = vault.Mask
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

func onlyPlaceholders(s string) bool { return execution.IsWholePlaceholder(s) }

func (a *Service) maskFormString(s string, lits []string, depth int) string {
	if depth >= maxSanitizeDepth {
		return a.scrubRecText(maskBearer(maskJWT(s)), lits)
	}
	vals := tolerantForm(s)
	for k, vs := range vals {
		for i, v := range vs {
			if execution.IsSensitiveKey(k) && strings.TrimSpace(v) != "" {
				vs[i] = vault.Mask
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
func (a *Service) sanitizeValue(v any, sensitive bool, depth int, lits []string) any {
	if sensitive && v != nil {
		return vault.Mask
	}
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			if execution.IsSensitiveKey(k) {
				if val != nil {
					out[k] = vault.Mask
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
			return vault.Mask
		}
		return x
	default:
		return v
	}
}

// trySanitizeStructured returns sanitized JSON or a sanitized partial structure.
// ok is false when s looks structured but cannot be parsed even partially.
func (a *Service) trySanitizeStructured(s string, depth int, lits []string) (string, bool) {
	if depth >= maxSanitizeDepth {
		return "", false
	}
	render := func(body string) (string, bool) {
		if j, err := execution.ParseRecJSON(body); err == nil {
			return string(execution.CompactJSON(a.sanitizeValue(j, false, depth+1, lits))), true
		}
		j, ok := decodePartialJSON(body)
		if !ok || j == nil {
			return "", false
		}
		switch j.(type) {
		case map[string]any, []any:
			return string(execution.CompactJSON(a.sanitizeValue(j, false, depth+1, lits))), true
		default:
			return string(execution.CompactJSON(jsonOutline(j, 0))), true
		}
	}
	if pre, tail, ok := execution.SplitCommandJSON(s); ok {
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

func (a *Service) sanitizeString(s string, sensitive bool, depth int, lits []string) string {
	if sensitive {
		if strings.TrimSpace(s) == "" {
			return s
		}
		return vault.Mask
	}
	// Markers we already produced must survive a second pass. "[file omitted]"
	// starts with '[' and would otherwise be parsed as a broken JSON array.
	if s == structuredOmitted || s == omittedFileValue || s == vault.Mask {
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

// secretPlaceholder turns a sensitive leaf into an existing vault reference or a
// required parameter. It does not write the vault.
func (a *Service) secretPlaceholder(t *execution.Tool, path string, v any) string {
	raw := strings.TrimSpace(fmt.Sprint(v))
	if raw == "" || raw == vault.Mask || execution.IsWholePlaceholder(raw) {
		return raw
	}
	if a != nil && a.vault != nil {
		if ref := a.vault.FindByValue(raw); ref != "" && a.vault.TypeOf(ref) == "secret" {
			return "{{secret." + ref + "}}"
		}
	}
	return newRecSecretParam(t, path, v)
}

// revealsSecret reports whether sanitizing s would hide a credential. JSON
// whitespace alone does not count.
func (a *Service) revealsSecret(s string, lits []string) bool {
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
	return strings.Contains(safe, vault.Mask) || strings.Contains(safe, structuredOmitted)
}

func (a *Service) parameterizeRemainders(t *execution.Tool, s string, lits []string) string {
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
		if !execution.CrossFieldLiteral(lit) || seen[lit] {
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

func (a *Service) parameterizeJSONNode(t *execution.Tool, v any, sensitive bool, lits []string, depth int) any {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sortStrings(keys)
		for _, k := range keys {
			x[k] = a.parameterizeJSONNode(t, x[k], sensitive || execution.IsSensitiveKey(k), lits, depth)
		}
		return x
	case []any:
		for i := range x {
			x[i] = a.parameterizeJSONNode(t, x[i], sensitive, lits, depth)
		}
		return x
	case string:
		if sensitive && strings.TrimSpace(x) != "" && !execution.IsWholePlaceholder(x) {
			return a.secretPlaceholder(t, "value", x)
		}
		return a.parameterizeStringValue(t, x, lits, depth)
	default:
		if sensitive && v != nil {
			raw := fmt.Sprint(v)
			if raw != "" && !execution.IsWholePlaceholder(raw) {
				return newRecSecretParam(t, "value", v)
			}
		}
		return v
	}
}

func (a *Service) parameterizeStringValue(t *execution.Tool, s string, lits []string, depth int) string {
	if s == "" || onlyPlaceholders(s) || s == structuredOmitted || s == omittedFileValue || s == vault.Mask {
		return s
	}
	if structuredKind(s) != "" {
		if depth >= maxSanitizeDepth {
			return structuredOmitted
		}
		render := func(body string) (string, bool) {
			if j, err := execution.ParseRecJSON(body); err == nil {
				return string(execution.CompactJSON(a.parameterizeJSONNode(t, j, false, lits, depth+1))), true
			}
			j, ok := decodePartialJSON(body)
			if !ok || j == nil {
				return "", false
			}
			switch j.(type) {
			case map[string]any, []any:
				return string(execution.CompactJSON(a.parameterizeJSONNode(t, j, false, lits, depth+1))), true
			default:
				return structuredOmitted, true
			}
		}
		if pre, tail, ok := execution.SplitCommandJSON(s); ok {
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
				if execution.IsSensitiveKey(k) && strings.TrimSpace(v) != "" && !execution.IsWholePlaceholder(v) {
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
