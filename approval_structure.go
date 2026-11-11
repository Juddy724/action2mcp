package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"strings"
)

const (
	maxApprovalDepth          = 64
	maxApprovalContainerBytes = maxApprovalArgs
	maxApprovalJSONTokens     = 16 * 1024
	maxApprovalWalkBytes      = 4 * 1024 * 1024
)

var errApprovalStructureLimit = errors.New("approval structure limit")

// Keep the JSON token stream's members, including duplicates. Decoding objects
// into maps before examining their keys would lose security-relevant values.
type approvalJSONField struct {
	key   string
	value *approvalJSON
}

type approvalJSON struct {
	kind   json.Delim
	fields []approvalJSONField
	items  []*approvalJSON
	scalar any
}

func parseApprovalJSON(text string) (*approvalJSON, error) {
	if len(text) > maxApprovalContainerBytes {
		return nil, errApprovalStructureLimit
	}
	d := json.NewDecoder(strings.NewReader(quoteApprovalReferences(text)))
	d.UseNumber()
	tokens := 0
	next := func() (json.Token, error) {
		tokens++
		if tokens > maxApprovalJSONTokens {
			return nil, errApprovalStructureLimit
		}
		return d.Token()
	}
	var read func(int) (*approvalJSON, error)
	read = func(depth int) (*approvalJSON, error) {
		if depth > maxApprovalDepth {
			return nil, errApprovalStructureLimit
		}
		token, err := next()
		if err != nil {
			return nil, err
		}
		node := &approvalJSON{scalar: token}
		delim, composite := token.(json.Delim)
		if !composite {
			return node, nil
		}
		node.kind = delim
		switch delim {
		case '{':
			for d.More() {
				key, err := next()
				name, ok := key.(string)
				if err != nil {
					return nil, err
				}
				if !ok {
					return nil, errors.New("invalid approval JSON key")
				}
				value, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				node.fields = append(node.fields, approvalJSONField{name, value})
			}
		case '[':
			for d.More() {
				value, err := read(depth + 1)
				if err != nil {
					return nil, err
				}
				node.items = append(node.items, value)
			}
		default:
			return nil, errors.New("invalid approval JSON delimiter")
		}
		end, err := next()
		if err != nil {
			return nil, err
		}
		if delim == '{' && end != json.Delim('}') || delim == '[' && end != json.Delim(']') {
			return nil, errors.New("invalid approval JSON end")
		}
		return node, nil
	}
	node, err := read(0)
	if err != nil {
		return nil, err
	}
	if _, err := next(); err != io.EOF {
		if err == nil {
			err = errors.New("trailing approval JSON")
		}
		return nil, err
	}
	return node, nil
}

// Legacy templates allow unquoted reference tokens. Normalize just those tokens
// for analysis and display; execution keeps its original rendering rules.
func quoteApprovalReferences(text string) string {
	var out strings.Builder
	for i := 0; i < len(text); {
		if text[i] == '"' {
			_, end := approvalTemplateToken(text, i)
			out.WriteString(text[i:end])
			i = end
			continue
		}
		if strings.HasPrefix(text[i:], "{{") {
			if loc := placeholderRe.FindStringIndex(text[i:]); loc != nil && loc[0] == 0 {
				out.Write(compactJSON(text[i : i+loc[1]]))
				i += loc[1]
				continue
			}
		}
		out.WriteByte(text[i])
		i++
	}
	return out.String()
}

type approvalTemplateAnalysis struct {
	params                  map[string]bool
	values                  []string
	template                bool
	limitedHeaders          map[string]bool
	limitedURL, limitedBody bool
}

func (a *approvalTemplateAnalysis) references(text string) {
	if a == nil {
		return
	}
	for {
		m := placeholderRe.FindStringSubmatchIndex(text)
		if m == nil {
			break
		}
		a.params[text[m[2]:m[3]]] = true
		text = text[m[1]:]
	}
}

func (a *approvalTemplateAnalysis) literal(value string) {
	if a == nil || value == "" || value == secretMask || a.template && placeholderRe.MatchString(value) {
		return
	}
	a.values = append(a.values, value)
	if prefix, tail, ok := strings.Cut(value, " "); ok && strings.EqualFold(prefix, "Bearer") {
		a.values = append(a.values, strings.TrimSpace(tail))
	}
}

// Static portions of a sensitive scalar remain confidential when it also
// contains substitutions. Container grammar has already been handled by the walk.
func (a *approvalTemplateAnalysis) literalParts(value string) {
	if a == nil || !a.template || !placeholderRe.MatchString(value) {
		a.literal(value)
		return
	}
	for _, part := range placeholderRe.Split(value, -1) {
		if strings.TrimSpace(part) != "" && !strings.EqualFold(strings.TrimSpace(part), "Bearer") {
			a.literal(part)
		}
	}
}

func analyzeApprovalTemplate(t *Tool) *approvalTemplateAnalysis {
	a := &approvalTemplateAnalysis{params: map[string]bool{}, template: true, limitedHeaders: map[string]bool{}}
	r := approvalPreviewRedactor{scrub: func(s string) string { return s }, analysis: a}
	for key, value := range t.Headers {
		// Headers are opaque to the target: every substitution is confidential,
		// independently of the header's name or the value's inner grammar.
		a.references(value)
		r.budget = &approvalWalkBudget{}
		r.container(value, isSensitiveKey(key) || IsCredHeader(key), true, 0)
		a.limitedHeaders[key] = r.budget.failed
		if r.budget.failed {
			a.collectLimitedSecrets(value)
		}
	}
	r.budget = &approvalWalkBudget{}
	r.url(t.URL, false, 0)
	a.limitedURL = r.budget.failed
	if a.limitedURL {
		a.collectLimitedSecrets(t.URL)
	}
	r.budget = &approvalWalkBudget{}
	r.body(t.Body, headerGet(t.Headers, "Content-Type"))
	a.limitedBody = r.budget.failed
	if a.limitedBody {
		a.collectLimitedSecrets(t.Body)
	}
	return a
}

// When structured analysis hits a resource limit, still collect literals that
// could be sensitive so AI-facing outputs can be scrubbed. The scan is linear
// and non-recursive: values following sensitive keys first; if that scan cannot
// finish, every quoted or form literal in the container is treated as secret.
func (a *approvalTemplateAnalysis) collectLimitedSecrets(text string) {
	if a == nil || text == "" {
		return
	}
	if len(text) > maxApprovalContainerBytes {
		text = text[:maxApprovalContainerBytes]
	}
	values, complete := scanApprovalSensitiveLiterals(text)
	if !complete {
		values = scanApprovalAllLiterals(text)
	}
	for _, value := range values {
		if value == "" {
			continue
		}
		a.literal(value)
		if decoded, err := url.QueryUnescape(value); err == nil && decoded != value {
			a.literal(decoded)
		}
		if decoded, err := url.PathUnescape(value); err == nil && decoded != value {
			a.literal(decoded)
		}
	}
}

func scanApprovalUserinfo(text string) []string {
	var values []string
	for _, raw := range approvalEmbeddedURLRe.FindAllString(text, -1) {
		scheme, rest, ok := strings.Cut(strings.TrimSpace(raw), "://")
		if !ok || scheme == "" {
			continue
		}
		end := strings.IndexAny(rest, "/?#")
		if end < 0 {
			end = len(rest)
		}
		at := strings.LastIndexByte(rest[:end], '@')
		if at < 0 {
			continue
		}
		_, password, hasPassword := strings.Cut(rest[:at], ":")
		if !hasPassword || password == "" {
			continue
		}
		values = append(values, password)
	}
	return values
}

func skipApprovalSpace(text string, i int) int {
	for i < len(text) && (text[i] == ' ' || text[i] == '\t' || text[i] == '\n' || text[i] == '\r') {
		i++
	}
	return i
}

func readApprovalQuoted(text string, i int) (string, int, bool) {
	if i >= len(text) || (text[i] != '"' && text[i] != '\'') {
		return "", i, false
	}
	quote := text[i]
	end := i + 1
	for end < len(text) {
		if text[end] == '\\' {
			if end+1 >= len(text) {
				return "", i, false
			}
			end += 2
			continue
		}
		if text[end] == quote {
			end++
			if quote == '"' {
				var value string
				if json.Unmarshal([]byte(text[i:end]), &value) != nil {
					return "", i, false
				}
				return value, end, true
			}
			return text[i+1 : end-1], end, true
		}
		end++
	}
	return "", i, false
}

func readApprovalScalar(text string, i int) (string, int, bool) {
	i = skipApprovalSpace(text, i)
	if i >= len(text) {
		return "", i, false
	}
	if text[i] == '{' || text[i] == '[' {
		return "", i, false
	}
	if text[i] == '"' || text[i] == '\'' {
		return readApprovalQuoted(text, i)
	}
	end := i
	for end < len(text) && !strings.ContainsRune(",}&]# \t\r\n", rune(text[end])) {
		end++
	}
	if end == i {
		return "", i, false
	}
	return text[i:end], end, true
}

func readApprovalBareKey(text string, i int) (string, int) {
	if i >= len(text) || !isApprovalKeyByte(text[i]) {
		return "", i
	}
	end := i + 1
	for end < len(text) && isApprovalKeyByte(text[end]) {
		end++
	}
	return text[i:end], end
}

func isApprovalKeyByte(b byte) bool {
	return b == '_' || b == '-' || b == '.' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9'
}

func scanApprovalSensitiveLiterals(text string) ([]string, bool) {
	values := scanApprovalUserinfo(text)
	work := 0
	i := 0
	for i < len(text) {
		work++
		if work > maxApprovalWalkBytes {
			return values, false
		}
		if text[i] == '"' || text[i] == '\'' {
			key, end, ok := readApprovalQuoted(text, i)
			if !ok {
				return values, false
			}
			j := skipApprovalSpace(text, end)
			if j < len(text) && (text[j] == ':' || text[j] == '=') {
				value, vend, vok := readApprovalScalar(text, j+1)
				if vok && isSensitiveKey(key) {
					values = append(values, value)
				}
				if vok {
					i = vend
					continue
				}
			}
			i = end
			continue
		}
		if key, end := readApprovalBareKey(text, i); end > i {
			j := skipApprovalSpace(text, end)
			if j < len(text) && (text[j] == '=' || text[j] == ':') {
				if j+2 < len(text) && text[j] == ':' && text[j+1] == '/' && text[j+2] == '/' {
					i = j
					continue
				}
				value, vend, vok := readApprovalScalar(text, j+1)
				if vok && isSensitiveKey(key) {
					values = append(values, value)
				}
				if vok {
					i = vend
					continue
				}
			}
			i = end
			continue
		}
		i++
	}
	return values, true
}

func scanApprovalAllLiterals(text string) []string {
	values := scanApprovalUserinfo(text)
	i := 0
	for i < len(text) {
		if text[i] == '"' || text[i] == '\'' {
			value, end, ok := readApprovalQuoted(text, i)
			if !ok {
				break
			}
			if value != "" {
				values = append(values, value)
			}
			i = end
			continue
		}
		if _, end := readApprovalBareKey(text, i); end > i {
			j := skipApprovalSpace(text, end)
			if j < len(text) && text[j] == '=' {
				value, vend, vok := readApprovalScalar(text, j+1)
				if vok {
					if value != "" {
						values = append(values, value)
					}
					i = vend
					continue
				}
			}
			i = end
			continue
		}
		i++
	}
	return values
}
