package main

import (
	"encoding/base64"
	"encoding/json"
	"html"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// A decoded byte keeps its source range. Matching decoded views avoids an
// exponential list of mixed percent/unicode encodings, and lets us replace just
// the secret in the original display without decoding surrounding user text.
type approvalTextSpan struct{ start, end int }

type approvalTextEncoding uint8

const (
	approvalPathEncoding approvalTextEncoding = iota
	approvalQueryEncoding
	approvalJSONEncoding
	approvalHTMLEncoding
)

func (a *App) scrubApprovalText(text string, values []string) string {
	var vault *Vault
	if a != nil {
		vault = a.vault
	}
	return scrubSecretText(text, vault, values)
}

func scrubSecretText(text string, vault *Vault, values []string) string {
	if text == "" {
		return text
	}
	if len(text) > maxApprovalContainerBytes {
		return secretMask
	}
	variants := map[string]bool{}
	addBase64 := func(value string) {
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			variants[encoding.EncodeToString([]byte(value))] = true
		}
	}
	if vault != nil {
		for _, value := range vault.secretVariants() {
			variants[value] = true
			addBase64(value)
		}
	}
	for _, value := range values {
		if value == "" || value == secretMask {
			continue
		}
		variants[value] = true
		variants[url.QueryEscape(value)] = true
		variants[url.PathEscape(value)] = true
		variants[html.EscapeString(value)] = true
		addBase64(value)
		for i := 0; i < 9; i++ {
			if len(value) > len(text) {
				break
			}
			b, _ := json.Marshal(value)
			value = string(b[1 : len(b)-1])
			variants[value] = true
		}
	}
	if len(variants) == 0 {
		return text
	}
	type view struct {
		text  string
		spans []approvalTextSpan
		depth int
	}
	spans := make([]approvalTextSpan, len(text))
	for i := range spans {
		spans[i] = approvalTextSpan{i, i + 1}
	}
	views := []view{{text, spans, 0}}
	seen := map[string]bool{text: true}
	var matches []approvalTextSpan
	work := 0
	// Decode grammars independently: a percent sequence may be literal inside
	// JSON, and '+' may be literal in a path. Search the bounded decoding graph
	// so mixed and nested encodings do not require enumerating hex spellings.
	for at := 0; at < len(views); at++ {
		current := views[at]
		for value := range variants {
			work += len(current.text)
			if work > maxApprovalWalkBytes {
				return secretMask
			}
			for start := 0; start < len(current.text); {
				i := strings.Index(current.text[start:], value)
				if i < 0 {
					break
				}
				i += start
				matches = append(matches, approvalTextSpan{current.spans[i].start, current.spans[i+len(value)-1].end})
				start = i + len(value)
			}
		}
		for encoding := approvalPathEncoding; encoding <= approvalHTMLEncoding; encoding++ {
			work += len(current.text)
			if work > maxApprovalWalkBytes {
				return secretMask
			}
			next, positions := decodeApprovalText(current.text, current.spans, encoding)
			if seen[next] {
				continue
			}
			if current.depth >= maxApprovalDepth || len(views) >= 128 {
				// Never expose an encoding we stopped analyzing for resource limits.
				return secretMask
			}
			seen[next] = true
			views = append(views, view{next, positions, current.depth + 1})
		}
		views[at].spans = nil
	}
	if len(matches) == 0 {
		return text
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].start == matches[j].start {
			return matches[i].end > matches[j].end
		}
		return matches[i].start < matches[j].start
	})
	var out strings.Builder
	last := 0
	for i := 0; i < len(matches); {
		span := matches[i]
		i++
		for i < len(matches) && matches[i].start < span.end {
			if matches[i].end > span.end {
				span.end = matches[i].end
			}
			i++
		}
		out.WriteString(text[last:span.start])
		out.WriteString(secretMask)
		last = span.end
	}
	out.WriteString(text[last:])
	return out.String()
}

func approvalHex(text string, digits int) (rune, bool) {
	if len(text) < digits {
		return 0, false
	}
	n, err := strconv.ParseUint(text[:digits], 16, 32)
	return rune(n), err == nil
}

func decodeApprovalText(text string, spans []approvalTextSpan, encoding approvalTextEncoding) (string, []approvalTextSpan) {
	var out strings.Builder
	positions := make([]approvalTextSpan, 0, len(text))
	for i := 0; i < len(text); {
		consumed, decoded := 1, text[i:i+1]
		switch text[i] {
		case '%':
			if encoding == approvalPathEncoding || encoding == approvalQueryEncoding {
				if n, ok := approvalHex(text[i+1:], 2); ok {
					consumed, decoded = 3, string([]byte{byte(n)})
				}
			}
		case '+':
			if encoding == approvalQueryEncoding {
				decoded = " "
			}
		case '\\':
			if encoding == approvalJSONEncoding && i+1 < len(text) {
				const escapes = "\"\\/bfnrt"
				const replacements = "\"\\/\b\f\n\r\t"
				if j := strings.IndexByte(escapes, text[i+1]); j >= 0 {
					consumed, decoded = 2, replacements[j:j+1]
				} else if text[i+1] == 'u' {
					if n, ok := approvalHex(text[i+2:], 4); ok {
						consumed = 6
						if n >= 0xd800 && n <= 0xdbff && i+12 <= len(text) && text[i+6:i+8] == `\u` {
							if low, ok := approvalHex(text[i+8:], 4); ok && low >= 0xdc00 && low <= 0xdfff {
								n, consumed = utf16.DecodeRune(n, low), 12
							}
						}
						decoded = string(n)
					}
				}
			}
		case '&':
			if encoding == approvalHTMLEncoding {
				end := min(len(text), i+33)
				if j := strings.IndexByte(text[i:end], ';'); j > 0 {
					entity := text[i : i+j+1]
					if value := html.UnescapeString(entity); value != entity {
						consumed, decoded = j+1, value
					}
				}
			}
		}
		span := approvalTextSpan{spans[i].start, spans[i+consumed-1].end}
		out.WriteString(decoded)
		for range len(decoded) {
			positions = append(positions, span)
		}
		i += consumed
	}
	return out.String(), positions
}
