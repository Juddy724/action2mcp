package vault

import (
	"action2mcp/internal/ahocorasick"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
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

// minSecretScrubLen is the minimum length at which a passed value (cookie,
// harvested header, prepared secret) is used for substring scrubbing.
// Shorter strings collide with ordinary data — digits inside IDs, "LIMIT 10",
// one-character cookie flags — and are not useful as credentials.
// Vault secrets keep their own threshold (>= 3) because the user explicitly
// marked them; they travel through Vault.secretVariants, not this path.
const MinSecretScrubLen = 8

// minExplicitSecretLen is used when scrubbing values the program itself
// classified as secrets (approval secret parameters, template literals).
// It matches Vault's conservative floor so a 5-character parameter such as
// "token" is still masked in the approval preview, while 1–2 character
// incidental values are not. Result-row scrubbing uses minSecretScrubLen.
const minExplicitSecretLen = 3

// minConfigTokenLen is the minimum length for configuration-hide values
// (ds_id, env_id, env_type, space_code, db_type) to be token-boundary
// masked in error, preview, and audit text. Three-character datasource
// ids must still be hidden there; 1–2 character values are skipped.
const minConfigTokenLen = 3

func ScrubSecretText(text string, vault *Vault, values []string) string {
	return scrubSecretTextMin(text, vault, values, MinSecretScrubLen)
}

func ScrubExplicitSecretText(text string, vault *Vault, values []string) string {
	return scrubSecretTextMin(text, vault, values, minExplicitSecretLen)
}

func scrubSecretTextMin(text string, vault *Vault, values []string, minLen int) string {
	if text == "" {
		return text
	}
	if len(text) > MaxScrubBytes {
		return Mask
	}
	if minLen < 1 {
		minLen = 1
	}
	variants := map[string]bool{}
	addBase64 := func(value string) {
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			variants[encoding.EncodeToString([]byte(value))] = true
		}
	}
	if vault != nil {
		for _, value := range vault.SecretVariants() {
			variants[value] = true
			addBase64(value)
		}
	}
	for _, value := range values {
		if value == "" || value == Mask || len(value) < minLen {
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
	patterns := make([]string, 0, len(variants))
	for value := range variants {
		if value != "" {
			patterns = append(patterns, value)
		}
	}
	matcher := ahocorasick.New(patterns)
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
	//
	// Each view is scanned once with Aho–Corasick (cost independent of the
	// number of variants). The walk budget counts len(text) once per view,
	// plus the existing depth / 128-view caps. Pathological inputs still
	// fail closed.
	for at := 0; at < len(views); at++ {
		current := views[at]
		work += len(current.text)
		if work > MaxDecodeWalkBytes {
			return Mask
		}
		for _, hit := range matcher.Find(current.text) {
			if hit.Start < 0 || hit.End > len(current.spans) || hit.Start >= hit.End {
				continue
			}
			matches = append(matches, approvalTextSpan{current.spans[hit.Start].start, current.spans[hit.End-1].end})
		}
		for encoding := approvalPathEncoding; encoding <= approvalHTMLEncoding; encoding++ {
			next, positions := decodeApprovalText(current.text, current.spans, encoding)
			if seen[next] {
				continue
			}
			if current.depth >= MaxDecodeDepth || len(views) >= 128 {
				// Never expose an encoding we stopped analyzing for resource limits.
				return Mask
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
		out.WriteString(Mask)
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

func isConfigTokenChar(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || r == '_'
}

func configTokenBoundary(text string, start, end int) bool {
	if start > 0 {
		r, _ := utf8.DecodeLastRuneInString(text[:start])
		if r != utf8.RuneError && isConfigTokenChar(r) {
			return false
		}
	}
	if end < len(text) {
		r, _ := utf8.DecodeRuneInString(text[end:])
		if r != utf8.RuneError && isConfigTokenChar(r) {
			return false
		}
	}
	return true
}

// scrubConfigTokens masks configuration identifiers (datasource ids, env
// values, space codes, db types) using token-boundary matching: a value is
// replaced only when it is not inside a longer alphanumeric or underscore
// run. This is for error messages, request echoes, approval previews and
// audit text — not for successful result rows, where these values may
// legitimately appear inside ordinary data.
func ScrubConfigTokens(text string, values []string) string {
	if text == "" || len(values) == 0 {
		return text
	}
	seen := map[string]bool{}
	list := make([]string, 0, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" || v == Mask || len(v) < minConfigTokenLen || seen[v] {
			continue
		}
		seen[v] = true
		list = append(list, v)
	}
	if len(list) == 0 {
		return text
	}
	type span struct{ start, end int }
	var matches []span
	for _, hit := range ahocorasick.New(list).Find(text) {
		if !configTokenBoundary(text, hit.Start, hit.End) {
			continue
		}
		matches = append(matches, span{hit.Start, hit.End})
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
		sp := matches[i]
		i++
		for i < len(matches) && matches[i].start < sp.end {
			if matches[i].end > sp.end {
				sp.end = matches[i].end
			}
			i++
		}
		if sp.start < last {
			if sp.end > last {
				// overlapping after a previous write: already covered
			}
			continue
		}
		out.WriteString(text[last:sp.start])
		out.WriteString(Mask)
		last = sp.end
	}
	out.WriteString(text[last:])
	return out.String()
}
