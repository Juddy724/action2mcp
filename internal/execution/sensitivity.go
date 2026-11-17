package execution

import (
	"action2mcp/internal/vault"
	"regexp"
	"strings"
	"unicode"
)

// crossFieldLiteral reports whether a captured secret may be replaced wherever
// it appears. Short, boolean, numeric and version-like values are masked only
// in place, under a sensitive key, so they cannot chew up user agents or
// server-authored words such as create_pack=true.
func CrossFieldLiteral(s string) bool {
	s = strings.TrimSpace(s)
	// A generated reference is only a value that is entirely placeholders.
	// Recorded text that merely contains "{{...}}" is still a secret.
	if len(s) < 6 || s == vault.Mask || IsWholePlaceholder(s) {
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
func IsSensitiveKey(k string) bool {
	seg := LastKey(strings.TrimSpace(k))
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
func PathSensitive(p string) bool {
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
		if IsSensitiveKey(part) {
			sens = true
		}
	}
	return sens
}

var commandJSONRe = regexp.MustCompile(`(?s)^(\s*[A-Za-z_][\w.:-]{0,40}\s+)([\[{].*)$`)

func SplitCommandJSON(s string) (prefix, tail string, ok bool) {
	m := commandJSONRe.FindStringSubmatch(s)
	if m == nil {
		return "", "", false
	}
	return m[1], m[2], true
}

const RemovedSecretDescription = "敏感字段，录制到的值已移除，调用时另填。"

// isWholePlaceholder reports a value we generated: the entire string is one or
// more {{references}} and nothing else. Recorded data that only contains a
// placeholder substring is not a reference.
func IsWholePlaceholder(s string) bool {
	t := strings.TrimSpace(s)
	if t == "" || !strings.Contains(t, "{{") {
		return false
	}
	return strings.TrimSpace(placeholderRe.ReplaceAllString(t, "")) == ""
}

func LastKey(p string) string {
	if i := strings.LastIndexAny(p, ".]"); i >= 0 && i < len(p)-1 {
		return p[i+1:]
	}
	return strings.TrimRight(idxRe.ReplaceAllString(p, "$1"), "]")
}
