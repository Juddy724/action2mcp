package credential

import (
	"net/url"
	"regexp"
	"strings"
)

var vaultNameRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

// isRefName: placeholders served by the vault, not by the AI.
func IsRefName(n string) bool {
	return strings.HasPrefix(n, "cfg.") || strings.HasPrefix(n, "secret.")
}

// headerBindingName reports the header name in a "header.X" server-side
// reference. The "header." prefix is matched case-insensitively.
func HeaderBindingName(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if len(ref) < 8 || !strings.EqualFold(ref[:7], "header.") {
		return "", false
	}
	name := strings.TrimSpace(ref[7:])
	if name == "" {
		return "", false
	}
	return name, true
}

// cookieBindingName reports the cookie name in a "cookie.X" server-side
// reference. The "cookie." prefix is matched case-insensitively.
func CookieBindingName(ref string) (string, bool) {
	ref = strings.TrimSpace(ref)
	if len(ref) < 8 || !strings.EqualFold(ref[:7], "cookie.") {
		return "", false
	}
	name := strings.TrimSpace(ref[7:])
	if name == "" {
		return "", false
	}
	return name, true
}

// isCookieJarRef reports whether ref is header.cookie (any case), which
// resolves to the login-center cookie jar for the request URL, not site_headers.
func IsCookieJarRef(ref string) bool {
	name, ok := HeaderBindingName(ref)
	return ok && HeaderKey(name) == "cookie"
}

func IsHeaderCookieRef(n string) bool {
	if _, ok := HeaderBindingName(n); ok {
		return true
	}
	_, ok := CookieBindingName(n)
	return ok
}

func IsServerRef(n string, ws bool) bool {
	if IsRefName(n) {
		return true
	}
	return ws && IsHeaderCookieRef(n)
}

func NormalizeOrigin(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if o := Origin(s); o != "" {
		return o
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return strings.TrimRight(s, "/")
	}
	return strings.ToLower(u.Scheme + "://" + u.Host)
}

// sameSite compares origins, ignoring the scheme when only one side gave it.
func SameSite(a, b string) bool {
	a, b = NormalizeOrigin(a), NormalizeOrigin(b)
	if a == b {
		return true
	}
	ua, e1 := url.Parse(a)
	ub, e2 := url.Parse(b)
	return e1 == nil && e2 == nil && strings.EqualFold(ua.Host, ub.Host)
}

func ValidName(name string) bool { return vaultNameRe.MatchString(name) }
