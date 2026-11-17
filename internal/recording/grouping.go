package recording

import (
	"net/url"
	"path"
	"regexp"
	"strings"
)

var uuidPathRe = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

var uuidSpanRe = regexp.MustCompile(`(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

var digitsPathRe = regexp.MustCompile(`^[0-9]{3,}$`)

var hexPathRe = regexp.MustCompile(`(?i)^[0-9a-f]{12,}$`)

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
func TemplatePath(p string) (string, bool) {
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

func GroupKey(method, rawURL string) (host, templated, rawPath, key string) {
	host, rawPath = "", "/"
	if u, err := url.Parse(rawURL); err == nil && u != nil {
		host = strings.ToLower(u.Host)
		if u.Path != "" {
			rawPath = u.Path
		}
	}
	templated, _ = TemplatePath(rawPath)
	method = strings.ToUpper(strings.TrimSpace(method))
	key = method + "\n" + host + "\n" + templated
	return host, templated, rawPath, key
}

func IsStaticAssetPath(p string) bool {
	low := strings.ToLower(p)
	return staticExt[path.Ext(low)] || strings.HasSuffix(low, "favicon.ico")
}

func IsSuspectNoise(method, resource, pth, reason string, noise bool) bool {
	if !noise || reason == "跨域预检" || IsStaticAssetPath(pth) {
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

func ReasonListed(list []string, reason string) bool {
	for _, r := range list {
		if r == reason {
			return true
		}
	}
	return false
}

func ValidNoteCategory(c string) bool {
	switch c {
	case "query", "write", "auth", "config", "page", "noise":
		return true
	default:
		return false
	}
}
