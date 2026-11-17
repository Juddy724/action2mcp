package credential

import (
	"regexp"
	"sort"
	"strings"
)

// ---------- credential / header filtering ----------

var credHeaderRe = regexp.MustCompile(`(?i)^(cookie|authorization|proxy-authorization|.*csrf.*|.*xsrf.*|.*token.*|.*auth.*|.*session.*|x-api-key|api-key|apikey|x-sign.*|signature)$`)

// headers that must never be replayed verbatim
var dropHeaders = map[string]bool{"host": true, "content-length": true, "connection": true, "accept-encoding": true, "keep-alive": true,
	"transfer-encoding": true, "upgrade": true, "te": true, "trailer": true, "proxy-connection": true, "priority": true, "if-none-match": true, "if-modified-since": true}

func IsCredHeader(name string) bool {
	n := strings.ToLower(name)
	if n == "x-requested-with" {
		return false
	}
	return credHeaderRe.MatchString(n)
}

// SanitizeHeaders splits recorded headers into replayable headers and credential header names.
func SanitizeHeaders(h map[string]string) (map[string]string, []string) {
	out := map[string]string{}
	var creds []string
	for k, v := range h {
		lk := strings.ToLower(k)
		if strings.HasPrefix(k, ":") || dropHeaders[lk] || strings.HasPrefix(lk, "sec-") && lk != "sec-ch-ua" {
			continue
		}
		if IsCredHeader(k) {
			creds = append(creds, lk)
			continue
		}
		out[k] = v
	}
	sort.Strings(creds)
	return out, creds
}

// ShouldDropHeader reports headers that are never replayed verbatim.
func ShouldDropHeader(name string) bool { return dropHeaders[strings.ToLower(name)] }
