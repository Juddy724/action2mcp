package credential

import (
	"net"
	"net/url"
	"strings"
)

func Origin(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "wss":
		scheme = "https"
	case "ws":
		scheme = "http"
	case "http", "https":
	default:
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if host == "" {
		return ""
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "http" || u.Scheme == "ws" {
			// already mapped scheme
		}
	} else if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		// Keep non-default ports. If Hostname() stripped brackets, JoinHostPort handles IPv6.
		if ip := net.ParseIP(host); ip != nil && strings.Contains(host, ":") {
			return scheme + "://" + net.JoinHostPort(host, port)
		}
		return scheme + "://" + host + ":" + port
	}
	return scheme + "://" + host
}

func HeaderKey(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}
