package execution

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// ErrConsoleRequest identifies a blocked request to the local console listener.
var ErrConsoleRequest = errors.New("不允许工具访问控制台自身接口")

func localListenIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsUnspecified() {
		return true
	}
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		if network, ok := addr.(*net.IPNet); ok && network.IP.Equal(ip) {
			return true
		}
	}
	return false
}

// CheckIP protects direct/dialed peers, including WebSocket connections.
func (g HTTPGuard) CheckIP(ip net.IP, port string) error {
	n, err := strconv.Atoi(port)
	if err == nil && n == g.ConsolePort && localListenIP(ip) {
		return ErrConsoleRequest
	}
	return nil
}

// CheckDestination validates URL host/port and every resolved address.
func (g HTTPGuard) CheckDestination(ctx context.Context, raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	port := u.Port()
	if port == "" {
		port = "80"
		if u.Scheme == "https" || u.Scheme == "wss" {
			port = "443"
		}
	}
	n, err := strconv.Atoi(port)
	if err != nil || n != g.ConsolePort {
		return nil
	}
	host := u.Hostname()
	if i := strings.LastIndex(host, "%"); i >= 0 {
		host = host[:i]
	}
	if ip := net.ParseIP(host); ip != nil {
		return g.CheckIP(ip, port)
	}
	if strings.EqualFold(strings.TrimSuffix(host, "."), "localhost") {
		return ErrConsoleRequest
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return err
	}
	for _, addr := range addrs {
		if err := g.CheckIP(addr.IP, port); err != nil {
			return err
		}
	}
	return nil
}

type toolTransport struct {
	guard HTTPGuard
	base  http.RoundTripper
}

func (t toolTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if err := t.guard.CheckDestination(r.Context(), r.URL.String()); err != nil {
		return nil, err
	}
	return t.base.RoundTrip(r)
}

// Client clones the supplied client and wraps transport/dial guards. The caller
// closes only the returned private idle-connection pool.
func (g HTTPGuard) Client(source *http.Client) (http.Client, func()) {
	client := *source
	base := client.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	closeIdle := func() {}
	if transport, ok := base.(*http.Transport); ok {
		clone := transport.Clone()
		dial := clone.DialContext
		if dial == nil {
			dial = (&net.Dialer{}).DialContext
		}
		clone.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			// Resolve once, check every address, then dial the checked IP.
			addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, addr := range addrs {
				if err := g.CheckIP(addr.IP, port); err != nil {
					return nil, err
				}
			}
			var last error
			for _, addr := range addrs {
				ip := addr.IP.String()
				if addr.Zone != "" {
					ip += "%" + addr.Zone
				}
				conn, err := dial(ctx, network, net.JoinHostPort(ip, port))
				if err == nil {
					if remote, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
						if err := g.CheckIP(remote.IP, strconv.Itoa(remote.Port)); err != nil {
							conn.Close()
							return nil, err
						}
					}
					return conn, nil
				}
				last = err
			}
			if last == nil {
				last = errors.New("无法解析目标地址")
			}
			return nil, last
		}
		clone.DialTLS, clone.DialTLSContext = nil, nil
		base, closeIdle = clone, clone.CloseIdleConnections
	}
	client.Transport = toolTransport{g, base}
	return client, closeIdle
}

// HTTPGuard is an immutable per-call console-listener policy. It checks logical
// destinations, redirects, resolved dial IPs and the connected remote address.
// It neither resolves credentials nor owns browser/session/application state.
type HTTPGuard struct{ ConsolePort int }
