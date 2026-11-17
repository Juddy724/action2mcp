package execution

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestReplacedTransportAndPinnedDialCannotContactConsole(t *testing.T) {
	var dialed atomic.Bool
	source := &http.Client{Transport: &http.Transport{DialContext: func(context.Context, string, string) (net.Conn, error) {
		dialed.Store(true)
		return nil, errors.New("unexpected dial")
	}}}
	client, closeIdle := (HTTPGuard{ConsolePort: 19002}).Client(source)
	defer closeIdle()
	request, _ := http.NewRequest("GET", "http://127.0.0.1:"+strconv.Itoa(19002)+"/api", nil)
	if _, err := client.Do(request); err == nil || dialed.Load() {
		t.Fatal("replaced client bypassed transport guard")
	}
	transport := client.Transport.(toolTransport).base.(*http.Transport)
	if _, err := transport.DialContext(context.Background(), "tcp", "127.0.0.1:19002"); !errors.Is(err, ErrConsoleRequest) || dialed.Load() {
		t.Fatal("dial guard allowed local destination")
	}
}

func TestConsoleAddressVariantsAndNonConsoleDestinations(t *testing.T) {
	guard := HTTPGuard{ConsolePort: 19002}
	for _, raw := range []string{"http://127.0.0.1:19002/api", "http://127.0.0.1:019002/api", "http://localhost.:19002/api", "ws://[::1]:19002/", "http://0.0.0.0:19002/", "http://[::]:19002/"} {
		if err := guard.CheckDestination(context.Background(), raw); !errors.Is(err, ErrConsoleRequest) {
			t.Errorf("accepted console address %s: %v", raw, err)
		}
	}
	for _, raw := range []string{"http://127.0.0.1:19003/", "http://localhost:19003/", "https://198.51.100.1:19002/"} {
		if err := guard.CheckDestination(context.Background(), raw); err != nil {
			t.Errorf("blocked non-console %s: %v", raw, err)
		}
	}
	if err := guard.CheckIP(net.ParseIP("::1"), "019002"); !errors.Is(err, ErrConsoleRequest) {
		t.Fatal("WS direct-IP guard lost normalized-port protection")
	}
}

func TestGuardedClientPreservesSourceAndTimeout(t *testing.T) {
	transport := &http.Transport{}
	source := &http.Client{Transport: transport, Timeout: 7 * time.Second}
	client, closeIdle := (HTTPGuard{ConsolePort: 19002}).Client(source)
	defer closeIdle()
	if source.Transport != transport || client.Timeout != source.Timeout {
		t.Fatal("guard mutated the source client or timeout")
	}
	guarded, ok := client.Transport.(toolTransport)
	if !ok || guarded.base == transport {
		t.Fatal("guard did not privately clone native transport")
	}
}
