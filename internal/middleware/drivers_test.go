package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

type observation struct {
	allow                   bool
	required                []string
	action, blocked, result string
	err                     error
}

func (o *observation) Require(action string, perms ...string) (string, bool) {
	o.action = action
	o.required = append(o.required, perms...)
	if !o.allow {
		return "permission-denied", false
	}
	return "", true
}
func (o *observation) Block(action, message string) string {
	o.action, o.blocked = action, message
	return message
}
func (o *observation) Complete(action, result string, err error) (string, bool) {
	o.action, o.result, o.err = action, result, err
	return "observed-and-scrubbed", err != nil
}

func TestPermissionDenialNeverResolvesCredentials(t *testing.T) {
	for _, tc := range []struct {
		kind, tool, permission string
		args                   map[string]any
	}{
		{"mysql", "db_query", "select", map[string]any{"sql": "SELECT 1"}},
		{"mysql", "db_query", "update", map[string]any{"sql": "UPDATE shop.orders SET x=2 WHERE id=1"}},
		{"redis", "redis_command", "write", map[string]any{"command": "SET order:1 private-value"}},
		{"redis", "redis_scan", "read", map[string]any{"match": "order:*"}},
		{"mq", "mq_send", "send", map[string]any{"topic": "order"}},
		{"mq", "mq_peek", "consume", map[string]any{"topic": "order"}},
	} {
		t.Run(tc.kind+"/"+tc.tool+"/"+tc.permission, func(t *testing.T) {
			var d Drivers
			m := &Target{Name: "scoped", Type: tc.kind, Password: func() (string, error) { t.Fatal("credentials resolved after permission denial"); return "", nil }}
			o := &observation{}
			got, isError := d.Execute(context.Background(), m, tc.tool, tc.args, o)
			if got != "permission-denied" || !isError || !reflect.DeepEqual(o.required, []string{tc.permission}) || o.action == "" {
				t.Fatalf("reply=%q error=%t observation=%+v", got, isError, o)
			}
			if strings.Contains(o.action, "private-value") {
				t.Fatal("Redis audit action contains a value")
			}
		})
	}
}

func TestScopeViolationsNeverResolveCredentials(t *testing.T) {
	for _, tc := range []struct {
		kind, tool string
		config     Config
		args       map[string]any
	}{
		{"mysql", "db_query", Config{AllowedDBs: []string{"shop"}}, map[string]any{"sql": "SELECT * FROM other.orders"}},
		{"mysql", "db_query", Config{}, map[string]any{"sql": "SELECT SLEEP(10)"}},
		{"redis", "redis_command", Config{KeyPrefixes: []string{"order:"}}, map[string]any{"command": "GET user:1"}},
		{"redis", "redis_scan", Config{KeyPrefixes: []string{"order:"}}, map[string]any{"match": "*"}},
		{"mq", "mq_send", Config{Topics: []string{"order*"}}, map[string]any{"topic": "user"}},
	} {
		t.Run(tc.kind+"/"+tc.tool, func(t *testing.T) {
			var d Drivers
			m := &Target{Name: "scoped", Type: tc.kind, Config: tc.config, Password: func() (string, error) { t.Fatal("credentials resolved before scope rejection"); return "", nil }}
			o := &observation{allow: true}
			_, isError := d.Execute(context.Background(), m, tc.tool, tc.args, o)
			if !isError || o.blocked == "" || o.action == "" {
				t.Fatalf("error=%t observation=%+v", isError, o)
			}
		})
	}
}

func TestCredentialResolutionFailureUsesCompletionPort(t *testing.T) {
	sentinel := errors.New("credential-unavailable")
	for _, kind := range []string{"mysql", "redis", "mq"} {
		t.Run(kind, func(t *testing.T) {
			var d Drivers
			m := &Target{Name: "db", Type: kind, Config: Config{MQKind: "kafka"}, Password: func() (string, error) { return "", sentinel }}
			tool := map[string]string{"mysql": "db_query", "redis": "redis_command", "mq": "mq_send"}[kind]
			args := map[string]any{"sql": "SELECT 1", "command": "GET order:1", "topic": "order"}
			o := &observation{allow: true}
			reply, isError := d.Execute(context.Background(), m, tool, args, o)
			if reply != "observed-and-scrubbed" || !isError || !errors.Is(o.err, sentinel) {
				t.Fatalf("reply=%q error=%t observation=%+v", reply, isError, o)
			}
		})
	}
}

type fakeRedis struct {
	redis.UniversalClient
	args  []any
	value any
}

func (r *fakeRedis) Do(ctx context.Context, args ...any) *redis.Cmd {
	r.args = append([]any(nil), args...)
	cmd := redis.NewCmd(ctx, args...)
	cmd.SetVal(r.value)
	return cmd
}

func TestCachedRedisUsesObserverAndResultBudget(t *testing.T) {
	var d Drivers
	m := &Target{ID: 1, Type: "redis", Name: "cache", CacheConfig: `{"host":"fake"}`, Config: Config{MaxResultKB: 1}, Password: func() (string, error) { return "pw", nil }}
	cl := &fakeRedis{value: strings.Repeat("界", 1000)}
	// Populate only the package-owned cache; no real Redis/network is used.
	d.put(m.ID, m.cacheKey("pw"), cl)
	o := &observation{allow: true}
	reply, isError := d.Execute(context.Background(), m, "redis_command", map[string]any{"command": "GET order:1"}, o)
	if reply != "observed-and-scrubbed" || isError || !strings.Contains(o.result, `"truncated":true`) || !reflect.DeepEqual(cl.args, []any{"GET", "order:1"}) {
		t.Fatalf("reply=%q error=%t args=%v result=%s", reply, isError, cl.args, o.result)
	}
	if o.action != "GET order:1" {
		t.Fatalf("action=%q", o.action)
	}
}

type closingClient struct{ done chan struct{} }

func (c *closingClient) Close() error { close(c.done); return nil }
func awaitClosed(t *testing.T, c *closingClient) {
	t.Helper()
	select {
	case <-c.done:
	case <-time.After(2 * time.Second):
		t.Fatal("old native client was not closed")
	}
}

func TestPoolReplacementAndDropOwnLifecycle(t *testing.T) {
	var d Drivers
	old, current := &closingClient{make(chan struct{})}, &closingClient{make(chan struct{})}
	d.put(1, "old", old)
	d.put(1, "new", current)
	awaitClosed(t, old)
	if _, ok := d.pool.Load("old"); ok {
		t.Fatal("stale cache entry survived configuration change")
	}
	if v, ok := d.pool.Load("new"); !ok || v != current {
		t.Fatal("replacement cache entry missing")
	}
	d.Drop(1)
	awaitClosed(t, current)
	if _, ok := d.pool.Load("new"); ok {
		t.Fatal("dropped entry survived")
	}
	d.Drop(1) // idempotent; must not double-close the same client
}

func TestConcurrentPoolInvalidation(t *testing.T) {
	var d Drivers
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(id int64) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				key := fmt.Sprint(id, "/", j)
				d.put(id, key, struct{}{})
				d.pool.Load(key)
				d.Drop(id)
			}
		}(int64(i))
	}
	wg.Wait()
	if len(d.keys) != 0 {
		t.Fatal("invalidated key registry not empty")
	}
}

func TestConnectionCacheIdentityRetainsCanonicalConfigAndPassword(t *testing.T) {
	m := &Target{ID: 42, Type: "mysql", CacheConfig: `{"host":"localhost","ws_headers":{"Authorization":"{{secret.auth}}"}}`}
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s|%s", m.ID, m.Type, m.CacheConfig, "pw")))
	if got := m.cacheKey("pw"); got != hex.EncodeToString(h[:]) {
		t.Fatalf("cache identity changed: %s", got)
	}
	if m.cacheKey("pw") == m.cacheKey("rotated") {
		t.Fatal("credential rotation reused cache key")
	}
	old := m.cacheKey("pw")
	m.CacheConfig += " "
	if old == m.cacheKey("pw") {
		t.Fatal("full configuration no longer participates in cache key")
	}
}
