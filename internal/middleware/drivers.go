// Package middleware owns native MySQL, Redis and message-queue drivers, their
// scope enforcement, result limits, and cached connection lifecycle. Application
// exposure checks, credential storage and audit persistence are supplied by ports.
package middleware

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"sync"
)

// Target is a caller-owned read-only call snapshot. Do not mutate it during a call.
// Password resolves credentials at use time;
// CacheConfig is the canonical persisted configuration JSON, retaining cache identity.
// Neither callbacks nor the resolved password are serialized or returned to callers.
type Target struct {
	ID          int64
	Name, Type  string
	Config      Config
	CacheConfig string
	Password    func() (string, error)
}

func (m *Target) cacheKey(pw string) string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d|%s|%s|%s", m.ID, m.Type, m.CacheConfig, pw)))
	return hex.EncodeToString(h[:])
}

// Observer is the caller-owned permission/audit boundary. Require must fail closed;
// Complete is responsible for scrubbing both errors and successful results.
// Actions are sent with every observation, not exposed as shared mutable state.
type Observer interface {
	Require(action string, permissions ...string) (string, bool)
	Block(action, message string) string
	Complete(action, result string, err error) (string, bool)
}

// Drivers is safe for concurrent calls; its zero value is ready to use. Pool
// contents and synchronization remain private. Browser/WebSocket sessions are not
// part of this service.
type Drivers struct {
	mu   sync.Mutex
	pool sync.Map
	keys map[int64]string
}

// Test probes connectivity using the supplied context. The caller bounds its
// lifetime and scrubs driver errors before presenting them.
func (a *Drivers) Test(ctx context.Context, m *Target) (string, error) {
	switch m.Type {
	case "mysql":
		return a.testMySQL(ctx, m)
	case "redis":
		return a.testRedis(ctx, m)
	case "mq":
		return a.testMQ(ctx, m)
	}
	return "", fmt.Errorf("未知类型")
}

// Execute runs a native tool after scope checks and Observer.Require. Exposure
// to an enabled pack is a caller precondition, not a database lookup in drivers.
func (a *Drivers) Execute(ctx context.Context, m *Target, tool string, args map[string]any, observer Observer) (string, bool) {
	c := &mwCall{m: m, tool: tool, observer: observer}
	switch m.Type {
	case "mysql":
		return a.callDB(ctx, c, args)
	case "redis":
		return a.callRedis(ctx, c, args)
	case "mq":
		return a.callMQ(ctx, c, args)
	}
	return "未知工具", true
}

type mwCall struct {
	m            *Target
	tool, action string
	observer     Observer
}

func (c *mwCall) need(perms ...string) (string, bool) { return c.observer.Require(c.action, perms...) }
func (c *mwCall) blocked(message string) string       { return c.observer.Block(c.action, message) }
func (c *mwCall) done(result string, err error) (string, bool) {
	return c.observer.Complete(c.action, result, err)
}

func (a *Drivers) put(id int64, key string, v any) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.keys == nil {
		a.keys = map[int64]string{}
	}
	if old, ok := a.keys[id]; ok && old != key {
		if ov, ok := a.pool.LoadAndDelete(old); ok {
			go closeClient(ov)
		}
	}
	a.keys[id] = key
	a.pool.Store(key, v)
}

// Drop invalidates and asynchronously closes the cached client for id.
func (a *Drivers) Drop(id int64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if old, ok := a.keys[id]; ok {
		if ov, ok := a.pool.LoadAndDelete(old); ok {
			go closeClient(ov)
		}
		delete(a.keys, id)
	}
}

func closeClient(v any) {
	switch x := v.(type) {
	case io.Closer:
		x.Close()
	case interface{ Close() }:
		x.Close()
	case interface{ Shutdown() error }:
		x.Shutdown()
	}
}
