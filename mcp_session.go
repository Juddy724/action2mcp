package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MCP exposure modes (console setting "mcp_mode").
const (
	ModeTiered = "tiered" // 阶梯模式: only entry tools; agent lists packs and loads what it needs (default)
	ModeFlat   = "flat"   // 平铺模式: all tools of all enabled packs at once (0.3.0 behaviour)
)

func (a *App) mcpMode() string {
	if a.store.GetSetting("mcp_mode", ModeTiered) == ModeFlat {
		return ModeFlat
	}
	return ModeTiered
}

// mcpSession is the per-connection state: one per Mcp-Session-Id (HTTP), i.e. one per `a2m mcp` stdio process.
type mcpSession struct {
	id       string
	mu       sync.Mutex
	client   string
	loaded   map[int64]bool // pack ids loaded via load_pack
	stream   chan []byte    // GET /mcp SSE stream (nil when the client has none open)
	lastSeen time.Time
}

func (s *mcpSession) loadedIDs() map[int64]bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[int64]bool{}
	for k, v := range s.loaded {
		if v {
			out[k] = true
		}
	}
	return out
}

func (s *mcpSession) clientName() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.client == "" {
		return "未知客户端"
	}
	return s.client
}

// session returns the session for an id, creating it lazily (a server restart must not break clients
// that still hold an old id; they just start with nothing loaded).
func (a *App) session(id string) *mcpSession {
	if v, ok := a.mcpSessions.Load(id); ok {
		s := v.(*mcpSession)
		s.mu.Lock()
		s.lastSeen = time.Now()
		s.mu.Unlock()
		return s
	}
	s := &mcpSession{id: id, loaded: map[int64]bool{}, lastSeen: time.Now()}
	v, _ := a.mcpSessions.LoadOrStore(id, s)
	a.gcSessions()
	return v.(*mcpSession)
}

// gcSessions drops sessions idle for more than a day without an open stream.
func (a *App) gcSessions() {
	cut := time.Now().Add(-24 * time.Hour)
	a.mcpSessions.Range(func(k, v any) bool {
		s := v.(*mcpSession)
		s.mu.Lock()
		dead := s.stream == nil && s.lastSeen.Before(cut)
		s.mu.Unlock()
		if dead {
			a.mcpSessions.Delete(k)
		}
		return true
	})
}

func notificationJSON(method string) []byte {
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method})
	return b
}

// push sends a server->client message on the session's GET stream. Returns false if no stream is open.
func (s *mcpSession) push(msg []byte) bool {
	s.mu.Lock() // held during the (non-blocking) send so the stream can't be closed underneath us
	defer s.mu.Unlock()
	if s.stream == nil {
		return false
	}
	select {
	case s.stream <- msg:
		return true
	default: // stream is stuck; drop rather than block a tool call
		return false
	}
}

// broadcastToolsChanged tells every connected client that its tool list may have changed
// (pack toggled/edited in the console, tool edited, mode switched).
func (a *App) broadcastToolsChanged() {
	msg := notificationJSON("notifications/tools/list_changed")
	a.mcpSessions.Range(func(_, v any) bool {
		v.(*mcpSession).push(msg)
		return true
	})
}

// handleMCPStream serves GET /mcp: the standard Streamable HTTP server->client SSE stream.
func (a *App) handleMCPStream(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		w.Header().Set("Allow", "GET, POST, DELETE")
		http.Error(w, "GET /mcp needs Accept: text/event-stream", http.StatusMethodNotAllowed)
		return
	}
	fl, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", 500)
		return
	}
	s := a.session(r.Header.Get("Mcp-Session-Id"))
	ch := make(chan []byte, 32)
	s.mu.Lock()
	if s.stream != nil {
		close(s.stream) // only one GET stream per session; the newest wins
	}
	s.stream = ch
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		if s.stream == ch {
			s.stream = nil
		}
		s.lastSeen = time.Now()
		s.mu.Unlock()
	}()
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(200)
	fmt.Fprint(w, ": action2mcp stream\n\n")
	fl.Flush()
	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-a.quit:
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", msg)
			fl.Flush()
		case <-tick.C:
			fmt.Fprint(w, ": ping\n\n")
			fl.Flush()
		}
	}
}

func (a *App) handleMCPDelete(w http.ResponseWriter, r *http.Request) {
	if id := r.Header.Get("Mcp-Session-Id"); id != "" {
		if v, ok := a.mcpSessions.LoadAndDelete(id); ok {
			s := v.(*mcpSession)
			s.mu.Lock()
			if s.stream != nil {
				close(s.stream)
				s.stream = nil
			}
			s.mu.Unlock()
		}
	}
	w.WriteHeader(200)
}
