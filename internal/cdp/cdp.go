// Package cdp is a tiny Chrome DevTools Protocol client over websocket.
package cdp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// Event is a CDP event.
type Event struct {
	Method    string          `json:"method"`
	SessionID string          `json:"sessionId,omitempty"`
	Params    json.RawMessage `json:"params"`
}

type message struct {
	ID        int64           `json:"id,omitempty"`
	Method    string          `json:"method,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// Conn is a CDP connection to a browser endpoint.
type Conn struct {
	ws      *websocket.Conn
	wmu     sync.Mutex
	mu      sync.Mutex
	nextID  int64
	pending map[int64]chan message
	events  chan Event
	qmu     sync.Mutex
	queue   []Event
	qsig    chan struct{}
	rdone   chan struct{}
	done    chan struct{}
	err     error
}

// Dial connects to a browser websocket debugger URL.
func Dial(ctx context.Context, wsURL string) (*Conn, error) {
	d := websocket.Dialer{HandshakeTimeout: 10 * time.Second, ReadBufferSize: 1 << 16, WriteBufferSize: 1 << 16}
	ws, _, err := d.DialContext(ctx, wsURL, nil)
	if err != nil {
		return nil, err
	}
	c := &Conn{ws: ws, pending: map[int64]chan message{}, events: make(chan Event, 256), done: make(chan struct{}), qsig: make(chan struct{}, 1), rdone: make(chan struct{})}
	go c.readLoop()
	go c.pump()
	return c, nil
}

// Events returns the event channel. It is closed when the connection closes.
func (c *Conn) Events() <-chan Event { return c.events }

// Done is closed when the connection is closed.
func (c *Conn) Done() <-chan struct{} { return c.done }

func (c *Conn) readLoop() {
	defer func() {
		c.mu.Lock()
		for id, ch := range c.pending {
			close(ch)
			delete(c.pending, id)
		}
		c.mu.Unlock()
		close(c.done)
	}()
	for {
		_, data, err := c.ws.ReadMessage()
		if err != nil {
			c.err = err
			return
		}
		var m message
		if err := json.Unmarshal(data, &m); err != nil {
			continue
		}
		if m.ID != 0 {
			c.mu.Lock()
			ch := c.pending[m.ID]
			delete(c.pending, m.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- m
			}
			continue
		}
		if m.Method != "" {
			c.qmu.Lock()
			c.queue = append(c.queue, Event{Method: m.Method, SessionID: m.SessionID, Params: m.Params})
			c.qmu.Unlock()
			select {
			case c.qsig <- struct{}{}:
			default:
			}
		}
	}
}

// pump delivers queued events in order without ever blocking the read loop.
func (c *Conn) pump() {
	defer close(c.events)
	for {
		c.qmu.Lock()
		q := c.queue
		c.queue = nil
		c.qmu.Unlock()
		for _, ev := range q {
			c.events <- ev
		}
		if len(q) > 0 {
			continue
		}
		select {
		case <-c.qsig:
		case <-c.done:
			c.qmu.Lock()
			q := c.queue
			c.queue = nil
			c.qmu.Unlock()
			for _, ev := range q {
				c.events <- ev
			}
			return
		}
	}
}

// ErrClosed is returned when the connection is closed.
var ErrClosed = errors.New("cdp: connection closed")

// Call sends a command and waits for its result. sessionID may be empty (browser target).
func (c *Conn) Call(ctx context.Context, sessionID, method string, params any, result any) error {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		raw = b
	}
	c.mu.Lock()
	select {
	case <-c.done:
		c.mu.Unlock()
		return ErrClosed
	default:
	}
	c.nextID++
	id := c.nextID
	ch := make(chan message, 1)
	c.pending[id] = ch
	c.mu.Unlock()
	b, _ := json.Marshal(message{ID: id, Method: method, SessionID: sessionID, Params: raw})
	c.wmu.Lock()
	err := c.ws.WriteMessage(websocket.TextMessage, b)
	c.wmu.Unlock()
	if err != nil {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return err
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	select {
	case m, ok := <-ch:
		if !ok {
			return ErrClosed
		}
		if m.Error != nil {
			return fmt.Errorf("cdp %s: %s (%d)", method, m.Error.Message, m.Error.Code)
		}
		if result != nil && len(m.Result) > 0 {
			return json.Unmarshal(m.Result, result)
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
		return ctx.Err()
	}
}

// Close closes the connection.
func (c *Conn) Close() error { return c.ws.Close() }
