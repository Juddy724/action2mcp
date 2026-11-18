package mcp

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
)

// Call carries one tools/call request: its transport session and notifications it produced.
type Call struct {
	Session *Session
	mu      sync.Mutex
	notes   [][]byte // server->client notifications produced while handling the request
}

func TextResult(text string, isErr bool) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isErr}
}

// ArgObject accepts an object, a JSON string holding an object (some agents stringify), or nothing.
func ArgObject(v any) (map[string]any, error) {
	switch x := v.(type) {
	case nil:
		return map[string]any{}, nil
	case map[string]any:
		return x, nil
	case string:
		if strings.TrimSpace(x) == "" {
			return map[string]any{}, nil
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(x), &m); err != nil {
			return nil, err
		}
		if m == nil {
			m = map[string]any{}
		}
		return m, nil
	}
	return nil, fmt.Errorf("类型 %T", v)
}

var entryToolNames = []string{"list_packs", "load_pack", "unload_pack", "call_pack_tool"}

func IsEntryTool(n string) bool {
	for _, x := range entryToolNames {
		if x == n {
			return true
		}
	}
	return false
}

type ToolBrief struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
	Annotations any    `json:"annotations,omitempty"`
}

func ArgString(args map[string]any, k string) string {
	switch v := args[k].(type) {
	case string:
		return v
	case nil:
		return ""
	case float64:
		return fmt.Sprint(v)
	}
	b, _ := json.Marshal(args[k])
	return string(b)
}

func ArgInt(args map[string]any, k string, def int) int {
	switch v := args[k].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case string:
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return def
}

func Annotations(readOnly, destructive, idempotent bool) map[string]any {
	return map[string]any{
		"readOnlyHint":    readOnly,
		"destructiveHint": destructive,
		"idempotentHint":  idempotent,
	}
}

func (c *Call) NotifyToolsChanged() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.notes = append(c.notes, Notification("notifications/tools/list_changed"))
}

// Notifications returns the server->client notifications produced by this call.
func (c *Call) Notifications() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([][]byte, len(c.notes))
	copy(out, c.notes)
	return out
}

const writeOpPrefix = "【写操作，仅在用户明确要求时调用】"

func ApplyWritePrefix(desc string) string {
	desc = strings.TrimSpace(desc)
	if strings.HasPrefix(desc, writeOpPrefix) {
		return desc
	}
	if desc == "" {
		return writeOpPrefix
	}
	return writeOpPrefix + " " + desc
}
