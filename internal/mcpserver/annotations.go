package mcpserver

import (
	"action2mcp/internal/analysis"
	"action2mcp/internal/execution"
	"strings"
)

// toolOpKind reports whether a recorded (or WS) tool is a write, plus MCP annotations.
func toolOpKind(t *execution.Tool) (write bool, ann map[string]any) {
	method := ""
	if t != nil {
		method = strings.ToUpper(strings.TrimSpace(t.Method))
	}
	write = analysis.IsWriteMethod(method)
	if t != nil && execution.IsFlowMethod(method) && t.Approval == "always" {
		write = true
	}
	if t != nil && t.Config.SqlGuardEnabled() {
		write = false
	}
	if t != nil {
		switch t.Config.EffectiveOpKind() {
		case execution.OpKindRead:
			write = false
		case execution.OpKindWrite:
			write = true
		}
	}
	ann = map[string]any{
		"readOnlyHint":    !write,
		"destructiveHint": false,
		"idempotentHint":  !write,
	}
	if write {
		ann["idempotentHint"] = method == "PUT" || method == "DELETE"
		ann["destructiveHint"] = method == "DELETE"
		if execution.IsWSMethod(method) {
			ann["idempotentHint"] = false
			ann["destructiveHint"] = false
		}
	}
	return write, ann
}
