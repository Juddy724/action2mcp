package approval

import (
	"action2mcp/internal/domain"
	"action2mcp/internal/vault"
	"strings"
)

// Edits replace whole parameters. Only a wholly masked secret retains its value.
func mergeValue(original, edit any, secret bool) (any, error) {
	if secret {
		text := domain.ArgumentText(edit)
		if text == vault.Mask || text == SecretUnchanged {
			return original, nil
		}
		if strings.Contains(text, vault.Mask) {
			return nil, NewError(400, "提交值内部夹带 ******，请输入完整的新秘密参数值，未执行")
		}
	}
	return edit, nil
}

const SecretUnchanged = "******（未改动）"

// EditArgs replaces whole parameters, preserving masked secrets only when the
// execution-owned classifier marks the original parameter sensitive. Both maps
// are copied with the same bounded JSON/float64 semantics as MCP input.
func EditArgs(original, edits map[string]any, secret func(name string, original any) bool) (map[string]any, error) {
	edits, err := CopyArgs(edits)
	if err != nil {
		return nil, err
	}
	merged, err := CopyArgs(original)
	if err != nil {
		return nil, err
	}
	for key, value := range edits {
		merged[key], err = mergeValue(original[key], value, secret(key, original[key]))
		if err != nil {
			return nil, err
		}
	}
	return CopyArgs(merged)
}
