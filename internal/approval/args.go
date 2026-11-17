package approval

import (
	"action2mcp/internal/vault"
	"encoding/json"
)

func CopyArgs(args map[string]any) (map[string]any, error) {
	b, err := json.Marshal(args)
	if err != nil {
		return nil, NewError(400, "参数无法序列化，未执行")
	}
	if len(b) > vault.MaxScrubBytes {
		return nil, NewError(400, "参数过大，无法审批，未执行")
	}
	var copy map[string]any
	if err := json.Unmarshal(b, &copy); err != nil {
		return nil, err
	}
	if copy == nil {
		copy = map[string]any{}
	}
	return copy, nil
}
