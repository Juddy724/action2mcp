package domain

import (
	"encoding/json"
	"strconv"
)

type Param struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // string|number|integer|boolean
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
	Secret      bool   `json:"secret,omitempty"`
}

// ArgumentText retains MCP/template string conversion, including float64 and JSON containers.
func ArgumentText(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case nil:
		return ""
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}
