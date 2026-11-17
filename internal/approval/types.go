package approval

import "action2mcp/internal/domain"

type Error struct {
	Status  int
	Message string
}

func (e *Error) Error() string { return e.Message }

func NewError(status int, message string) error {
	return &Error{status, message}
}

type Record struct {
	ID               int64                 `json:"id"`
	TS               string                `json:"ts"`
	Tool             string                `json:"tool"`
	ToolID           int64                 `json:"tool_id"`
	ToolRev          int64                 `json:"tool_rev"`
	Title            string                `json:"title"`
	Client           string                `json:"client"`
	ArgsDisplay      map[string]string     `json:"args_display"`
	FinalArgsDisplay map[string]string     `json:"final_args_display,omitempty"`
	Status           string                `json:"status"`
	Feedback         string                `json:"feedback"`
	DecidedAt        string                `json:"decided_at"`
	Result           string                `json:"result"`
	ResultFull       string                `json:"-"`
	HasFullResult    bool                  `json:"has_full_result,omitempty"`
	Preview          domain.RequestPreview `json:"preview"`
	PreviewHash      string                `json:"preview_hash"`
	Params           []domain.Param        `json:"params"`
	Nonce            string                `json:"nonce,omitempty"`
}

type Preview struct {
	Preview     domain.RequestPreview `json:"preview"`
	PreviewHash string                `json:"preview_hash"`
}
