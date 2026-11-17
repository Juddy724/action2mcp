package execution

import (
	"action2mcp/internal/domain"

	_ "modernc.org/sqlite"
)

type Tool struct {
	ID                int64             `json:"id"`
	Approval          string            `json:"approval"`
	Rev               int64             `json:"rev"`
	Name              string            `json:"name"`
	Title             string            `json:"title"`
	Description       string            `json:"description"`
	Method            string            `json:"method"`
	URL               string            `json:"url"`
	Headers           map[string]string `json:"headers"`
	Body              string            `json:"body"`
	Params            []domain.Param    `json:"params"`
	CredHeaders       []string          `json:"cred_headers"`
	SourceReqID       int64             `json:"source_request_id,omitempty"`
	CreatedAt         string            `json:"created_at,omitempty"`
	UpdatedAt         string            `json:"updated_at,omitempty"`
	Packs             []string          `json:"packs,omitempty"`
	Config            ToolConfig        `json:"config"`
	AllowDisableGuard bool              `json:"-"`
	configErr         error
	mwID              int64  `json:"-"`
	mwFingerprint     string `json:"-"`
	mwName            string `json:"-"`
	mwAlias           string `json:"-"`
}

type Cookie struct {
	Name     string  `json:"name"`
	Value    string  `json:"value"`
	Domain   string  `json:"domain"`
	Path     string  `json:"path"`
	Expires  float64 `json:"expires"`
	Secure   bool    `json:"secure"`
	HTTPOnly bool    `json:"httpOnly"`
	Session  bool    `json:"session"`
}

// ConsoleBinding identifies a generated SQL tool and its approved configuration.
// This metadata is deliberately excluded from the JSON tool schema.
type ConsoleBinding struct {
	ID                       int64
	Fingerprint, Name, Alias string
}

func (t *Tool) BindConsole(b ConsoleBinding) {
	t.mwID = b.ID
	t.mwFingerprint = b.Fingerprint
	t.mwName = b.Name
	t.mwAlias = b.Alias
}
func (t *Tool) ConsoleBinding() ConsoleBinding {
	return ConsoleBinding{t.mwID, t.mwFingerprint, t.mwName, t.mwAlias}
}
func (t *Tool) ConfigError() error { return t.configErr }

// LoadConfig retains malformed historical configuration as an execution error.
func (t *Tool) LoadConfig(raw string) { t.Config, t.configErr = ParseToolConfigJSON(raw) }
