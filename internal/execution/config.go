package execution

import (
	"action2mcp/internal/htmlmd"
	"action2mcp/internal/sqlguard"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// sqlGuardMaxRowsCap is the SQL guard row cap. The value is owned by internal/sqlguard.
const SQLGuardMaxRowsCap = sqlguard.MaxRowsCap

const (
	SQLGuardMaxRowsDefault = 200
	WSTimeoutMinMS         = 1000
	WSTimeoutMaxMS         = 120000
	wsTimeoutDefaultMS     = 30000
	WSMaxBytesMin          = 4096
	WSMaxBytesMax          = 262144
	wsMaxBytesDefault      = 262144
	wsMaxMessages          = 8
)

type SQLGuardConfig struct {
	Enabled       bool   `json:"enabled"`
	Param         string `json:"param,omitempty"`
	Path          string `json:"path,omitempty"`
	MaxRows       int    `json:"max_rows,omitempty"`
	AllowDescribe bool   `json:"allow_describe,omitempty"`
}

type WSCollectConfig struct {
	ResultCmd   string   `json:"result_cmd,omitempty"`
	CloseCmds   []string `json:"close_cmds,omitempty"`
	SuccessPath string   `json:"success_path,omitempty"`
	DonePath    string   `json:"done_path,omitempty"`
	MessagePath string   `json:"message_path,omitempty"`
	TimeoutMS   int      `json:"timeout_ms,omitempty"`
	MaxBytes    int      `json:"max_bytes,omitempty"`
}

type WSAuthConfig struct {
	RetryRelogin     bool     `json:"retry_relogin,omitempty"`
	FailMessageMatch []string `json:"fail_if_success_false_and_message_matches,omitempty"`
}

type FlowConfig struct {
	Steps  []FlowStep `json:"steps"`
	Output FlowOutput `json:"output,omitempty"`
}

type FlowStep struct {
	ID               string         `json:"id"`
	Name             string         `json:"name,omitempty"`
	Kind             string         `json:"kind"` // "tool" | "script"
	ParallelWithPrev bool           `json:"parallel_with_prev,omitempty"`
	ToolName         string         `json:"tool_name,omitempty"`
	ArgsFrom         string         `json:"args_from,omitempty"`
	Args             map[string]any `json:"args,omitempty"`
	Runtime          string         `json:"runtime,omitempty"` // "builtin_js" | "python" | "go" | "java" | "node" | "shell"
	Code             string         `json:"code,omitempty"`
}

type FlowOutput struct {
	Mode     string `json:"mode,omitempty"` // "last" | "template"
	Template string `json:"template,omitempty"`
}

type ToolConfig struct {
	Messages       []string         `json:"messages,omitempty"`
	SQLGuard       *SQLGuardConfig  `json:"sql_guard,omitempty"`
	Collect        *WSCollectConfig `json:"collect,omitempty"`
	Auth           *WSAuthConfig    `json:"auth,omitempty"`
	Flow           *FlowConfig      `json:"flow,omitempty"`
	ResultFormat   string           `json:"result_format,omitempty"`   // ""/"auto", "raw", "selector"
	ResultSelector string           `json:"result_selector,omitempty"` // used when ResultFormat=selector
	DetectFailure  *bool            `json:"detect_failure,omitempty"`  // nil = enabled; false disables
	OpKind         string           `json:"op_kind,omitempty"`         // ""/"auto", "read", "write"
	SampleOutput   string           `json:"sample_output,omitempty"`   // compact scrubbed JSON/text preview of output
}

const (
	ResultFormatAuto     = "auto"
	ResultFormatRaw      = "raw"
	ResultFormatSelector = "selector"
	OpKindAuto           = "auto"
	OpKindRead           = "read"
	OpKindWrite          = "write"
)

func (c ToolConfig) EffectiveResultFormat() string {
	switch strings.ToLower(strings.TrimSpace(c.ResultFormat)) {
	case "", ResultFormatAuto:
		return ResultFormatAuto
	case ResultFormatRaw:
		return ResultFormatRaw
	case ResultFormatSelector:
		return ResultFormatSelector
	default:
		return ResultFormatAuto
	}
}

func (c ToolConfig) DetectFailureEnabled() bool {
	return c.DetectFailure == nil || *c.DetectFailure
}

func (c ToolConfig) EffectiveOpKind() string {
	switch strings.ToLower(strings.TrimSpace(c.OpKind)) {
	case "", OpKindAuto:
		return OpKindAuto
	case OpKindRead:
		return OpKindRead
	case OpKindWrite:
		return OpKindWrite
	default:
		return OpKindAuto
	}
}

func BoolPtr(v bool) *bool { return &v }

// validatePresentation is save-time only. Runtime (freezeWSCall) must not
// fail a call because of these fields; illegal selectors fall back instead.
func ValidatePresentation(c ToolConfig) error {
	f := strings.ToLower(strings.TrimSpace(c.ResultFormat))
	if f != "" && f != ResultFormatAuto && f != ResultFormatRaw && f != ResultFormatSelector {
		return fmt.Errorf("返回格式必须是 auto、raw 或 selector，而不是 %q", c.ResultFormat)
	}
	k := strings.ToLower(strings.TrimSpace(c.OpKind))
	if k != "" && k != OpKindAuto && k != OpKindRead && k != OpKindWrite {
		return fmt.Errorf("操作类型必须是 auto、read 或 write，而不是 %q", c.OpKind)
	}
	if f == ResultFormatSelector {
		sel := strings.TrimSpace(c.ResultSelector)
		if sel == "" {
			return errors.New("返回格式为「只取区域」时必须填写 CSS 选择器")
		}
		if err := htmlmd.ValidateResultSelector(sel); err != nil {
			return err
		}
	}
	return nil
}

func presentationFields(c ToolConfig) ToolConfig {
	return ToolConfig{
		ResultFormat:   c.ResultFormat,
		ResultSelector: c.ResultSelector,
		DetectFailure:  c.DetectFailure,
		OpKind:         c.OpKind,
	}
}

func IsWSMethod(method string) bool {
	return strings.ToUpper(strings.TrimSpace(method)) == "WS"
}

func IsFlowMethod(method string) bool {
	return strings.ToUpper(strings.TrimSpace(method)) == "FLOW"
}

var flowStepIDRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,64}$`)

func ValidateFlowConfig(f *FlowConfig) error {
	if f == nil || len(f.Steps) == 0 {
		return errors.New("自定义工具至少需要包含 1 个节点")
	}
	seen := map[string]bool{}
	for _, s := range f.Steps {
		id := strings.TrimSpace(s.ID)
		if !flowStepIDRe.MatchString(id) {
			return fmt.Errorf("节点标识 %q 只能包含英文字母、数字和下划线（1–64 位）", s.ID)
		}
		if seen[id] {
			return fmt.Errorf("节点标识 %q 重复，请保证每个节点标识唯一", id)
		}
		seen[id] = true
		switch strings.ToLower(strings.TrimSpace(s.Kind)) {
		case "tool":
			if strings.TrimSpace(s.ToolName) == "" {
				return fmt.Errorf("节点 %s：工具节点必须选择目标工具", id)
			}
		case "script":
			if strings.TrimSpace(s.Code) == "" {
				return fmt.Errorf("节点 %s：脚本节点代码不能为空", id)
			}
		default:
			return fmt.Errorf("节点 %s：节点类型必须是 tool 或 script", id)
		}
	}
	return nil
}

func ParseToolConfigJSON(raw string) (ToolConfig, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ToolConfig{}, nil
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(raw)))
	dec.DisallowUnknownFields()
	var cfg ToolConfig
	if err := dec.Decode(&cfg); err != nil {
		// Unknown fields should not break old/forward files: retry without the restriction.
		if err2 := json.Unmarshal([]byte(raw), &cfg); err2 != nil {
			return ToolConfig{}, fmt.Errorf("工具配置无法解析：%w", err2)
		}
	}
	return cfg, nil
}

func (c ToolConfig) SqlGuardEnabled() bool {
	return c.SQLGuard != nil && c.SQLGuard.Enabled
}

func (c ToolConfig) MaxRows() int {
	n := SQLGuardMaxRowsDefault
	if c.SQLGuard != nil && c.SQLGuard.MaxRows > 0 {
		n = c.SQLGuard.MaxRows
	}
	if n > SQLGuardMaxRowsCap {
		n = SQLGuardMaxRowsCap
	}
	if n < 1 {
		n = 1
	}
	return n
}

func (c ToolConfig) timeout() int {
	n := wsTimeoutDefaultMS
	if c.Collect != nil && c.Collect.TimeoutMS > 0 {
		n = c.Collect.TimeoutMS
	}
	return n
}

func (c ToolConfig) maxBytes() int {
	n := wsMaxBytesDefault
	if c.Collect != nil && c.Collect.MaxBytes > 0 {
		n = c.Collect.MaxBytes
	}
	return n
}

func (c *ToolConfig) ApplyDefaults() {
	if c.SQLGuard != nil && c.SQLGuard.Enabled {
		if c.SQLGuard.MaxRows == 0 {
			c.SQLGuard.MaxRows = SQLGuardMaxRowsDefault
		}
		if strings.TrimSpace(c.SQLGuard.Param) == "" {
			c.SQLGuard.Param = "sql"
		}
		if strings.TrimSpace(c.SQLGuard.Path) == "" {
			c.SQLGuard.Path = "data.sql"
		}
	}
	if c.Collect != nil {
		if c.Collect.TimeoutMS == 0 {
			c.Collect.TimeoutMS = wsTimeoutDefaultMS
		}
		if c.Collect.MaxBytes == 0 {
			c.Collect.MaxBytes = wsMaxBytesDefault
		}
		if c.Collect.ResultCmd == "" {
			c.Collect.ResultCmd = "execResult"
		}
		if len(c.Collect.CloseCmds) == 0 {
			c.Collect.CloseCmds = []string{"close"}
		}
		if c.Collect.SuccessPath == "" {
			c.Collect.SuccessPath = "data.success"
		}
		if c.Collect.DonePath == "" {
			c.Collect.DonePath = "data.done"
		}
		if c.Collect.MessagePath == "" {
			c.Collect.MessagePath = "data.message"
		}
	}
}

func ValidateToolConfig(method string, c ToolConfig, requireComplete bool) error {
	if IsFlowMethod(method) {
		if c.SqlGuardEnabled() || len(c.Messages) > 0 || c.Collect != nil || c.Auth != nil {
			return errors.New("自定义流程工具不能包含 WebSocket 配置")
		}
		if requireComplete || c.Flow != nil {
			return ValidateFlowConfig(c.Flow)
		}
		return nil
	}
	if c.Flow != nil {
		return errors.New("普通 HTTP/WebSocket 工具不能包含自定义流程配置")
	}
	empty := !c.SqlGuardEnabled() && len(c.Messages) == 0 && c.Collect == nil && c.Auth == nil
	if !IsWSMethod(method) {
		if empty {
			return nil
		}
		return errors.New("HTTP 工具不能包含 WebSocket 配置")
	}
	if c.SqlGuardEnabled() && len(c.Messages) != 1 {
		return errors.New("开启 SQL 护栏时必须恰好有一条 execute 消息")
	}
	if len(c.Messages) > wsMaxMessages {
		return fmt.Errorf("WebSocket 消息最多 %d 条", wsMaxMessages)
	}
	if requireComplete && len(c.Messages) == 0 {
		return errors.New("WebSocket 工具至少需要一条消息模板")
	}
	if c.SQLGuard != nil && c.SQLGuard.Enabled {
		if c.SQLGuard.MaxRows < 0 || c.SQLGuard.MaxRows > SQLGuardMaxRowsCap {
			return fmt.Errorf("sql_guard.max_rows 必须在 1–%d 之间", SQLGuardMaxRowsCap)
		}
		if c.SQLGuard.MaxRows == 0 {
			// default applied later
		} else if c.SQLGuard.MaxRows < 1 {
			return errors.New("sql_guard.max_rows 必须至少为 1")
		}
	}
	if c.Collect != nil {
		if c.Collect.TimeoutMS != 0 && (c.Collect.TimeoutMS < WSTimeoutMinMS || c.Collect.TimeoutMS > WSTimeoutMaxMS) {
			return fmt.Errorf("collect.timeout_ms 必须在 %d–%d 之间", WSTimeoutMinMS, WSTimeoutMaxMS)
		}
		if c.Collect.MaxBytes != 0 && (c.Collect.MaxBytes < WSMaxBytesMin || c.Collect.MaxBytes > WSMaxBytesMax) {
			return fmt.Errorf("collect.max_bytes 必须在 %d–%d 之间", WSMaxBytesMin, WSMaxBytesMax)
		}
	}
	return nil
}

func validateToolConfigAndCreds(t *Tool, requireComplete bool) error {
	if err := ValidateToolConfig(t.Method, t.Config, requireComplete); err != nil {
		return err
	}
	return ValidateWSCredentialBindings(t)
}

func (c ToolConfig) Marshal() string {
	b, err := json.Marshal(c)
	if err != nil {
		return "{}"
	}
	if string(b) == "null" {
		return "{}"
	}
	return string(b)
}

func configTemplateTexts(t *Tool) []string {
	out := []string{t.URL, t.Body}
	for _, v := range t.Headers {
		out = append(out, v)
	}
	for _, m := range t.Config.Messages {
		out = append(out, m)
	}
	if t.Config.SQLGuard != nil {
		out = append(out, t.Config.SQLGuard.Param, t.Config.SQLGuard.Path)
	}
	if t.Config.Flow != nil {
		out = append(out, t.Config.Flow.Output.Template)
		for _, s := range t.Config.Flow.Steps {
			out = append(out, s.Code, s.ArgsFrom)
			for _, v := range s.Args {
				if b, err := json.Marshal(v); err == nil {
					out = append(out, string(b))
				}
			}
		}
	}
	return out
}

func (c ToolConfig) SQLGuardPath() string {
	if c.SQLGuard != nil && strings.TrimSpace(c.SQLGuard.Path) != "" {
		return c.SQLGuard.Path
	}
	return "data.sql"
}
