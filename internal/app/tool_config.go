package app

import (
	"action2mcp/internal/htmlmd"
	"action2mcp/internal/sqlguard"
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// sqlGuardMaxRowsCap is the SQL guard row cap. The value is owned by internal/sqlguard.
const sqlGuardMaxRowsCap = sqlguard.MaxRowsCap

const (
	sqlGuardMaxRowsDefault = 200
	wsTimeoutMinMS         = 1000
	wsTimeoutMaxMS         = 120000
	wsTimeoutDefaultMS     = 30000
	wsMaxBytesMin          = 4096
	wsMaxBytesMax          = 262144
	wsMaxBytesDefault      = 262144
	wsMaxMessages          = 8
)

type SQLGuardConfig struct {
	Enabled bool   `json:"enabled"`
	Param   string `json:"param,omitempty"`
	Path    string `json:"path,omitempty"`
	MaxRows int    `json:"max_rows,omitempty"`
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

type ToolConfig struct {
	Messages       []string         `json:"messages,omitempty"`
	SQLGuard       *SQLGuardConfig  `json:"sql_guard,omitempty"`
	Collect        *WSCollectConfig `json:"collect,omitempty"`
	Auth           *WSAuthConfig    `json:"auth,omitempty"`
	ResultFormat   string           `json:"result_format,omitempty"`   // ""/"auto", "raw", "selector"
	ResultSelector string           `json:"result_selector,omitempty"` // used when ResultFormat=selector
	DetectFailure  *bool            `json:"detect_failure,omitempty"`  // nil = enabled; false disables
	OpKind         string           `json:"op_kind,omitempty"`         // ""/"auto", "read", "write"
}

const (
	resultFormatAuto     = "auto"
	resultFormatRaw      = "raw"
	resultFormatSelector = "selector"
	opKindAuto           = "auto"
	opKindRead           = "read"
	opKindWrite          = "write"
)

func (c ToolConfig) resultFormat() string {
	switch strings.ToLower(strings.TrimSpace(c.ResultFormat)) {
	case "", resultFormatAuto:
		return resultFormatAuto
	case resultFormatRaw:
		return resultFormatRaw
	case resultFormatSelector:
		return resultFormatSelector
	default:
		return resultFormatAuto
	}
}

func (c ToolConfig) detectFailureEnabled() bool {
	return c.DetectFailure == nil || *c.DetectFailure
}

func (c ToolConfig) opKind() string {
	switch strings.ToLower(strings.TrimSpace(c.OpKind)) {
	case "", opKindAuto:
		return opKindAuto
	case opKindRead:
		return opKindRead
	case opKindWrite:
		return opKindWrite
	default:
		return opKindAuto
	}
}

func boolPtr(v bool) *bool { return &v }

// validatePresentation is save-time only. Runtime (freezeWSCall) must not
// fail a call because of these fields; illegal selectors fall back instead.
func validatePresentation(c ToolConfig) error {
	f := strings.ToLower(strings.TrimSpace(c.ResultFormat))
	if f != "" && f != resultFormatAuto && f != resultFormatRaw && f != resultFormatSelector {
		return fmt.Errorf("返回格式必须是 auto、raw 或 selector，而不是 %q", c.ResultFormat)
	}
	k := strings.ToLower(strings.TrimSpace(c.OpKind))
	if k != "" && k != opKindAuto && k != opKindRead && k != opKindWrite {
		return fmt.Errorf("操作类型必须是 auto、read 或 write，而不是 %q", c.OpKind)
	}
	if f == resultFormatSelector {
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

func isWSMethod(method string) bool {
	return strings.ToUpper(strings.TrimSpace(method)) == "WS"
}

func parseToolConfigJSON(raw string) (ToolConfig, error) {
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

func (c ToolConfig) sqlGuardEnabled() bool {
	return c.SQLGuard != nil && c.SQLGuard.Enabled
}

func (c ToolConfig) maxRows() int {
	n := sqlGuardMaxRowsDefault
	if c.SQLGuard != nil && c.SQLGuard.MaxRows > 0 {
		n = c.SQLGuard.MaxRows
	}
	if n > sqlGuardMaxRowsCap {
		n = sqlGuardMaxRowsCap
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

func (c *ToolConfig) applyDefaults() {
	if c.SQLGuard != nil && c.SQLGuard.Enabled {
		if c.SQLGuard.MaxRows == 0 {
			c.SQLGuard.MaxRows = sqlGuardMaxRowsDefault
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

func validateToolConfig(method string, c ToolConfig, requireComplete bool) error {
	empty := !c.sqlGuardEnabled() && len(c.Messages) == 0 && c.Collect == nil && c.Auth == nil
	if !isWSMethod(method) {
		if empty {
			return nil
		}
		return errors.New("HTTP 工具不能包含 WebSocket 配置")
	}
	if c.sqlGuardEnabled() && len(c.Messages) != 1 {
		return errors.New("开启 SQL 护栏时必须恰好有一条 execute 消息")
	}
	if len(c.Messages) > wsMaxMessages {
		return fmt.Errorf("WebSocket 消息最多 %d 条", wsMaxMessages)
	}
	if requireComplete && len(c.Messages) == 0 {
		return errors.New("WebSocket 工具至少需要一条消息模板")
	}
	if c.SQLGuard != nil && c.SQLGuard.Enabled {
		if c.SQLGuard.MaxRows < 0 || c.SQLGuard.MaxRows > sqlGuardMaxRowsCap {
			return fmt.Errorf("sql_guard.max_rows 必须在 1–%d 之间", sqlGuardMaxRowsCap)
		}
		if c.SQLGuard.MaxRows == 0 {
			// default applied later
		} else if c.SQLGuard.MaxRows < 1 {
			return errors.New("sql_guard.max_rows 必须至少为 1")
		}
	}
	if c.Collect != nil {
		if c.Collect.TimeoutMS != 0 && (c.Collect.TimeoutMS < wsTimeoutMinMS || c.Collect.TimeoutMS > wsTimeoutMaxMS) {
			return fmt.Errorf("collect.timeout_ms 必须在 %d–%d 之间", wsTimeoutMinMS, wsTimeoutMaxMS)
		}
		if c.Collect.MaxBytes != 0 && (c.Collect.MaxBytes < wsMaxBytesMin || c.Collect.MaxBytes > wsMaxBytesMax) {
			return fmt.Errorf("collect.max_bytes 必须在 %d–%d 之间", wsMaxBytesMin, wsMaxBytesMax)
		}
	}
	return nil
}

func validateToolConfigAndCreds(t *Tool, requireComplete bool) error {
	if err := validateToolConfig(t.Method, t.Config, requireComplete); err != nil {
		return err
	}
	return validateWSCredentialBindings(t)
}

func (c ToolConfig) marshal() string {
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
	return out
}

func inheritSqlGuard(tx *sql.Tx, t *Tool, allowDisable bool) error {
	oldEnabled := false
	oldMax := sqlGuardMaxRowsCap
	rows, err := tx.Query(`WITH involved_tools AS (
SELECT id,config,source_request_id FROM tools
WHERE id=? OR name=? OR (source_request_id=? AND ?>0)
), sources(source_request_id) AS (
SELECT ? WHERE ?>0
UNION SELECT source_request_id FROM involved_tools WHERE source_request_id>0
UNION SELECT h.source_request_id FROM tool_approval_sources h JOIN involved_tools t ON t.id=h.tool_id
)
SELECT config, 0, 0 FROM involved_tools
UNION ALL SELECT '', f.sql_guard, f.max_rows FROM source_guard_floor f JOIN sources s ON s.source_request_id=f.source_request_id`,
		t.ID, t.Name, t.SourceReqID, t.SourceReqID, t.SourceReqID, t.SourceReqID)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		var floorOn, floorRows int
		if err := rows.Scan(&raw, &floorOn, &floorRows); err != nil {
			return err
		}
		if floorOn == 1 {
			oldEnabled = true
			if floorRows > 0 && floorRows < oldMax {
				oldMax = floorRows
			}
		}
		if strings.TrimSpace(raw) != "" {
			cfg, err := parseToolConfigJSON(raw)
			if err != nil {
				// Corrupt historical config cannot authorize a weaker guard.
				if isWSMethod(t.Method) {
					oldEnabled = true
				}
				continue
			}
			if cfg.sqlGuardEnabled() {
				oldEnabled = true
				if cfg.maxRows() < oldMax {
					oldMax = cfg.maxRows()
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	explicit := t.Config.SQLGuard != nil
	wantEnabled := t.Config.sqlGuardEnabled()
	if !explicit && oldEnabled {
		wantEnabled = true
	}
	if oldEnabled && !wantEnabled && !allowDisable {
		wantEnabled = true
	}
	if oldEnabled && !wantEnabled && allowDisable && explicit && !t.Config.SQLGuard.Enabled {
		if t.Approval == "off" {
			return errors.New("不能在关闭 SQL 护栏的同时把审批降为 off；请先关闭护栏并保持每次审批，再另行修改审批模式")
		}
		t.Approval = stricterApproval(t.Approval, "always")
	}

	if wantEnabled {
		if t.Config.SQLGuard == nil {
			t.Config.SQLGuard = &SQLGuardConfig{Enabled: true}
		}
		t.Config.SQLGuard.Enabled = true
		maxRows := t.Config.maxRows()
		if oldEnabled && maxRows > oldMax {
			maxRows = oldMax
		}
		t.Config.SQLGuard.MaxRows = maxRows
		t.Config.applyDefaults()
		t.Approval = stricterApproval(t.Approval, "always")
	} else if oldEnabled && !allowDisable {
		return errors.New("不能关闭或削弱已开启的 SQL 护栏")
	}
	return validateToolConfig(t.Method, t.Config, false)
}
