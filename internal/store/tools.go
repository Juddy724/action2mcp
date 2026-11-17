package store

import (
	"action2mcp/internal/execution"
	"database/sql"
	"errors"
	"strconv"
	"strings"
	"time"
)

func inheritSqlGuard(tx *sql.Tx, t *execution.Tool, allowDisable bool) error {
	oldEnabled := false
	oldMax := execution.SQLGuardMaxRowsCap
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
			cfg, err := execution.ParseToolConfigJSON(raw)
			if err != nil {
				// Corrupt historical config cannot authorize a weaker guard.
				if execution.IsWSMethod(t.Method) {
					oldEnabled = true
				}
				continue
			}
			if cfg.SqlGuardEnabled() {
				oldEnabled = true
				if cfg.MaxRows() < oldMax {
					oldMax = cfg.MaxRows()
				}
			}
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	explicit := t.Config.SQLGuard != nil
	wantEnabled := t.Config.SqlGuardEnabled()
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
			t.Config.SQLGuard = &execution.SQLGuardConfig{Enabled: true}
		}
		t.Config.SQLGuard.Enabled = true
		maxRows := t.Config.MaxRows()
		if oldEnabled && maxRows > oldMax {
			maxRows = oldMax
		}
		t.Config.SQLGuard.MaxRows = maxRows
		t.Config.ApplyDefaults()
		t.Approval = stricterApproval(t.Approval, "always")
	} else if oldEnabled && !allowDisable {
		return errors.New("不能关闭或削弱已开启的 SQL 护栏")
	}
	return execution.ValidateToolConfig(t.Method, t.Config, false)
}

func defaultApproval(method string) string {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH", "DELETE", "WS":
		return "always"
	default:
		return "off"
	}
}

func validateApproval(policy string) error {
	if policy != "" && policy != "off" && policy != "always" {
		return errors.New("审批模式只能是 off 或 always")
	}
	return nil
}

func stricterApproval(a, b string) string {
	if a == "always" || b == "always" {
		return "always"
	}
	return "off"
}

// Resolve both overwrite selectors and every current/historical source inside
// the write transaction. No connection is acquired outside tx while it is open.
func inheritToolApproval(tx *sql.Tx, t *execution.Tool) error {
	rows, err := tx.Query(`WITH involved_tools AS (
SELECT id,approval,source_request_id FROM tools
WHERE id=? OR name=? OR (source_request_id=? AND ?>0)
), sources(source_request_id) AS (
SELECT ? WHERE ?>0
UNION SELECT source_request_id FROM involved_tools WHERE source_request_id>0
UNION SELECT h.source_request_id FROM tool_approval_sources h JOIN involved_tools t ON t.id=h.tool_id
)
SELECT approval FROM involved_tools
UNION ALL SELECT f.approval FROM source_approval_floor f JOIN sources s ON s.source_request_id=f.source_request_id`,
		t.ID, t.Name, t.SourceReqID, t.SourceReqID, t.SourceReqID, t.SourceReqID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var policy string
		if err := rows.Scan(&policy); err != nil {
			rows.Close()
			return err
		}
		t.Approval = stricterApproval(t.Approval, policy)
	}
	err = rows.Err()
	rows.Close()
	return err
}

func (s *Store) ApprovalTimeout() time.Duration {
	n, err := strconv.Atoi(s.GetSetting("approval_timeout_secs", "300"))
	if err != nil {
		n = 300
	}
	if n < 30 {
		n = 30
	}
	if n > 1800 {
		n = 1800
	}
	return time.Duration(n) * time.Second
}

// Import reads and writes the policy on the same connection.
func (s *Store) ImportTool(t *execution.Tool) (bool, error) {
	if err := validateApproval(t.Approval); err != nil {
		return false, err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var id int64
	var policy string
	err = tx.QueryRow(`SELECT id,approval FROM tools WHERE name=?`, t.Name).Scan(&id, &policy)
	if err != nil && err != sql.ErrNoRows {
		return false, err
	}
	updated := err == nil
	t.ID = id
	if t.Approval == "" {
		t.Approval = defaultApproval(t.Method)
	}
	if updated {
		t.Approval = stricterApproval(t.Approval, policy)
	}
	if err := inheritToolApproval(tx, t); err != nil {
		return false, err
	}
	if err := saveTool(tx, t); err != nil {
		return false, err
	}
	return updated, tx.Commit()
}

// EnabledToolRevision returns the current revision of a tool only while it is
// in at least one enabled pack; otherwise it returns sql.ErrNoRows.
func (s *Store) EnabledToolRevision(id int64) (int64, error) {
	var rev int64
	err := s.db.QueryRow(`SELECT rev FROM tools WHERE id=? AND EXISTS (SELECT 1 FROM pack_tools pt JOIN packs p ON p.id=pt.pack_id WHERE pt.tool_id=tools.id AND p.enabled=1)`, id).Scan(&rev)
	return rev, err
}
