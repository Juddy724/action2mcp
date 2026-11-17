package app

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"
)

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
func inheritToolApproval(tx *sql.Tx, t *Tool) error {
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
func (s *Store) ImportTool(t *Tool) (bool, error) {
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

type ApprovalRecord struct {
	ID               int64             `json:"id"`
	TS               string            `json:"ts"`
	Tool             string            `json:"tool"`
	ToolID           int64             `json:"tool_id"`
	ToolRev          int64             `json:"tool_rev"`
	Title            string            `json:"title"`
	Client           string            `json:"client"`
	ArgsDisplay      map[string]string `json:"args_display"`
	FinalArgsDisplay map[string]string `json:"final_args_display,omitempty"`
	Status           string            `json:"status"`
	Feedback         string            `json:"feedback"`
	DecidedAt        string            `json:"decided_at"`
	Result           string            `json:"result"`
	ResultFull       string            `json:"-"`
	HasFullResult    bool              `json:"has_full_result,omitempty"`
	Preview          RequestPreview    `json:"preview"`
	PreviewHash      string            `json:"preview_hash"`
	Params           []Param           `json:"params"`
	Nonce            string            `json:"nonce,omitempty"`
}

func (s *Store) insertApproval(r *ApprovalRecord) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO approvals(ts,tool,tool_id,tool_rev,client,args_display,final_args_display,status,feedback,decided_at,result,title,preview_display,params_json) VALUES(?,?,?,?,?,?,'','pending','','','',?,?,?)`,
		r.TS, r.Tool, r.ToolID, r.ToolRev, r.Client, js(r.ArgsDisplay), r.Title,
		js(ApprovalPreview{r.Preview, r.PreviewHash}), js(r.Params))
	if err != nil {
		return err
	}
	r.ID, err = res.LastInsertId()
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Called under approvalMu: only in-memory pending entries have a usable nonce
// and count toward the cap. A failed terminal write is repaired on the next poll
// or call; OpenStore and import/export never perform this server-only sweep.
func (s *Store) sweepOrphanApprovals(live map[int64]*pendingApproval) error {
	ids := []any{now()}
	marks := []string{}
	for id := range live {
		ids = append(ids, id)
		marks = append(marks, "?")
	}
	query := `UPDATE approvals SET status='cancelled',decided_at=? WHERE status='pending'`
	if len(marks) > 0 {
		query += ` AND id NOT IN (` + strings.Join(marks, ",") + `)`
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(query, ids...); err != nil {
		return err
	}
	if err := trimApprovals(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func trimApprovals(tx *sql.Tx) error {
	_, err := tx.Exec(`DELETE FROM approvals WHERE status<>'pending' AND id NOT IN (SELECT id FROM approvals WHERE status<>'pending' ORDER BY id DESC LIMIT 1000)`)
	return err
}

func (s *Store) finishApproval(r *ApprovalRecord) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE approvals SET status=?,feedback=?,decided_at=?,final_args_display=?,preview_display=?,result=? WHERE id=? AND status='pending'`,
		r.Status, r.Feedback, r.DecidedAt, js(r.FinalArgsDisplay), js(ApprovalPreview{r.Preview, r.PreviewHash}), r.Result, r.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return approvalErr(409, "本次审批已结束")
	}
	if err := trimApprovals(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Only cmdServe calls this; export/import must not cancel a running server's rows.
func (s *Store) CancelPendingApprovals() error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE approvals SET status='cancelled',decided_at=? WHERE status='pending'`, now()); err != nil {
		return err
	}
	if err := trimApprovals(tx); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) listApprovals(status string, limit int) ([]ApprovalRecord, error) {
	rows, err := s.db.Query(`SELECT id,ts,tool,tool_id,tool_rev,client,args_display,final_args_display,status,feedback,decided_at,result,COALESCE(result_full,''),title,preview_display,params_json FROM approvals WHERE (?='all' OR status='pending') ORDER BY id DESC LIMIT ?`, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ApprovalRecord{}
	for rows.Next() {
		var r ApprovalRecord
		var args, final, preview, params string
		if err := rows.Scan(&r.ID, &r.TS, &r.Tool, &r.ToolID, &r.ToolRev, &r.Client, &args, &final, &r.Status, &r.Feedback, &r.DecidedAt, &r.Result, &r.ResultFull, &r.Title, &preview, &params); err != nil {
			return nil, err
		}
		r.HasFullResult = r.ResultFull != "" && r.ResultFull != r.Result
		r.ResultFull = ""
		json.Unmarshal([]byte(args), &r.ArgsDisplay)
		json.Unmarshal([]byte(final), &r.FinalArgsDisplay)
		var p ApprovalPreview
		json.Unmarshal([]byte(preview), &p)
		r.Preview, r.PreviewHash = p.Preview, p.PreviewHash
		json.Unmarshal([]byte(params), &r.Params)
		out = append(out, r)
	}
	return out, rows.Err()
}
