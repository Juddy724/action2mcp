package approval

import (
	"action2mcp/internal/domain"
	"database/sql"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"
)

// SQLStore owns approval history persistence over the application's existing DB.
// Schema/migration ownership stays at the composition root; no new DB is opened.
type SQLStore struct{ db *sql.DB }

func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }
func now() string                      { return time.Now().Format("2006-01-02 15:04:05") }
func js(v any) string                  { b, _ := json.Marshal(v); return string(b) }
func finalArgsJSON(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	return js(m)
}

type storedPreview struct {
	Preview     domain.RequestPreview `json:"preview"`
	PreviewHash string                `json:"preview_hash"`
	Explanation string                `json:"explanation,omitempty"`
}

func (s *SQLStore) Insert(r *Record) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`INSERT INTO approvals(ts,tool,tool_id,tool_rev,client,args_display,final_args_display,status,feedback,decided_at,result,title,preview_display,params_json) VALUES(?,?,?,?,?,?,'','pending','','','',?,?,?)`,
		r.TS, r.Tool, r.ToolID, r.ToolRev, r.Client, js(r.ArgsDisplay), r.Title,
		js(storedPreview{r.Preview, r.PreviewHash, r.Explanation}), js(r.Params))
	if err != nil {
		return err
	}
	r.ID, err = res.LastInsertId()
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Called under the service mutex: only in-memory pending entries have a usable nonce
// and count toward the cap. A failed terminal write is repaired on the next poll
// or call; OpenStore and import/export never perform this server-only sweep.
func (s *SQLStore) Sweep(live []int64) error {
	ids := []any{now()}
	marks := []string{}
	for _, id := range live {
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

func (s *SQLStore) Finish(r *Record) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE approvals SET status=?,feedback=?,decided_at=?,final_args_display=?,preview_display=?,result=? WHERE id=? AND status='pending'`,
		r.Status, r.Feedback, r.DecidedAt, finalArgsJSON(r.FinalArgsDisplay), js(storedPreview{r.Preview, r.PreviewHash, r.Explanation}), r.Result, r.ID)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return NewError(409, "本次审批已结束")
	}
	if err := trimApprovals(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Only cmdServe calls this; export/import must not cancel a running server's rows.
func (s *SQLStore) CancelPending() error {
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

func (s *SQLStore) List(status string, limit int) ([]Record, error) {
	rows, err := s.db.Query(`SELECT id,ts,tool,tool_id,tool_rev,client,args_display,final_args_display,status,feedback,decided_at,result,COALESCE(result_full,''),title,preview_display,params_json FROM approvals WHERE (?='all' OR status='pending') ORDER BY id DESC LIMIT ?`, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Record{}
	for rows.Next() {
		var r Record
		var args, final, preview, params string
		if err := rows.Scan(&r.ID, &r.TS, &r.Tool, &r.ToolID, &r.ToolRev, &r.Client, &args, &final, &r.Status, &r.Feedback, &r.DecidedAt, &r.Result, &r.ResultFull, &r.Title, &preview, &params); err != nil {
			return nil, err
		}
		r.HasFullResult = r.ResultFull != "" && r.ResultFull != r.Result
		r.ResultFull = ""
		json.Unmarshal([]byte(args), &r.ArgsDisplay)
		json.Unmarshal([]byte(final), &r.FinalArgsDisplay)
		var p storedPreview
		json.Unmarshal([]byte(preview), &p)
		r.Preview, r.PreviewHash, r.Explanation = p.Preview, p.PreviewHash, p.Explanation
		json.Unmarshal([]byte(params), &r.Params)
		out = append(out, r)
	}
	return out, rows.Err()
}

const (
	approvalResultPreviewBytes = 2 * 1024
	approvalResultPreviewLines = 20
	approvalResultFullMax      = 1 << 20 // 1 MB
	approvalResultTruncMark    = "…[已截断]"
	approvalResultFullCapNote  = "…[已截断]（结果超过 1MB，已截断保存）"
)

func cutUTF8(s string, n int) string {
	if n >= len(s) {
		return s
	}
	if n < 0 {
		return ""
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// previewApprovalResult keeps the first ~20 lines or ~2KB, whichever is
// shorter, and appends a truncation marker when anything is dropped.
func previewApprovalResult(s string) string {
	if s == "" {
		return s
	}
	cut := len(s)
	lines := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines++
			if lines >= approvalResultPreviewLines {
				cut = i
				break
			}
		}
		if i+1 >= approvalResultPreviewBytes && cut == len(s) {
			cut = i + 1
			break
		}
	}
	if cut >= len(s) {
		return s
	}
	return strings.TrimRight(cutUTF8(s, cut), "\r\n") + "\n" + approvalResultTruncMark
}

func capApprovalResultFull(s string) (string, bool) {
	if len(s) <= approvalResultFullMax {
		return s, false
	}
	return cutUTF8(s, approvalResultFullMax) + "\n" + approvalResultFullCapNote, true
}

func (s *SQLStore) Result(id int64) (string, bool, error) {
	if id <= 0 {
		return "", false, NewError(404, "审批记录不存在")
	}
	var result, full string
	err := s.db.QueryRow(`SELECT result, COALESCE(result_full,'') FROM approvals WHERE id=?`, id).Scan(&result, &full)
	if err == sql.ErrNoRows {
		return "", false, NewError(404, "审批记录不存在")
	}
	if err != nil {
		return "", false, err
	}
	if full == "" {
		full = result
	}
	truncated := strings.Contains(full, approvalResultFullCapNote)
	return full, truncated, nil
}
func (s *SQLStore) Exists(id int64) (bool, error) {
	var exists int
	err := s.db.QueryRow(`SELECT 1 FROM approvals WHERE id=?`, id).Scan(&exists)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}
func (s *SQLStore) SaveResult(id int64, result string) error {
	full, _ := capApprovalResultFull(result)
	summary := previewApprovalResult(full)
	_, err := s.db.Exec(`UPDATE approvals SET result=?, result_full=? WHERE id=?`, summary, full, id)
	return err
}
