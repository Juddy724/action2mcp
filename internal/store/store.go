package store

import (
	"action2mcp/internal/approval"
	"action2mcp/internal/domain"
	"action2mcp/internal/execution"
	"action2mcp/internal/recording"
	sitecfg "action2mcp/internal/site"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const RecordingPackID int64 = -1

const RecordingPackName = "录制分析"

type Store struct {
	Approvals *approval.SQLStore
	*recording.Store
	*sitecfg.Repository
	db *sql.DB
}

type Pack struct {
	ID            int64   `json:"id"`
	Name          string  `json:"name"`
	Description   string  `json:"description"`
	Enabled       bool    `json:"enabled"`
	Scenarios     string  `json:"scenarios"`
	Guide         string  `json:"guide"`
	ToolIDs       []int64 `json:"tool_ids"`
	MiddlewareIDs []int64 `json:"middleware_ids"`
	CreatedAt     string  `json:"created_at,omitempty"`
}

// maxPackGuideBytes is the stored size of one pack's usage guide.
const maxPackGuideBytes = 8 * 1024

func now() string { return time.Now().Format("2006-01-02 15:04:05") }

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=secure_delete(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, Approvals: approval.NewSQLStore(db), Store: recording.NewStore(db), Repository: sitecfg.NewRepository(db)}
	schema := `
CREATE TABLE IF NOT EXISTS recordings(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, start_url TEXT, status TEXT, created_at TEXT, ended_at TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY AUTOINCREMENT, recording_id INTEGER REFERENCES recordings(id) ON DELETE CASCADE, seq INTEGER, method TEXT, url TEXT, resource_type TEXT,
  req_headers TEXT, req_body TEXT, status INTEGER, resp_headers TEXT, resp_body TEXT, resp_mime TEXT, noise INTEGER, noise_reason TEXT, ts TEXT);
CREATE INDEX IF NOT EXISTS idx_req_rec ON requests(recording_id);
CREATE TABLE IF NOT EXISTS request_notes(
  request_id INTEGER PRIMARY KEY REFERENCES requests(id) ON DELETE CASCADE,
  recording_id INTEGER NOT NULL REFERENCES recordings(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL,
  category TEXT NOT NULL CHECK(category IN ('query','write','auth','config','page','noise')),
  useful INTEGER CHECK(useful IN (0,1)),
  noise_override INTEGER CHECK(noise_override IN (0,1)),
  source TEXT NOT NULL CHECK(source IN ('agent','user')),
  updated_at TEXT NOT NULL,
  group_key TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS idx_request_notes_rec ON request_notes(recording_id);
CREATE TABLE IF NOT EXISTS tools(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, title TEXT, description TEXT, method TEXT, url TEXT, headers TEXT, body TEXT, params TEXT, cred_headers TEXT, source_request_id INTEGER, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS source_approval_floor(source_request_id INTEGER PRIMARY KEY, approval TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS tool_approval_sources(tool_id INTEGER REFERENCES tools(id) ON DELETE CASCADE, source_request_id INTEGER NOT NULL, PRIMARY KEY(tool_id,source_request_id));
CREATE TABLE IF NOT EXISTS packs(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, description TEXT, enabled INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS pack_tools(pack_id INTEGER REFERENCES packs(id) ON DELETE CASCADE, tool_id INTEGER REFERENCES tools(id) ON DELETE CASCADE, PRIMARY KEY(pack_id, tool_id));
CREATE TABLE IF NOT EXISTS cookie_jar(name TEXT, domain TEXT, path TEXT, value TEXT, expires REAL, secure INTEGER, http_only INTEGER, session INTEGER, updated_at TEXT, PRIMARY KEY(name, domain, path));
CREATE TABLE IF NOT EXISTS vault(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, type TEXT, value_enc TEXT, site TEXT DEFAULT '', note TEXT DEFAULT '', created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS sites(id INTEGER PRIMARY KEY AUTOINCREMENT, origin TEXT UNIQUE, config TEXT, status TEXT DEFAULT 'unknown', last_login_at TEXT DEFAULT '', last_check_at TEXT DEFAULT '', last_error TEXT DEFAULT '', login_count INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS middleware(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, type TEXT, config TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS pack_middleware(pack_id INTEGER REFERENCES packs(id) ON DELETE CASCADE, mw_id INTEGER REFERENCES middleware(id) ON DELETE CASCADE, PRIMARY KEY(pack_id, mw_id));
CREATE TABLE IF NOT EXISTS mw_audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, client TEXT, mw TEXT, tool TEXT, action TEXT, perm TEXT, allowed INTEGER, result TEXT, ms INTEGER);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS approvals(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, tool TEXT, tool_id INTEGER, tool_rev INTEGER, client TEXT, args_display TEXT, final_args_display TEXT, status TEXT, feedback TEXT, decided_at TEXT, result TEXT, result_full TEXT NOT NULL DEFAULT '', title TEXT, preview_display TEXT, params_json TEXT);

`
	if _, err := db.Exec(schema); err != nil {
		return nil, err
	}
	// 0.4.0: packs.scenarios (适用场景)
	if !s.hasColumn("packs", "scenarios") {
		if _, err := db.Exec(`ALTER TABLE packs ADD COLUMN scenarios TEXT DEFAULT ''`); err != nil {
			return nil, err
		}
	}
	// pack usage guide shown to the model after load_pack (flat mode: initialize instructions)
	if !s.hasColumn("packs", "guide") {
		if _, err := db.Exec(`ALTER TABLE packs ADD COLUMN guide TEXT DEFAULT ''`); err != nil {
			return nil, err
		}
	}
	// Recording analysis: annotations and an overall workflow summary.
	if !s.hasColumn("recordings", "summary") {
		if _, err := db.Exec(`ALTER TABLE recordings ADD COLUMN summary TEXT NOT NULL DEFAULT ''`); err != nil {
			return nil, err
		}
	}
	groupKeyAdded := false
	if !s.hasColumn("request_notes", "group_key") {
		if _, err := db.Exec(`ALTER TABLE request_notes ADD COLUMN group_key TEXT NOT NULL DEFAULT ''`); err != nil {
			return nil, err
		}
		groupKeyAdded = true
	}
	if _, err := db.Exec(`CREATE INDEX IF NOT EXISTS idx_request_notes_group ON request_notes(recording_id, group_key)`); err != nil {
		return nil, err
	}
	if groupKeyAdded {
		if err := s.BackfillNoteGroupKeys(); err != nil {
			return nil, err
		}
	}
	for _, col := range []struct{ name, ddl string }{
		{"approval", `ALTER TABLE tools ADD COLUMN approval TEXT NOT NULL DEFAULT 'off'`},
		{"rev", `ALTER TABLE tools ADD COLUMN rev INTEGER NOT NULL DEFAULT 1`},
	} {
		if !s.hasColumn("tools", col.name) {
			if _, err := db.Exec(col.ddl); err != nil {
				return nil, err
			}
		}
	}
	if _, err := db.Exec(`INSERT INTO tool_approval_sources(tool_id,source_request_id)
SELECT id,source_request_id FROM tools WHERE source_request_id>0 ON CONFLICT DO NOTHING;
INSERT INTO source_approval_floor(source_request_id,approval)
SELECT source_request_id,CASE WHEN MAX(approval='always') THEN 'always' ELSE 'off' END
FROM tools WHERE source_request_id>0 GROUP BY source_request_id
ON CONFLICT(source_request_id) DO UPDATE SET approval=CASE
WHEN source_approval_floor.approval='always' OR excluded.approval='always' THEN 'always' ELSE 'off' END;`); err != nil {
		return nil, err
	}
	if !s.hasColumn("tools", "config") {
		if _, err := db.Exec(`ALTER TABLE tools ADD COLUMN config TEXT NOT NULL DEFAULT '{}'`); err != nil {
			return nil, err
		}
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS site_headers(
		origin TEXT NOT NULL,
		name TEXT NOT NULL,
		value_enc TEXT NOT NULL,
		generation INTEGER NOT NULL DEFAULT 0,
		updated_at TEXT,
		PRIMARY KEY(origin, name)
	)`); err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS site_header_gens(
		origin TEXT PRIMARY KEY,
		generation INTEGER NOT NULL,
		started_at TEXT
	)`); err != nil {
		return nil, err
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS source_guard_floor(
		source_request_id INTEGER PRIMARY KEY,
		sql_guard INTEGER NOT NULL DEFAULT 0,
		max_rows INTEGER NOT NULL DEFAULT 200
	)`); err != nil {
		return nil, err
	}
	if err := s.migrateV8WSToolsToSQLMiddleware(); err != nil {
		return nil, err
	}
	if err := s.MigrateWSSiteOrigins(); err != nil {
		return nil, err
	}
	if err := s.migrateV9SQLConsoleRowEnv(); err != nil {
		return nil, err
	}
	if !s.hasColumn("approvals", "result_full") {
		if _, err := db.Exec(`ALTER TABLE approvals ADD COLUMN result_full TEXT NOT NULL DEFAULT ''`); err != nil {
			return nil, err
		}
	}
	if err := s.migrateV11SQLConsoleApproval(); err != nil {
		return nil, err
	}
	if _, err := db.Exec(fmt.Sprintf(`PRAGMA user_version=%d`, schemaUserVersion)); err != nil {
		return nil, err
	}
	if runtime.GOOS != "windows" && path != "" && !strings.Contains(path, "mode=memory") && !strings.HasPrefix(path, ":") {
		if st, err := os.Stat(path); err == nil && st.Mode().Perm() != 0o600 {
			_ = os.Chmod(path, 0o600)
		}
	}
	// recordings left in "recording" state by a crash are finished now
	db.Exec(`UPDATE recordings SET status='done', ended_at=? WHERE status='recording'`, now())
	return s, nil
}

func js(v any) string { b, _ := json.Marshal(v); return string(b) }

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

const toolCols = `id,name,title,description,method,url,headers,body,params,cred_headers,source_request_id,created_at,updated_at,approval,rev,config`

func scanTool(sc interface{ Scan(...any) error }) (*execution.Tool, error) {
	var t execution.Tool
	var h, p, c, cfg string
	var src sql.NullInt64
	if err := sc.Scan(&t.ID, &t.Name, &t.Title, &t.Description, &t.Method, &t.URL, &h, &t.Body, &p, &c, &src, &t.CreatedAt, &t.UpdatedAt, &t.Approval, &t.Rev, &cfg); err != nil {
		return nil, err
	}
	t.SourceReqID = src.Int64
	json.Unmarshal([]byte(h), &t.Headers)
	json.Unmarshal([]byte(p), &t.Params)
	json.Unmarshal([]byte(c), &t.CredHeaders)
	if t.Headers == nil {
		t.Headers = map[string]string{}
	}
	if t.Params == nil {
		t.Params = []domain.Param{}
	}
	if t.CredHeaders == nil {
		t.CredHeaders = []string{}
	}
	// Keep malformed historical configuration fail-closed at execution/save.
	t.LoadConfig(cfg)
	return &t, nil
}

func saveTool(w *sql.Tx, t *execution.Tool) error {
	if err := validateApproval(t.Approval); err != nil {
		return err
	}
	if t.ConfigError() != nil && execution.IsWSMethod(t.Method) {
		return t.ConfigError()
	}
	if err := inheritSqlGuard(w, t, t.AllowDisableGuard); err != nil {
		return err
	}
	if err := execution.ValidateToolConfig(t.Method, t.Config, false); err != nil {
		return err
	}
	if err := execution.ValidatePresentation(t.Config); err != nil {
		return err
	}
	if err := execution.ValidateWSCredentialBindings(t); err != nil {
		return err
	}
	previous := "off"
	sources := map[int64]bool{}
	if t.ID != 0 {
		var source int64
		if err := w.QueryRow(`SELECT approval,COALESCE(source_request_id,0) FROM tools WHERE id=?`, t.ID).Scan(&previous, &source); err != nil {
			return err
		}
		if t.SourceReqID <= 0 {
			t.SourceReqID = source
		}
		if source > 0 {
			sources[source] = true
		}
		rows, err := w.Query(`SELECT source_request_id FROM tool_approval_sources WHERE tool_id=?`, t.ID)
		if err != nil {
			return err
		}
		for rows.Next() {
			if err := rows.Scan(&source); err != nil {
				rows.Close()
				return err
			}
			sources[source] = true
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	if t.SourceReqID > 0 {
		sources[t.SourceReqID] = true
	}
	if t.Approval == "" {
		t.Approval = defaultApproval(t.Method)
		if t.ID != 0 {
			t.Approval = previous
		}
	}
	if t.Headers == nil {
		t.Headers = map[string]string{}
	}
	if t.Params == nil {
		t.Params = []domain.Param{}
	}
	if t.CredHeaders == nil {
		t.CredHeaders = []string{}
	}
	t.UpdatedAt = now()
	if t.ID == 0 {
		t.CreatedAt = t.UpdatedAt
		r, err := w.Exec(`INSERT INTO tools(name,title,description,method,url,headers,body,params,cred_headers,source_request_id,created_at,updated_at,approval,rev,config) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,1,?)`,
			t.Name, t.Title, t.Description, t.Method, t.URL, js(t.Headers), t.Body, js(t.Params), js(t.CredHeaders), t.SourceReqID, t.CreatedAt, t.UpdatedAt, t.Approval, t.Config.Marshal())
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("工具标识 %q 已存在，请换一个", t.Name)
			}
			return err
		}
		t.Rev = 1
		t.ID, err = r.LastInsertId()
		if err != nil {
			return err
		}
	} else {
		err := w.QueryRow(`UPDATE tools SET name=?,title=?,description=?,method=?,url=?,headers=?,body=?,params=?,cred_headers=?,source_request_id=?,updated_at=?,approval=?,rev=rev+1,config=? WHERE id=? RETURNING rev,created_at`,
			t.Name, t.Title, t.Description, t.Method, t.URL, js(t.Headers), t.Body, js(t.Params), js(t.CredHeaders), t.SourceReqID, t.UpdatedAt, t.Approval, t.Config.Marshal(), t.ID).Scan(&t.Rev, &t.CreatedAt)
		if err != nil && strings.Contains(err.Error(), "UNIQUE") {
			return fmt.Errorf("工具标识 %q 已存在，请换一个", t.Name)
		}
		if err == sql.ErrNoRows {
			return errors.New("工具不存在，无法更新")
		}
		if err != nil {
			return err
		}
	}
	// Console writes may lower this tool, but never its historical source floors.
	for source := range sources {
		if _, err := w.Exec(`INSERT INTO tool_approval_sources(tool_id,source_request_id) VALUES(?,?) ON CONFLICT DO NOTHING`, t.ID, source); err != nil {
			return err
		}
		if _, err := w.Exec(`INSERT INTO source_approval_floor(source_request_id,approval) VALUES(?,?)
ON CONFLICT(source_request_id) DO UPDATE SET approval=CASE
WHEN source_approval_floor.approval='always' OR excluded.approval='always' THEN 'always' ELSE 'off' END`, source, stricterApproval(previous, t.Approval)); err != nil {
			return err
		}
		guard, rows := 0, execution.SQLGuardMaxRowsCap
		if t.Config.SqlGuardEnabled() {
			guard = 1
			rows = t.Config.MaxRows()
		}
		if _, err := w.Exec(`INSERT INTO source_guard_floor(source_request_id,sql_guard,max_rows) VALUES(?,?,?)
ON CONFLICT(source_request_id) DO UPDATE SET
 sql_guard=CASE WHEN source_guard_floor.sql_guard=1 OR excluded.sql_guard=1 THEN 1 ELSE 0 END,
 max_rows=CASE WHEN source_guard_floor.sql_guard=1 OR excluded.sql_guard=1 THEN MIN(source_guard_floor.max_rows, excluded.max_rows) ELSE excluded.max_rows END`,
			source, guard, rows); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) hasColumn(table, col string) bool {
	rows, err := s.db.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		rows.Scan(&n)
		if n == col {
			return true
		}
	}
	return false
}

// GetSetting / SetSetting: small key-value settings stored in the DB (editable in the console).
func (s *Store) GetSetting(key, def string) string {
	var v string
	if err := s.db.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v); err != nil || v == "" {
		return def
	}
	return v
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

func (s *Store) SetSettings(values map[string]string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for key, value := range values {
		if _, err := tx.Exec(`INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Checkpoint() { s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`) }

func (s *Store) ListTools() ([]*execution.Tool, error) {
	rows, err := s.db.Query(`SELECT ` + toolCols + ` FROM tools ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*execution.Tool{}
	for rows.Next() {
		t, err := scanTool(rows)
		if err == nil {
			out = append(out, t)
		}
	}
	rows.Close()
	// pack names
	pr, err := s.db.Query(`SELECT pt.tool_id, p.name FROM pack_tools pt JOIN packs p ON p.id=pt.pack_id ORDER BY p.id`)
	if err == nil {
		m := map[int64][]string{}
		for pr.Next() {
			var id int64
			var n string
			pr.Scan(&id, &n)
			m[id] = append(m[id], n)
		}
		pr.Close()
		for _, t := range out {
			t.Packs = m[t.ID]
		}
	}
	return out, nil
}

func (s *Store) GetTool(id int64) (*execution.Tool, error) {
	return scanTool(s.db.QueryRow(`SELECT `+toolCols+` FROM tools WHERE id=?`, id))
}

func (s *Store) GetToolByName(name string) (*execution.Tool, error) {
	return scanTool(s.db.QueryRow(`SELECT `+toolCols+` FROM tools WHERE name=?`, name))
}

func (s *Store) SaveTool(t *execution.Tool) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := validateApproval(t.Approval); err != nil {
		return err
	}
	if err := saveTool(tx, t); err != nil {
		return err
	}
	return tx.Commit()
}

// Save and attach atomically. Failure rolls back both new tools and overwrites.
func (s *Store) SaveToolInPack(t *execution.Tool, packID int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id int64
	if err := tx.QueryRow(`SELECT id FROM packs WHERE id=?`, packID).Scan(&id); err != nil {
		return fmt.Errorf("流程包不存在或无法读取：%w", err)
	}
	// MCP cannot lower the policy, including when saving under a new name.
	t.Approval = defaultApproval(t.Method)
	if err := inheritToolApproval(tx, t); err != nil {
		return err
	}
	originalID := t.ID
	if err := saveTool(tx, t); err != nil {
		t.ID = originalID
		return err
	}
	if _, err := tx.Exec(`INSERT INTO pack_tools(pack_id,tool_id) VALUES(?,?) ON CONFLICT(pack_id,tool_id) DO NOTHING`, packID, t.ID); err != nil {
		t.ID = originalID
		return err
	}
	var membership int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM pack_tools pt JOIN tools t ON t.id=pt.tool_id JOIN packs p ON p.id=pt.pack_id WHERE pt.pack_id=? AND pt.tool_id=?`, packID, t.ID).Scan(&membership); err != nil {
		t.ID = originalID
		return err
	}
	if membership != 1 {
		t.ID = originalID
		return errors.New("工具或流程包不存在，未能加入流程包")
	}
	if err := tx.Commit(); err != nil {
		t.ID = originalID
		return err
	}
	return nil
}

func (s *Store) DeleteTool(id int64) error {
	_, err := s.db.Exec(`DELETE FROM tools WHERE id=?`, id)
	return err
}

// ExposedTools returns tools that belong to at least one enabled pack.
func (s *Store) ExposedTools() ([]*execution.Tool, error) {
	rows, err := s.db.Query(`SELECT ` + toolCols + ` FROM tools WHERE id IN (SELECT pt.tool_id FROM pack_tools pt JOIN packs p ON p.id=pt.pack_id WHERE p.enabled=1) ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*execution.Tool{}
	for rows.Next() {
		if t, err := scanTool(rows); err == nil {
			out = append(out, t)
		}
	}
	return out, nil
}

func (s *Store) ListPacks() ([]*Pack, error) {
	rows, err := s.db.Query(`SELECT id,name,description,enabled,COALESCE(scenarios,''),COALESCE(guide,''),created_at FROM packs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	out := []*Pack{}
	for rows.Next() {
		var p Pack
		var e int
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &e, &p.Scenarios, &p.Guide, &p.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		p.Enabled = e != 0
		p.ToolIDs = []int64{}
		p.MiddlewareIDs = []int64{}
		out = append(out, &p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	m := map[int64]*Pack{}
	for _, p := range out {
		m[p.ID] = p
	}
	r2, err := s.db.Query(`SELECT pack_id,tool_id FROM pack_tools ORDER BY tool_id`)
	if err != nil {
		return nil, err
	}
	for r2.Next() {
		var pid, tid int64
		if err := r2.Scan(&pid, &tid); err != nil {
			r2.Close()
			return nil, err
		}
		if p := m[pid]; p != nil {
			p.ToolIDs = append(p.ToolIDs, tid)
		}
	}
	if err := r2.Err(); err != nil {
		r2.Close()
		return nil, err
	}
	r2.Close()

	r3, err := s.db.Query(`SELECT pack_id,mw_id FROM pack_middleware ORDER BY mw_id`)
	if err != nil {
		return nil, err
	}
	for r3.Next() {
		var pid, mid int64
		if err := r3.Scan(&pid, &mid); err != nil {
			r3.Close()
			return nil, err
		}
		if p := m[pid]; p != nil {
			p.MiddlewareIDs = append(p.MiddlewareIDs, mid)
		}
	}
	if err := r3.Err(); err != nil {
		r3.Close()
		return nil, err
	}
	r3.Close()

	return out, nil
}

func (s *Store) SavePack(p *Pack) error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("流程包名称不能为空")
	}
	if p.ID == 0 && strings.EqualFold(strings.TrimSpace(p.Name), RecordingPackName) {
		return errors.New("流程包名称「录制分析」是内置包，请换一个名字")
	}
	p.Guide = strings.TrimSpace(p.Guide)
	if len(p.Guide) > maxPackGuideBytes {
		return fmt.Errorf("使用说明最长 %dKB", maxPackGuideBytes/1024)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if p.ID == 0 {
		r, err := tx.Exec(`INSERT INTO packs(name,description,enabled,scenarios,guide,created_at) VALUES(?,?,?,?,?,?)`, p.Name, p.Description, b2i(p.Enabled), p.Scenarios, p.Guide, now())
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("流程包 %q 已存在", p.Name)
			}
			return err
		}
		p.ID, err = r.LastInsertId()
		if err != nil {
			return err
		}
	} else {
		r, err := tx.Exec(`UPDATE packs SET name=?,description=?,enabled=?,scenarios=?,guide=? WHERE id=?`, p.Name, p.Description, b2i(p.Enabled), p.Scenarios, p.Guide, p.ID)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("流程包 %q 已存在", p.Name)
			}
			return err
		}
		n, err := r.RowsAffected()
		if err != nil {
			return err
		}
		if n != 1 {
			return errors.New("流程包不存在，无法更新")
		}
	}
	if p.ToolIDs != nil {
		if _, err := tx.Exec(`DELETE FROM pack_tools WHERE pack_id=?`, p.ID); err != nil {
			return err
		}
		for _, tid := range p.ToolIDs {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO pack_tools(pack_id,tool_id) VALUES(?,?)`, p.ID, tid); err != nil {
				return err
			}
		}
	}
	if p.MiddlewareIDs != nil {
		if _, err := tx.Exec(`DELETE FROM pack_middleware WHERE pack_id=?`, p.ID); err != nil {
			return err
		}
		for _, mid := range p.MiddlewareIDs {
			if _, err := tx.Exec(`INSERT OR IGNORE INTO pack_middleware(pack_id,mw_id) VALUES(?,?)`, p.ID, mid); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// AddPackMembers adds tools / middleware to a pack without touching other members.
// kind is "tools" or "middleware". Unknown ids are ignored.
func (s *Store) AddPackMembers(packID int64, kind string, ids []int64) (int, error) {
	table, col, src := "pack_tools", "tool_id", "tools"
	if kind == "middleware" {
		table, col, src = "pack_middleware", "mw_id", "middleware"
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM packs WHERE id=?`, packID).Scan(&n); err != nil || n == 0 {
		return 0, errors.New("流程包不存在")
	}
	added := 0
	for _, id := range ids {
		r, err := s.db.Exec(`INSERT OR IGNORE INTO `+table+`(pack_id,`+col+`) SELECT ?, id FROM `+src+` WHERE id=?`, packID, id)
		if err != nil {
			return added, err
		}
		if k, _ := r.RowsAffected(); k > 0 {
			added++
		}
	}
	return added, nil
}

// RemovePackMember removes one tool / middleware from a pack (the tool itself is kept).
func (s *Store) RemovePackMember(packID int64, kind string, id int64) (bool, error) {
	table, col := "pack_tools", "tool_id"
	if kind == "middleware" {
		table, col = "pack_middleware", "mw_id"
	}
	r, err := s.db.Exec(`DELETE FROM `+table+` WHERE pack_id=? AND `+col+`=?`, packID, id)
	if err != nil {
		return false, err
	}
	k, _ := r.RowsAffected()
	return k > 0, nil
}

func (s *Store) SetPackEnabled(id int64, en bool) error {
	_, err := s.db.Exec(`UPDATE packs SET enabled=? WHERE id=?`, b2i(en), id)
	return err
}

func (s *Store) DeletePack(id int64) error {
	_, err := s.db.Exec(`DELETE FROM packs WHERE id=?`, id)
	return err
}

func (s *Store) SaveCookies(cs []execution.Cookie) {
	if len(cs) == 0 {
		return
	}
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	for _, c := range cs {
		tx.Exec(`INSERT OR REPLACE INTO cookie_jar(name,domain,path,value,expires,secure,http_only,session,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`,
			c.Name, c.Domain, c.Path, c.Value, c.Expires, b2i(c.Secure), b2i(c.HTTPOnly), b2i(c.Session), now())
	}
	tx.Commit()
}

// ReplaceCookies replaces the whole jar with a fresh browser snapshot.
func (s *Store) ReplaceCookies(cs []execution.Cookie) {
	tx, err := s.db.Begin()
	if err != nil {
		return
	}
	tx.Exec(`DELETE FROM cookie_jar`)
	for _, c := range cs {
		tx.Exec(`INSERT OR REPLACE INTO cookie_jar(name,domain,path,value,expires,secure,http_only,session,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`,
			c.Name, c.Domain, c.Path, c.Value, c.Expires, b2i(c.Secure), b2i(c.HTTPOnly), b2i(c.Session), now())
	}
	tx.Commit()
}

func (s *Store) AllCookies() []execution.Cookie {
	rows, err := s.db.Query(`SELECT name,domain,path,value,expires,secure,http_only,session FROM cookie_jar`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []execution.Cookie
	for rows.Next() {
		var c execution.Cookie
		var a, b, d int
		rows.Scan(&c.Name, &c.Domain, &c.Path, &c.Value, &c.Expires, &a, &b, &d)
		c.Secure, c.HTTPOnly, c.Session = a != 0, b != 0, d != 0
		out = append(out, c)
	}
	return out
}

func (s *Store) ClearCookies() { s.db.Exec(`DELETE FROM cookie_jar`) }

// DB returns the shared SQLite handle so composed repositories (vault, login headers)
// use the same single connection and transaction ordering as before.
func (s *Store) DB() *sql.DB { return s.db }
