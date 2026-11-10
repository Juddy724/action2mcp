package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

type groupOverride struct {
	seq int
	id  int64
	on  bool
}

type Store struct {
	db     *sql.DB
	siteMu sync.Mutex
	ovMu   sync.Mutex
	ovGen  map[int64]uint64
	// recording → group key → overrides, sorted by seq, id
	ovCache map[int64]map[string][]groupOverride
}

type Recording struct {
	ID           int64  `json:"id"`
	Name         string `json:"name"`
	Summary      string `json:"summary"`
	StartURL     string `json:"start_url"`
	Status       string `json:"status"`
	CreatedAt    string `json:"created_at"`
	EndedAt      string `json:"ended_at"`
	RequestCount int    `json:"request_count"`
	UsefulCount  int    `json:"useful_count"`
}

type ReqRecord struct {
	ID             int64             `json:"id"`
	RecordingID    int64             `json:"recording_id"`
	Seq            int               `json:"seq"`
	Method         string            `json:"method"`
	URL            string            `json:"url"`
	ResourceType   string            `json:"resource_type"`
	ReqHeaders     map[string]string `json:"req_headers,omitempty"`
	ReqBody        string            `json:"req_body,omitempty"`
	Status         int               `json:"status"`
	RespHeaders    map[string]string `json:"resp_headers,omitempty"`
	RespBody       string            `json:"resp_body,omitempty"`
	RespMime       string            `json:"resp_mime"`
	Noise          bool              `json:"noise"`
	NoiseHeuristic bool              `json:"noise_heuristic"`
	Note           *RequestNote      `json:"note"`
	NoiseReason    string            `json:"noise_reason"`
	TS             string            `json:"ts"`
	ReqSize        int               `json:"req_size"`
	RespSize       int               `json:"resp_size"`
	IsLogin        bool              `json:"is_login,omitempty"`
}

type RequestNote struct {
	RequestID     int64  `json:"request_id"`
	RecordingID   int64  `json:"recording_id"`
	Purpose       string `json:"purpose"`
	Category      string `json:"category"`
	Useful        *bool  `json:"useful"`
	NoiseOverride *bool  `json:"noise_override"`
	Source        string `json:"source"`
	UpdatedAt     string `json:"updated_at"`
}

type Param struct {
	Name        string `json:"name"`
	Type        string `json:"type"` // string|number|integer|boolean
	Description string `json:"description"`
	Required    bool   `json:"required"`
	Default     string `json:"default,omitempty"`
}

type Tool struct {
	ID          int64             `json:"id"`
	Name        string            `json:"name"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	Params      []Param           `json:"params"`
	CredHeaders []string          `json:"cred_headers"`
	SourceReqID int64             `json:"source_request_id,omitempty"`
	CreatedAt   string            `json:"created_at,omitempty"`
	UpdatedAt   string            `json:"updated_at,omitempty"`
	Packs       []string          `json:"packs,omitempty"`
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

func now() string { return time.Now().Format("2006-01-02 15:04:05") }

func OpenStore(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=secure_delete(1)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
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
CREATE TABLE IF NOT EXISTS packs(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, description TEXT, enabled INTEGER, created_at TEXT);
CREATE TABLE IF NOT EXISTS pack_tools(pack_id INTEGER REFERENCES packs(id) ON DELETE CASCADE, tool_id INTEGER REFERENCES tools(id) ON DELETE CASCADE, PRIMARY KEY(pack_id, tool_id));
CREATE TABLE IF NOT EXISTS cookie_jar(name TEXT, domain TEXT, path TEXT, value TEXT, expires REAL, secure INTEGER, http_only INTEGER, session INTEGER, updated_at TEXT, PRIMARY KEY(name, domain, path));
CREATE TABLE IF NOT EXISTS vault(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, type TEXT, value_enc TEXT, site TEXT DEFAULT '', note TEXT DEFAULT '', created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS sites(id INTEGER PRIMARY KEY AUTOINCREMENT, origin TEXT UNIQUE, config TEXT, status TEXT DEFAULT 'unknown', last_login_at TEXT DEFAULT '', last_check_at TEXT DEFAULT '', last_error TEXT DEFAULT '', login_count INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS middleware(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, type TEXT, config TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS pack_middleware(pack_id INTEGER REFERENCES packs(id) ON DELETE CASCADE, mw_id INTEGER REFERENCES middleware(id) ON DELETE CASCADE, PRIMARY KEY(pack_id, mw_id));
CREATE TABLE IF NOT EXISTS mw_audit(id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, client TEXT, mw TEXT, tool TEXT, action TEXT, perm TEXT, allowed INTEGER, result TEXT, ms INTEGER);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT);

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
		if err := s.backfillNoteGroupKeys(); err != nil {
			return nil, err
		}
	}
	if _, err := db.Exec(`PRAGMA user_version=5`); err != nil {
		return nil, err
	}
	// recordings left in "recording" state by a crash are finished now
	db.Exec(`UPDATE recordings SET status='done', ended_at=? WHERE status='recording'`, now())
	return s, nil
}

// RedactRequestBody overwrites a stored request body (e.g. a recorded login with a password) and
// checkpoints the WAL so the old value is not left in the journal.
func (s *Store) RedactRequestBody(id int64, body string) error {
	_, err := s.db.Exec(`UPDATE requests SET req_body=? WHERE id=?`, body, id)
	s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
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

func js(v any) string { b, _ := json.Marshal(v); return string(b) }

// ---------- recordings ----------

func (s *Store) CreateRecording(name, startURL string) (int64, error) {
	r, err := s.db.Exec(`INSERT INTO recordings(name,start_url,status,created_at) VALUES(?,?,?,?)`, name, startURL, "recording", now())
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

func (s *Store) FinishRecording(id int64) {
	s.db.Exec(`UPDATE recordings SET status='done', ended_at=? WHERE id=?`, now(), id)
}

func (s *Store) ListRecordings() ([]Recording, error) {
	rows, err := s.db.Query(`SELECT r.id,r.name,r.summary,r.start_url,r.status,r.created_at,r.ended_at,
	 (SELECT COUNT(*) FROM requests q WHERE q.recording_id=r.id),
	 (SELECT COUNT(*) FROM requests q LEFT JOIN request_notes n ON n.request_id=q.id
	  WHERE q.recording_id=r.id AND COALESCE(n.noise_override,q.noise)=0)
	 FROM recordings r ORDER BY r.id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Recording{}
	for rows.Next() {
		var r Recording
		if err := rows.Scan(&r.ID, &r.Name, &r.Summary, &r.StartURL, &r.Status, &r.CreatedAt, &r.EndedAt, &r.RequestCount, &r.UsefulCount); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) GetRecording(id int64) (*Recording, error) {
	var r Recording
	err := s.db.QueryRow(`SELECT id,name,summary,start_url,status,created_at,ended_at,(SELECT COUNT(*) FROM requests q WHERE q.recording_id=recordings.id),
	 (SELECT COUNT(*) FROM requests q LEFT JOIN request_notes n ON n.request_id=q.id
	  WHERE q.recording_id=recordings.id AND COALESCE(n.noise_override,q.noise)=0) FROM recordings WHERE id=?`, id).
		Scan(&r.ID, &r.Name, &r.Summary, &r.StartURL, &r.Status, &r.CreatedAt, &r.EndedAt, &r.RequestCount, &r.UsefulCount)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func (s *Store) SetRecordingSummary(recordingID int64, summary string) error {
	summary = strings.TrimSpace(summary)
	if utf8.RuneCountInString(summary) > maxRecordingSummaryRunes {
		return fmt.Errorf("%w: 录制说明最长 %d 字", errInvalidNote, maxRecordingSummaryRunes)
	}
	r, err := s.db.Exec(`UPDATE recordings SET summary=? WHERE id=?`, summary, recordingID)
	if err != nil {
		return err
	}
	if n, err := r.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) DeleteRecording(id int64) error {
	_, err := s.db.Exec(`DELETE FROM recordings WHERE id=?`, id)
	return err
}

func (s *Store) UpdateRequest(q *ReqRecord) error {
	_, err := s.db.Exec(`UPDATE requests SET url=?, status=?, req_headers=?, req_body=?, resp_headers=?, resp_body=?, resp_mime=?, noise=?, noise_reason=? WHERE id=?`,
		q.URL, q.Status, js(q.ReqHeaders), q.ReqBody, js(q.RespHeaders), q.RespBody, q.RespMime, b2i(q.Noise), q.NoiseReason, q.ID)
	return err
}

func (s *Store) InsertRequest(q *ReqRecord) error {
	r, err := s.db.Exec(`INSERT INTO requests(recording_id,seq,method,url,resource_type,req_headers,req_body,status,resp_headers,resp_body,resp_mime,noise,noise_reason,ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		q.RecordingID, q.Seq, q.Method, q.URL, q.ResourceType, js(q.ReqHeaders), q.ReqBody, q.Status, js(q.RespHeaders), q.RespBody, q.RespMime, b2i(q.Noise), q.NoiseReason, q.TS)
	if err != nil {
		return err
	}
	q.ID, _ = r.LastInsertId()
	return nil
}

func (s *Store) ListRequests(recID int64) ([]ReqRecord, error) {
	rows, err := s.db.Query(`SELECT id,recording_id,seq,method,url,resource_type,status,resp_mime,noise,noise_reason,ts,length(req_body),length(resp_body) FROM requests WHERE recording_id=? ORDER BY seq`, recID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReqRecord{}
	for rows.Next() {
		var q ReqRecord
		var n int
		if err := rows.Scan(&q.ID, &q.RecordingID, &q.Seq, &q.Method, &q.URL, &q.ResourceType, &q.Status, &q.RespMime, &n, &q.NoiseReason, &q.TS, &q.ReqSize, &q.RespSize); err != nil {
			return nil, err
		}
		q.Noise = n != 0
		q.NoiseHeuristic = q.Noise
		out = append(out, q)
	}
	return out, rows.Err()
}

func (s *Store) GetRequest(id int64) (*ReqRecord, error) {
	var q ReqRecord
	var rh, sh string
	var n int
	err := s.db.QueryRow(`SELECT id,recording_id,seq,method,url,resource_type,req_headers,req_body,status,resp_headers,resp_body,resp_mime,noise,noise_reason,ts FROM requests WHERE id=?`, id).
		Scan(&q.ID, &q.RecordingID, &q.Seq, &q.Method, &q.URL, &q.ResourceType, &rh, &q.ReqBody, &q.Status, &sh, &q.RespBody, &q.RespMime, &n, &q.NoiseReason, &q.TS)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(rh), &q.ReqHeaders); err != nil {
		return nil, fmt.Errorf("无法解析请求头：%w", err)
	}
	if err := json.Unmarshal([]byte(sh), &q.RespHeaders); err != nil {
		return nil, fmt.Errorf("无法解析响应头：%w", err)
	}
	q.Noise = n != 0
	q.NoiseHeuristic = q.Noise
	return &q, nil
}

// SetRequestNote replaces a note, including nullable judgements. The request must
// belong to RecordingID; annotations never change the recorded noise heuristic.
// errInvalidNote marks validation failures of notes and summaries (HTTP 400).
var errInvalidNote = errors.New("标注无效")

const (
	maxRequestPurposeRunes   = 500
	maxRecordingSummaryRunes = 2000
)

func (s *Store) SetRequestNote(n RequestNote) error {
	switch n.Category {
	case "query", "write", "auth", "config", "page", "noise":
	default:
		return fmt.Errorf("%w: 分类必须是 query、write、auth、config、page 或 noise", errInvalidNote)
	}
	if n.Source != "agent" && n.Source != "user" {
		return fmt.Errorf("%w: 标注来源必须是 agent 或 user", errInvalidNote)
	}
	n.Purpose = strings.TrimSpace(n.Purpose)
	if utf8.RuneCountInString(n.Purpose) > maxRequestPurposeRunes {
		return fmt.Errorf("%w: 作用说明最长 %d 字", errInvalidNote, maxRequestPurposeRunes)
	}
	var method, rawURL string
	if err := s.db.QueryRow(`SELECT method, url FROM requests WHERE id=? AND recording_id=?`, n.RequestID, n.RecordingID).Scan(&method, &rawURL); err != nil {
		return err
	}
	_, _, _, gkey := requestGroupKey(method, rawURL)
	r, err := s.db.Exec(`INSERT INTO request_notes(request_id,recording_id,purpose,category,useful,noise_override,source,updated_at,group_key)
	 SELECT id,recording_id,?,?,?,?,?,?,? FROM requests WHERE id=? AND recording_id=?
	 ON CONFLICT(request_id) DO UPDATE SET purpose=excluded.purpose,category=excluded.category,
	 useful=excluded.useful,noise_override=excluded.noise_override,source=excluded.source,updated_at=excluded.updated_at,group_key=excluded.group_key`,
		n.Purpose, n.Category, n.Useful, n.NoiseOverride, n.Source, now(), gkey, n.RequestID, n.RecordingID)
	if err != nil {
		return err
	}
	if count, err := r.RowsAffected(); err != nil {
		return err
	} else if count == 0 {
		return sql.ErrNoRows
	}
	s.invalidateOverrides(n.RecordingID)
	return nil
}

func (s *Store) RequestNotes(recordingID int64) (map[int64]RequestNote, error) {
	rows, err := s.db.Query(`SELECT request_id,recording_id,purpose,category,useful,noise_override,source,updated_at
	 FROM request_notes WHERE recording_id=?`, recordingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]RequestNote{}
	for rows.Next() {
		var n RequestNote
		if err := rows.Scan(&n.RequestID, &n.RecordingID, &n.Purpose, &n.Category, &n.Useful, &n.NoiseOverride, &n.Source, &n.UpdatedAt); err != nil {
			return nil, err
		}
		out[n.RequestID] = n
	}
	return out, rows.Err()
}

func (s *Store) DeleteRequestNote(requestID int64) error {
	var recordingID int64
	_ = s.db.QueryRow(`SELECT recording_id FROM request_notes WHERE request_id=?`, requestID).Scan(&recordingID)
	_, err := s.db.Exec(`DELETE FROM request_notes WHERE request_id=?`, requestID)
	if err == nil && recordingID != 0 {
		s.invalidateOverrides(recordingID)
	}
	return err
}

func (s *Store) invalidateOverrides(recordingID int64) {
	s.ovMu.Lock()
	defer s.ovMu.Unlock()
	if s.ovGen == nil {
		s.ovGen = map[int64]uint64{}
	}
	s.ovGen[recordingID]++
	if s.ovCache != nil {
		delete(s.ovCache, recordingID)
	}
}

func (s *Store) backfillNoteGroupKeys() error {
	rows, err := s.db.Query(`SELECT n.request_id, r.method, r.url FROM request_notes n JOIN requests r ON r.id = n.request_id WHERE n.group_key = ''`)
	if err != nil {
		return err
	}
	type pair struct {
		id             int64
		method, rawURL string
	}
	var pending []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.id, &p.method, &p.rawURL); err != nil {
			rows.Close()
			return err
		}
		pending = append(pending, p)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()
	if len(pending) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, p := range pending {
		_, _, _, key := requestGroupKey(p.method, p.rawURL)
		if _, err := tx.Exec(`UPDATE request_notes SET group_key=? WHERE request_id=?`, key, p.id); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func overrideIsEarlier(seq int, id int64, curSeq int, curID int64) bool {
	if curID != 0 && id == curID {
		return false
	}
	// A request that has not been inserted yet is after every stored note.
	if curSeq <= 0 && curID == 0 {
		return true
	}
	if seq < curSeq {
		return true
	}
	if seq == curSeq && curID != 0 && id < curID {
		return true
	}
	return false
}

func (s *Store) loadGroupOverrides(recordingID int64) (map[string][]groupOverride, error) {
	rows, err := s.db.Query(`SELECT r.seq, r.id, n.group_key, n.noise_override FROM request_notes n
		JOIN requests r ON r.id = n.request_id
		WHERE n.recording_id = ? AND n.noise_override IS NOT NULL AND n.group_key != ''`, recordingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]groupOverride{}
	for rows.Next() {
		var h groupOverride
		var key string
		var ov int
		if err := rows.Scan(&h.seq, &h.id, &key, &ov); err != nil {
			return nil, err
		}
		h.on = ov != 0
		out[key] = append(out[key], h)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for key, hits := range out {
		sortGroupOverrides(hits)
		out[key] = hits
	}
	return out, nil
}

func sortGroupOverrides(hits []groupOverride) {
	for i := 1; i < len(hits); i++ {
		j := i
		for j > 0 && (hits[j].seq < hits[j-1].seq || (hits[j].seq == hits[j-1].seq && hits[j].id < hits[j-1].id)) {
			hits[j], hits[j-1] = hits[j-1], hits[j]
			j--
		}
	}
}

// NoiseOverrideForGroup returns a genuinely earlier note's noise_override for
// the same templated method+host+path. The current request is never a source,
// so a later flush cannot copy its own annotation into the stored heuristic.
// Results are cached per recording and dropped when notes change. The load
// uses idx_request_notes_group and does not sort in SQLite.
func (s *Store) NoiseOverrideForGroup(recordingID int64, method, rawURL string, seq int, id int64) (override bool, ok bool, err error) {
	_, _, _, want := requestGroupKey(method, rawURL)
	s.ovMu.Lock()
	gen := uint64(0)
	if s.ovGen != nil {
		gen = s.ovGen[recordingID]
	}
	if s.ovCache != nil {
		if groups, hit := s.ovCache[recordingID]; hit {
			s.ovMu.Unlock()
			return earlierOverride(groups[want], seq, id)
		}
	}
	s.ovMu.Unlock()
	groups, err := s.loadGroupOverrides(recordingID)
	if err != nil {
		return false, false, err
	}
	s.ovMu.Lock()
	if s.ovGen == nil {
		s.ovGen = map[int64]uint64{}
	}
	if s.ovGen[recordingID] == gen {
		if s.ovCache == nil {
			s.ovCache = map[int64]map[string][]groupOverride{}
		}
		s.ovCache[recordingID] = groups
	}
	s.ovMu.Unlock()
	return earlierOverride(groups[want], seq, id)
}

func earlierOverride(hits []groupOverride, seq int, id int64) (bool, bool, error) {
	for _, h := range hits {
		if overrideIsEarlier(h.seq, h.id, seq, id) {
			return h.on, true, nil
		}
	}
	return false, false, nil
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ---------- tools ----------

const toolCols = `id,name,title,description,method,url,headers,body,params,cred_headers,source_request_id,created_at,updated_at`

func scanTool(sc interface{ Scan(...any) error }) (*Tool, error) {
	var t Tool
	var h, p, c string
	var src sql.NullInt64
	if err := sc.Scan(&t.ID, &t.Name, &t.Title, &t.Description, &t.Method, &t.URL, &h, &t.Body, &p, &c, &src, &t.CreatedAt, &t.UpdatedAt); err != nil {
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
		t.Params = []Param{}
	}
	if t.CredHeaders == nil {
		t.CredHeaders = []string{}
	}
	return &t, nil
}

func (s *Store) ListTools() ([]*Tool, error) {
	rows, err := s.db.Query(`SELECT ` + toolCols + ` FROM tools ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Tool{}
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

func (s *Store) GetTool(id int64) (*Tool, error) {
	return scanTool(s.db.QueryRow(`SELECT `+toolCols+` FROM tools WHERE id=?`, id))
}

func (s *Store) GetToolByName(name string) (*Tool, error) {
	return scanTool(s.db.QueryRow(`SELECT `+toolCols+` FROM tools WHERE name=?`, name))
}

func (s *Store) SaveTool(t *Tool) error {
	return saveTool(s.db, t)
}

type toolWriter interface {
	Exec(string, ...any) (sql.Result, error)
}

func saveTool(w toolWriter, t *Tool) error {
	if t.Headers == nil {
		t.Headers = map[string]string{}
	}
	if t.Params == nil {
		t.Params = []Param{}
	}
	if t.CredHeaders == nil {
		t.CredHeaders = []string{}
	}
	t.UpdatedAt = now()
	if t.ID == 0 {
		t.CreatedAt = t.UpdatedAt
		r, err := w.Exec(`INSERT INTO tools(name,title,description,method,url,headers,body,params,cred_headers,source_request_id,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
			t.Name, t.Title, t.Description, t.Method, t.URL, js(t.Headers), t.Body, js(t.Params), js(t.CredHeaders), t.SourceReqID, t.CreatedAt, t.UpdatedAt)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				return fmt.Errorf("工具标识 %q 已存在，请换一个", t.Name)
			}
			return err
		}
		t.ID, err = r.LastInsertId()
		return err
	}
	r, err := w.Exec(`UPDATE tools SET name=?,title=?,description=?,method=?,url=?,headers=?,body=?,params=?,cred_headers=?,updated_at=? WHERE id=?`,
		t.Name, t.Title, t.Description, t.Method, t.URL, js(t.Headers), t.Body, js(t.Params), js(t.CredHeaders), t.UpdatedAt, t.ID)
	if err != nil && strings.Contains(err.Error(), "UNIQUE") {
		return fmt.Errorf("工具标识 %q 已存在，请换一个", t.Name)
	}
	if err != nil {
		return err
	}
	n, err := r.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("工具不存在，无法更新")
	}
	return nil
}

// Save and attach atomically. Failure rolls back both new tools and overwrites.
func (s *Store) SaveToolInPack(t *Tool, packID int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id int64
	if err := tx.QueryRow(`SELECT id FROM packs WHERE id=?`, packID).Scan(&id); err != nil {
		return fmt.Errorf("流程包不存在或无法读取：%w", err)
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
func (s *Store) ExposedTools() ([]*Tool, error) {
	rows, err := s.db.Query(`SELECT ` + toolCols + ` FROM tools WHERE id IN (SELECT pt.tool_id FROM pack_tools pt JOIN packs p ON p.id=pt.pack_id WHERE p.enabled=1) ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Tool{}
	for rows.Next() {
		if t, err := scanTool(rows); err == nil {
			out = append(out, t)
		}
	}
	return out, nil
}

// ---------- packs ----------

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
	if p.ID == 0 && strings.EqualFold(strings.TrimSpace(p.Name), recPackName) {
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

// ---------- cookie jar (local only, never exported) ----------

func (s *Store) SaveCookies(cs []Cookie) {
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
func (s *Store) ReplaceCookies(cs []Cookie) {
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

func (s *Store) AllCookies() []Cookie {
	rows, err := s.db.Query(`SELECT name,domain,path,value,expires,secure,http_only,session FROM cookie_jar`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []Cookie
	for rows.Next() {
		var c Cookie
		var a, b, d int
		rows.Scan(&c.Name, &c.Domain, &c.Path, &c.Value, &c.Expires, &a, &b, &d)
		c.Secure, c.HTTPOnly, c.Session = a != 0, b != 0, d != 0
		out = append(out, c)
	}
	return out
}

func (s *Store) ClearCookies() { s.db.Exec(`DELETE FROM cookie_jar`) }
