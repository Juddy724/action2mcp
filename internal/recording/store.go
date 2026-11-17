package recording

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

type groupOverride struct {
	seq int
	id  int64
	on  bool
}

type Store struct {
	db      *sql.DB
	ovMu    sync.Mutex
	ovGen   map[int64]uint64
	ovCache map[int64]map[string][]groupOverride
}

func NewStore(db *sql.DB) *Store { return &Store{db: db} }

func recordNow() string { return time.Now().Format("2006-01-02 15:04:05") }

func recordJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func recordBool(b bool) int {
	if b {
		return 1
	}
	return 0
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

// RedactRequestBody overwrites a stored request body (e.g. a recorded login with a password) and
// checkpoints the WAL so the old value is not left in the journal.
func (s *Store) RedactRequestBody(id int64, body string) error {
	_, err := s.db.Exec(`UPDATE requests SET req_body=? WHERE id=?`, body, id)
	s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return err
}

// ---------- recordings ----------

func (s *Store) CreateRecording(name, startURL string) (int64, error) {
	r, err := s.db.Exec(`INSERT INTO recordings(name,start_url,status,created_at) VALUES(?,?,?,?)`, name, startURL, "recording", recordNow())
	if err != nil {
		return 0, err
	}
	return r.LastInsertId()
}

func (s *Store) FinishRecording(id int64) {
	s.db.Exec(`UPDATE recordings SET status='done', ended_at=? WHERE id=?`, recordNow(), id)
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
	if utf8.RuneCountInString(summary) > MaxSummaryRunes {
		return fmt.Errorf("%w: 录制说明最长 %d 字", ErrInvalidNote, MaxSummaryRunes)
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

func (s *Store) UpdateRequest(q *Request) error {
	_, err := s.db.Exec(`UPDATE requests SET url=?, status=?, req_headers=?, req_body=?, resp_headers=?, resp_body=?, resp_mime=?, noise=?, noise_reason=? WHERE id=?`,
		q.URL, q.Status, recordJSON(q.ReqHeaders), q.ReqBody, recordJSON(q.RespHeaders), q.RespBody, q.RespMime, recordBool(q.Noise), q.NoiseReason, q.ID)
	return err
}

func (s *Store) InsertRequest(q *Request) error {
	r, err := s.db.Exec(`INSERT INTO requests(recording_id,seq,method,url,resource_type,req_headers,req_body,status,resp_headers,resp_body,resp_mime,noise,noise_reason,ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		q.RecordingID, q.Seq, q.Method, q.URL, q.ResourceType, recordJSON(q.ReqHeaders), q.ReqBody, q.Status, recordJSON(q.RespHeaders), q.RespBody, q.RespMime, recordBool(q.Noise), q.NoiseReason, q.TS)
	if err != nil {
		return err
	}
	q.ID, _ = r.LastInsertId()
	return nil
}

func (s *Store) ListRequests(recID int64) ([]Request, error) {
	rows, err := s.db.Query(`SELECT id,recording_id,seq,method,url,resource_type,status,resp_mime,noise,noise_reason,ts,length(req_body),length(resp_body) FROM requests WHERE recording_id=? ORDER BY seq`, recID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Request{}
	for rows.Next() {
		var q Request
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

func (s *Store) GetRequest(id int64) (*Request, error) {
	var q Request
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
var ErrInvalidNote = errors.New("标注无效")

const (
	MaxPurposeRunes = 500
	MaxSummaryRunes = 2000
)

func (s *Store) SetRequestNote(n Note) error {
	switch n.Category {
	case "query", "write", "auth", "config", "page", "noise":
	default:
		return fmt.Errorf("%w: 分类必须是 query、write、auth、config、page 或 noise", ErrInvalidNote)
	}
	if n.Source != "agent" && n.Source != "user" {
		return fmt.Errorf("%w: 标注来源必须是 agent 或 user", ErrInvalidNote)
	}
	n.Purpose = strings.TrimSpace(n.Purpose)
	if utf8.RuneCountInString(n.Purpose) > MaxPurposeRunes {
		return fmt.Errorf("%w: 作用说明最长 %d 字", ErrInvalidNote, MaxPurposeRunes)
	}
	var method, rawURL string
	if err := s.db.QueryRow(`SELECT method, url FROM requests WHERE id=? AND recording_id=?`, n.RequestID, n.RecordingID).Scan(&method, &rawURL); err != nil {
		return err
	}
	_, _, _, gkey := GroupKey(method, rawURL)
	r, err := s.db.Exec(`INSERT INTO request_notes(request_id,recording_id,purpose,category,useful,noise_override,source,updated_at,group_key)
	 SELECT id,recording_id,?,?,?,?,?,?,? FROM requests WHERE id=? AND recording_id=?
	 ON CONFLICT(request_id) DO UPDATE SET purpose=excluded.purpose,category=excluded.category,
	 useful=excluded.useful,noise_override=excluded.noise_override,source=excluded.source,updated_at=excluded.updated_at,group_key=excluded.group_key`,
		n.Purpose, n.Category, n.Useful, n.NoiseOverride, n.Source, recordNow(), gkey, n.RequestID, n.RecordingID)
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

func (s *Store) RequestNotes(recordingID int64) (map[int64]Note, error) {
	rows, err := s.db.Query(`SELECT request_id,recording_id,purpose,category,useful,noise_override,source,updated_at
	 FROM request_notes WHERE recording_id=?`, recordingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]Note{}
	for rows.Next() {
		var n Note
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

func (s *Store) BackfillNoteGroupKeys() error {
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
		_, _, _, key := GroupKey(p.method, p.rawURL)
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
	_, _, _, want := GroupKey(method, rawURL)
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
