package store

import (
	"action2mcp/internal/recording"
	"database/sql"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRequestNotesStore(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "notes.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.Close() })
	recID, err := s.CreateRecording("线上问题排查", "https://example.com/issues")
	if err != nil {
		t.Fatal(err)
	}
	otherID, err := s.CreateRecording("其他录制", "https://example.com/other")
	if err != nil {
		t.Fatal(err)
	}
	q := &recording.Request{RecordingID: recID, Method: "GET", URL: "https://example.com/api/logs", Noise: true}
	if err := s.InsertRequest(q); err != nil {
		t.Fatal(err)
	}
	if notes, err := s.RequestNotes(recID); err != nil || notes == nil || len(notes) != 0 {
		t.Fatalf("empty notes = %v, %v", notes, err)
	}
	values := []*bool{nil, new(true), new(false)}
	categories := []string{"query", "write", "auth", "config", "page", "noise"}
	for i, useful := range values {
		for j, override := range values {
			n := recording.Note{RequestID: q.ID, RecordingID: recID, Purpose: "按订单号查询业务日志。",
				Category: categories[(i*3+j)%len(categories)], Useful: useful, NoiseOverride: override,
				Source: "agent", UpdatedAt: "2000-01-01 00:00:00"}
			if i%2 != 0 {
				n.Source = "user"
			}
			if err := s.SetRequestNote(n); err != nil {
				t.Fatal(err)
			}
			notes, err := s.RequestNotes(recID)
			if err != nil || len(notes) != 1 {
				t.Fatalf("notes = %v, %v", notes, err)
			}
			got := notes[q.ID]
			if _, err := time.Parse("2006-01-02 15:04:05", got.UpdatedAt); err != nil || got.UpdatedAt == n.UpdatedAt {
				t.Fatalf("timestamp was not generated: %q", got.UpdatedAt)
			}
			n.UpdatedAt = got.UpdatedAt
			if !reflect.DeepEqual(got, n) {
				t.Fatalf("round trip = %+v, want %+v", got, n)
			}
		}
	}
	if notes, err := s.RequestNotes(otherID); err != nil || len(notes) != 0 {
		t.Fatalf("notes leaked across recordings: %v, %v", notes, err)
	}
	before, _ := s.RequestNotes(recID)
	bad := before[q.ID]
	bad.RecordingID = otherID
	if err := s.SetRequestNote(bad); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("mismatched recording accepted: %v", err)
	}
	bad.RecordingID, bad.RequestID = recID, q.ID+100
	if err := s.SetRequestNote(bad); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing request accepted: %v", err)
	}
	for _, field := range []string{"category", "source"} {
		bad = before[q.ID]
		if field == "category" {
			bad.Category = "invalid"
		} else {
			bad.Source = "invalid"
		}
		if err := s.SetRequestNote(bad); err == nil {
			t.Fatalf("invalid %s accepted", field)
		}
	}
	after, err := s.RequestNotes(recID)
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("rejected upsert changed data: %v, %v", after, err)
	}
	if raw, err := s.GetRequest(q.ID); err != nil || !raw.Noise {
		t.Fatalf("annotation changed heuristic: %+v, %v", raw, err)
	}
	if err := s.DeleteRequestNote(q.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRequestNote(q.ID); err != nil {
		t.Fatal("delete must be idempotent:", err)
	}
	if notes, err := s.RequestNotes(recID); err != nil || len(notes) != 0 {
		t.Fatalf("note not deleted: %v, %v", notes, err)
	}
	if err := s.SetRecordingSummary(recID, "先查订单，再查业务日志定位问题。"); err != nil {
		t.Fatal(err)
	}
	rec, err := s.GetRecording(recID)
	if err != nil || rec.Summary != "先查订单，再查业务日志定位问题。" {
		t.Fatalf("summary = %+v, %v", rec, err)
	}
	if err := s.SetRecordingSummary(recID, ""); err != nil {
		t.Fatal(err)
	}
	if rec, err := s.GetRecording(recID); err != nil || rec.Summary != "" {
		t.Fatalf("summary not cleared: %+v, %v", rec, err)
	}
	if err := s.SetRecordingSummary(recID+100, "missing"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("missing recording summary: %v", err)
	}

	// Both direct request deletion and recording deletion remove annotations.
	n := recording.Note{RequestID: q.ID, RecordingID: recID, Purpose: "查询日志", Category: "query", Source: "agent"}
	if err := s.SetRequestNote(n); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`DELETE FROM requests WHERE id=?`, q.ID); err != nil {
		t.Fatal(err)
	}
	if notes, err := s.RequestNotes(recID); err != nil || len(notes) != 0 {
		t.Fatalf("request deletion left notes: %v, %v", notes, err)
	}
	q.ID = 0
	if err := s.InsertRequest(q); err != nil {
		t.Fatal(err)
	}
	n.RequestID = q.ID
	if err := s.SetRequestNote(n); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRecording(recID); err != nil {
		t.Fatal(err)
	}
	if notes, err := s.RequestNotes(recID); err != nil || len(notes) != 0 {
		t.Fatalf("recording deletion left notes: %v, %v", notes, err)
	}
}

func TestRequestNotesMigrateFromSchema4(t *testing.T) {
	path := filepath.Join(t.TempDir(), "v4.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`
CREATE TABLE recordings(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, start_url TEXT, status TEXT, created_at TEXT, ended_at TEXT DEFAULT '');
CREATE TABLE requests(id INTEGER PRIMARY KEY AUTOINCREMENT, recording_id INTEGER REFERENCES recordings(id) ON DELETE CASCADE, seq INTEGER, method TEXT, url TEXT, resource_type TEXT,
 req_headers TEXT, req_body TEXT, status INTEGER, resp_headers TEXT, resp_body TEXT, resp_mime TEXT, noise INTEGER, noise_reason TEXT, ts TEXT);
INSERT INTO recordings VALUES(7,'旧录制','https://example.com/issues','done','2026-01-01 12:00:00','2026-01-01 12:01:00');
INSERT INTO requests VALUES(11,7,1,'GET','https://example.com/api/logs','Fetch','{}','',200,'{}','old response','application/json',1,'埋点/日志','2026-01-01 12:00:01');
PRAGMA user_version=4;`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.db.Close() })
	var version int
	if err := s.db.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version != schemaUserVersion {
		t.Fatalf("schema version = %d, %v", version, err)
	}
	rec, err := s.GetRecording(7)
	if err != nil || rec.Name != "旧录制" || rec.Summary != "" || rec.RequestCount != 1 || rec.UsefulCount != 0 {
		t.Fatalf("migrated recording: %+v, %v", rec, err)
	}
	q, err := s.GetRequest(11)
	if err != nil || q.RespBody != "old response" || !q.Noise || q.NoiseReason != "埋点/日志" {
		t.Fatalf("migration changed request: %+v, %v", q, err)
	}
	if notes, err := s.RequestNotes(7); err != nil || len(notes) != 0 {
		t.Fatalf("migrated notes: %v, %v", notes, err)
	}
	n := recording.Note{RequestID: 11, RecordingID: 7, Purpose: "查询业务日志", Category: "query", Useful: new(true), NoiseOverride: new(false), Source: "agent"}
	if err := s.SetRequestNote(n); err != nil {
		t.Fatal(err)
	}
	if err := s.SetRecordingSummary(7, "排查线上问题"); err != nil {
		t.Fatal(err)
	}
	s.db.Close()
	reopened, err := OpenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	s = reopened
	if notes, err := s.RequestNotes(7); err != nil || len(notes) != 1 || notes[11].Purpose != n.Purpose || notes[11].NoiseOverride == nil || *notes[11].NoiseOverride {
		t.Fatalf("reopen lost note: %v, %v", notes, err)
	}
	rec, err = s.GetRecording(7)
	if err != nil || rec.Summary != "排查线上问题" || rec.UsefulCount != 1 {
		t.Fatalf("reopen lost summary or effective count: %+v, %v", rec, err)
	}
	list, err := s.ListRecordings()
	if err != nil || len(list) != 1 || !reflect.DeepEqual(list[0], *rec) {
		t.Fatalf("list/detail disagree: %+v, %v", list, err)
	}
	if err := s.DeleteRecording(7); err != nil {
		t.Fatal(err)
	}
	if notes, err := s.RequestNotes(7); err != nil || len(notes) != 0 {
		t.Fatalf("migrated cascade failed: %v, %v", notes, err)
	}
}

func TestRequestNoteAndSummaryLengthLimits(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "limits.db"))
	if err != nil {
		t.Fatal(err)
	}
	recID, err := s.CreateRecording("limits", "https://example.com/")
	if err != nil {
		t.Fatal(err)
	}
	q := &recording.Request{RecordingID: recID, Method: "GET", URL: "https://example.com/api/items"}
	if err := s.InsertRequest(q); err != nil {
		t.Fatal(err)
	}
	long := strings.Repeat("长", recording.MaxPurposeRunes+1)
	if err := s.SetRequestNote(recording.Note{RequestID: q.ID, RecordingID: recID, Purpose: long, Category: "query", Source: "agent"}); !errors.Is(err, recording.ErrInvalidNote) {
		t.Fatalf("oversized purpose: %v", err)
	}
	if err := s.SetRequestNote(recording.Note{RequestID: q.ID, RecordingID: recID, Purpose: strings.Repeat("长", recording.MaxPurposeRunes), Category: "query", Source: "agent"}); err != nil {
		t.Fatalf("max purpose: %v", err)
	}
	if err := s.SetRecordingSummary(recID, strings.Repeat("长", recording.MaxSummaryRunes+1)); !errors.Is(err, recording.ErrInvalidNote) {
		t.Fatalf("oversized summary: %v", err)
	}
}
