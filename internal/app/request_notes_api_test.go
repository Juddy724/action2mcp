package app

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func TestRequestNotesAPI(t *testing.T) {
	a, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Shutdown)
	recID, err := a.store.CreateRecording("线上问题排查", "https://example.com/issues")
	if err != nil {
		t.Fatal(err)
	}
	if err := a.store.SetRecordingSummary(recID, "查询订单和业务日志以定位线上问题。"); err != nil {
		t.Fatal(err)
	}
	reqs := []*ReqRecord{
		{RecordingID: recID, Seq: 1, Method: "GET", URL: "https://example.com/api/orders", ResourceType: "Fetch", Status: 200},
		{RecordingID: recID, Seq: 2, Method: "GET", URL: "https://example.com/api/logs", ResourceType: "Fetch", Status: 200, Noise: true, NoiseReason: "埋点/日志"},
	}
	for _, q := range reqs {
		if err := a.store.InsertRequest(q); err != nil {
			t.Fatal(err)
		}
	}
	h := a.Handler()
	call := func(method, path, body string, wantStatus int) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(method, "http://localhost"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		h.ServeHTTP(w, r)
		if w.Code != wantStatus {
			t.Fatalf("%s %s: status %d, want %d: %s", method, path, w.Code, wantStatus, w.Body.String())
		}
		return w
	}
	getRecording := func() (Recording, []ReqRecord) {
		t.Helper()
		w := call("GET", fmt.Sprintf("/api/recordings/%d", recID), "", http.StatusOK)
		var d struct {
			Recording Recording   `json:"recording"`
			Requests  []ReqRecord `json:"requests"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
			t.Fatal(err)
		}
		if d.Recording.Summary != "查询订单和业务日志以定位线上问题。" || len(d.Requests) != 2 {
			t.Fatalf("recording response: %s", w.Body.String())
		}
		return d.Recording, d.Requests
	}
	checkRequest := func(index int, noise bool, note *RequestNote) {
		t.Helper()
		_, rows := getRecording()
		q := rows[index]
		if q.Noise != noise || q.NoiseHeuristic != reqs[index].Noise || !reflect.DeepEqual(q.Note, note) {
			t.Fatalf("compact noise/note: %+v, want noise=%v heuristic=%v note=%+v", q, noise, reqs[index].Noise, note)
		}
		w := call("GET", fmt.Sprintf("/api/requests/%d", q.ID), "", 200)
		var detail struct {
			Request ReqRecord `json:"request"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &detail); err != nil {
			t.Fatal(err)
		}
		if detail.Request.Noise != noise || detail.Request.NoiseHeuristic != q.NoiseHeuristic || !reflect.DeepEqual(detail.Request.Note, note) {
			t.Fatalf("detail/compact disagree: %s", w.Body.String())
		}
		raw, err := a.store.GetRequest(q.ID)
		if err != nil || raw.Noise != reqs[index].Noise || raw.NoiseReason != reqs[index].NoiseReason {
			t.Fatalf("API changed heuristic: %+v, %v", raw, err)
		}
	}

	// Absent annotations are explicit JSON null, including on older recordings.
	w := call("GET", fmt.Sprintf("/api/recordings/%d", recID), "", 200)
	var raw struct {
		Requests []map[string]json.RawMessage `json:"requests"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	for _, q := range raw.Requests {
		if string(q["note"]) != "null" || q["noise_heuristic"] == nil {
			t.Fatalf("missing note or heuristic: %v", q)
		}
	}
	checkRequest(0, false, nil)
	checkRequest(1, true, nil)
	agent := RequestNote{RequestID: reqs[1].ID, RecordingID: recID, Purpose: "查询业务日志", Category: "query", Useful: new(true), NoiseOverride: new(false), Source: "agent"}
	if err := a.store.SetRequestNote(agent); err != nil {
		t.Fatal(err)
	}
	notes, err := a.store.RequestNotes(recID)
	if err != nil {
		t.Fatal(err)
	}
	agent = notes[agent.RequestID]
	checkRequest(1, false, &agent)
	if rec, _ := getRecording(); rec.UsefulCount != 2 {
		t.Fatalf("business count ignored override: %+v", rec)
	}

	for index, original := range reqs {
		for _, override := range []*bool{new(true), new(false), nil} {
			// Spoofed ids/source/timestamp cannot change console authorship.
			n := RequestNote{RequestID: 99999, RecordingID: 99999, Purpose: "按订单号查询处理进度", Category: "query", Useful: new(false), NoiseOverride: override, Source: "agent", UpdatedAt: "2000-01-01 00:00:00"}
			path := fmt.Sprintf("/api/requests/%d/note", original.ID)
			w := call("PUT", path, js(n), 200)
			var saved RequestNote
			if err := json.Unmarshal(w.Body.Bytes(), &saved); err != nil {
				t.Fatal(err)
			}
			if saved.RequestID != original.ID || saved.RecordingID != recID || saved.Source != "user" || saved.UpdatedAt == n.UpdatedAt || saved.UpdatedAt == "" {
				t.Fatalf("server identity/authorship: %s", w.Body.String())
			}
			noise := original.Noise
			if override != nil {
				noise = *override
			}
			checkRequest(index, noise, &saved)
			// Useful=false describes workflow membership; it does not classify noise.
			rec, rows := getRecording()
			count := 0
			for _, q := range rows {
				if !q.Noise {
					count++
				}
			}
			if rec.UsefulCount != count {
				t.Fatalf("effective count = %d, want %d", rec.UsefulCount, count)
			}
			var listed []Recording
			if err := json.Unmarshal(call("GET", "/api/recordings", "", 200).Body.Bytes(), &listed); err != nil || len(listed) != 1 || listed[0].UsefulCount != count {
				t.Fatalf("recording list count: %+v, %v", listed, err)
			}
		}
		path := fmt.Sprintf("/api/requests/%d/note", original.ID)
		for i := 0; i < 2; i++ {
			call("DELETE", path, "", 200)
		}
		checkRequest(index, original.Noise, nil)
	}

	path := fmt.Sprintf("/api/requests/%d/note", reqs[0].ID)
	for _, body := range []string{`{`, `null`, `{}`, `{"category":"invalid"}`, `{"category":"query","useful":"yes"}`, `{"category":"query","noise_override":0}`} {
		call("PUT", path, body, 400)
	}
	checkRequest(0, false, nil)
	for _, method := range []string{"PUT", "DELETE"} {
		call(method, "/api/requests/99999/note", `{"category":"query"}`, 404)
		call(method, "/api/requests/invalid/note", `{"category":"query"}`, 404)
	}
}

func TestRequestNoteOverrideTakesPrecedenceForLogin(t *testing.T) {
	a, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Shutdown)
	recID, err := a.store.CreateRecording("登录", "https://example.com/login")
	if err != nil {
		t.Fatal(err)
	}
	q := &ReqRecord{RecordingID: recID, Method: "POST", URL: "https://example.com/login", ReqBody: "username=alice&password=example-password", Noise: true, NoiseReason: "埋点/日志"}
	if err := a.store.InsertRequest(q); err != nil {
		t.Fatal(err)
	}
	h := a.Handler()
	for _, override := range []*bool{nil, new(true), new(false)} {
		if err := a.store.SetRequestNote(RequestNote{RequestID: q.ID, RecordingID: recID, Category: "auth", NoiseOverride: override, Source: "agent"}); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{fmt.Sprintf("/api/recordings/%d", recID), fmt.Sprintf("/api/requests/%d", q.ID)} {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("GET", "http://localhost"+path, nil))
			var d struct {
				Requests []ReqRecord `json:"requests"`
				Request  ReqRecord   `json:"request"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil || w.Code != 200 {
				t.Fatalf("login response: %s, %v", w.Body.String(), err)
			}
			got := d.Request
			if len(d.Requests) != 0 {
				got = d.Requests[0]
			}
			wantNoise := override != nil && *override // login rows stay in the business list unless a note overrides
			if !got.IsLogin || !got.NoiseHeuristic || got.Noise != wantNoise || strings.Contains(w.Body.String(), "example-password") {
				t.Fatalf("login override=%v: %s", override, w.Body.String())
			}
		}
	}
}
