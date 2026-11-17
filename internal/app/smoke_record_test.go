package app

import (
	"strings"
	"testing"
)

// TestSmokeSeededRecordingAnalysis covers the recording-analysis tools with a
// store row the HTTP API cannot insert. The public console has no "create
// request" route; capture still comes from the browser.
func TestSmokeSeededRecordingAnalysis(t *testing.T) {
	app, err := NewApp(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	const secret = "smoke-cookie-secret"
	id, err := app.store.CreateRecording("smoke-flow", "https://example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	q := &ReqRecord{
		RecordingID:  id,
		Seq:          1,
		Method:       "GET",
		URL:          "https://example.com/api/items?q=demo",
		ResourceType: "XHR",
		Status:       200,
		RespMime:     "application/json",
		RespBody:     `{"items":["demo"]}`,
		ReqHeaders:   map[string]string{"Cookie": "sid=" + secret},
	}
	if err := app.store.InsertRequest(q); err != nil {
		t.Fatal(err)
	}
	list := smokeRecText(t, app.callRecTool(nil, "rec_list_recordings", nil))
	if !strings.Contains(list, "smoke-flow") || strings.Contains(list, secret) || strings.Contains(list, "sid=") {
		t.Fatalf("list leaked or missed the recording: %s", list)
	}
	view := smokeRecText(t, app.callRecTool(nil, "rec_get_recording", map[string]any{"recording_id": id}))
	if !strings.Contains(view, "/api/items") || strings.Contains(view, secret) || strings.Contains(view, "q=demo") {
		t.Fatalf("recording view: %s", view)
	}
	ann := smokeRecText(t, app.callRecTool(nil, "rec_annotate", map[string]any{
		"recording_id": id,
		"summary":      "查看示例条目",
		"notes": []any{
			map[string]any{"request_id": q.ID, "category": "query", "purpose": "列出示例条目", "useful": true},
		},
	}))
	if strings.Contains(ann, secret) {
		t.Fatalf("annotate leaked: %s", ann)
	}
	notes, err := app.store.RequestNotes(id)
	if err != nil {
		t.Fatal(err)
	}
	note := notes[q.ID]
	if note.Purpose != "列出示例条目" || note.Category != "query" {
		t.Fatalf("stored note: %+v", note)
	}
	detail := smokeRecText(t, app.callRecTool(nil, "rec_get_request", map[string]any{"request_id": q.ID, "max_body": 100000}))
	if !strings.Contains(detail, "列出示例条目") || strings.Contains(detail, secret) {
		t.Fatalf("request detail: %s", detail)
	}
}

func smokeRecText(t *testing.T, v any) string {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("result type %T", v)
	}
	if m["isError"] == true {
		t.Fatalf("tool error: %#v", m)
	}
	content, ok := m["content"].([]map[string]any)
	if !ok || len(content) == 0 {
		t.Fatalf("content: %#v", m["content"])
	}
	text, _ := content[0]["text"].(string)
	if text == "" {
		t.Fatalf("empty text: %#v", m)
	}
	return text
}
