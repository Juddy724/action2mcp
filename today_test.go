package main

import (
	"strings"
	"testing"
	"time"
)

func TestTodayDefault(t *testing.T) {
	tl := &Tool{Method: "POST", URL: "https://x/t-{{objectID}}.html", Headers: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, Body: "dates%5B1%5D={{date}}&objectID%5B1%5D={{objectID}}", Params: []Param{{Name: "objectID", Type: "string", Required: true}, {Name: "date", Type: "string", Default: "@today"}}}
	_, u, _, b, err := tl.Render(map[string]any{"objectID": "123"})
	if err != nil || u != "https://x/t-123.html" || !strings.Contains(b, time.Now().Format("2006-01-02")) || !strings.Contains(b, "objectID%5B1%5D=123") {
		t.Fatal(u, b, err)
	}
	_, _, _, b, _ = tl.Render(map[string]any{"objectID": "1", "date": "2026-10-01"})
	if !strings.Contains(b, "2026-10-01") {
		t.Fatal(b)
	}
}
