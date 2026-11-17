package recording

import (
	"testing"
)

func TestNoiseClassification(t *testing.T) {
	cases := []struct {
		q     Request
		noise bool
	}{
		{Request{Method: "GET", URL: "https://x.com/static/app.js", ResourceType: "Script"}, true},
		{Request{Method: "OPTIONS", URL: "https://x.com/api/order"}, true},
		{Request{Method: "POST", URL: "https://x.com/api/order/create", ResourceType: "Fetch", Status: 200, RespMime: "application/json"}, false},
		{Request{Method: "WS", URL: "wss://x.com/ws/logs", ResourceType: "WebSocket", Status: 101}, false},
		{Request{Method: "WS", URL: "wss://x.com/ws", ResourceType: "WebSocket", Status: 0}, true},
		{Request{Method: "WS", URL: "wss://www.google-analytics.com/g/collect", ResourceType: "WebSocket", Status: 101}, true},
		{Request{Method: "WS", URL: "wss://logs.example.com/log", ResourceType: "WebSocket", Status: 101}, false},
	}
	for _, c := range cases {
		if n, why := ClassifyNoise(&c.q); n != c.noise {
			t.Errorf("%s %s: noise=%v (%s) want %v", c.q.Method, c.q.URL, n, why, c.noise)
		}
	}
}
