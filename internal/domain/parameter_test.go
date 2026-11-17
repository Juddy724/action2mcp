package domain

import (
	"encoding/json"
	"testing"
)

func TestArgumentTextPreservesTemplateCoercion(t *testing.T) {
	for _, tc := range []struct {
		input any
		want  string
	}{{nil, ""}, {" value ", " value "}, {float64(12.5), "12.5"}, {true, "true"}, {map[string]any{"n": 1}, `{"n":1}`}, {[]any{1, "x"}, `[1,"x"]`}} {
		if got := ArgumentText(tc.input); got != tc.want {
			t.Fatalf("ArgumentText(%v)=%q want %q", tc.input, got, tc.want)
		}
	}
	value := Param{Name: "s", Type: "string", Secret: true, Required: true}
	b, err := json.Marshal(value)
	if err != nil || string(b) != `{"name":"s","type":"string","description":"","required":true,"secret":true}` {
		t.Fatalf("parameter wire schema changed: %s %v", b, err)
	}
}
