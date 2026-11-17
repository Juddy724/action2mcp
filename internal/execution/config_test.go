package execution

import (
	"action2mcp/internal/domain"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestBindValuesReportsAllMissingParams(t *testing.T) {
	tool := &Tool{Params: []domain.Param{
		{Name: "a", Type: "string", Required: true},
		{Name: "b", Type: "string", Required: true},
		{Name: "c", Type: "string", Required: false},
	}}
	_, err := tool.bindValues(map[string]any{}, nil, nil, false, time.Now())
	if err == nil || err.Error() != "缺少参数: a、b" {
		t.Fatalf("got %v", err)
	}
}

func TestDetectFailureFalseRoundTrip(t *testing.T) {
	off := BoolPtr(false)
	raw := ToolConfig{DetectFailure: off}.Marshal()
	if !strings.Contains(raw, `"detect_failure":false`) {
		t.Fatalf("unchecked detection must be stored as false: %s", raw)
	}
	back, err := ParseToolConfigJSON(raw)
	if err != nil || back.DetectFailureEnabled() {
		t.Fatalf("round trip: %+v %v", back, err)
	}
}
