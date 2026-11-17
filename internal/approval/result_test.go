package approval

import (
	"strings"
	"testing"
)

func TestPreviewApprovalResultAndCap(t *testing.T) {
	short := "HTTP 200\nok"
	if previewApprovalResult(short) != short {
		t.Fatal("short result should be unchanged")
	}
	full, trunc := capApprovalResultFull(short)
	if trunc || full != short {
		t.Fatal("short result should not be capped")
	}

	var lines []string
	for i := 0; i < 30; i++ {
		lines = append(lines, "line")
	}
	longLines := strings.Join(lines, "\n")
	prev := previewApprovalResult(longLines)
	if strings.Count(prev, "\n") > approvalResultPreviewLines {
		t.Fatalf("preview has too many lines: %q", prev)
	}
	if !strings.HasSuffix(prev, approvalResultTruncMark) {
		t.Fatalf("preview missing marker: %q", prev)
	}

	big := strings.Repeat("a", approvalResultPreviewBytes+50)
	prev = previewApprovalResult(big)
	if len(prev) > approvalResultPreviewBytes+len(approvalResultTruncMark)+5 {
		t.Fatalf("preview too large: %d", len(prev))
	}
	if !strings.Contains(prev, approvalResultTruncMark) {
		t.Fatal("byte-capped preview missing marker")
	}

	huge := strings.Repeat("b", approvalResultFullMax+100)
	capped, trunc := capApprovalResultFull(huge)
	if !trunc || !strings.Contains(capped, approvalResultFullCapNote) {
		t.Fatal("1MB cap did not apply")
	}
	if len(capped) > approvalResultFullMax+len(approvalResultFullCapNote)+5 {
		t.Fatalf("capped length %d", len(capped))
	}
}
