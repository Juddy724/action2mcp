package app

import (
	"strings"
	"testing"
)

func TestScrubSecretTextSkipsShortPassedValues(t *testing.T) {
	const customer = "1190177654321"
	const limit = "SELECT id FROM t WHERE customer_id=1190177654321 LIMIT 10"
	const date = "2026-01-15 10:30:00"
	const reqID = "aabbccddeeff00112233445566778899"
	short := []string{"0", "1", "ok", "PROD", "901", "abcdefg"} // 7 chars: below threshold
	for _, v := range short {
		in := limit + "\n" + customer + "\n" + date + "\n" + reqID + "\nflag=" + v
		got := scrubSecretText(in, nil, []string{v})
		if got != in {
			t.Fatalf("short value %q was used for substring scrub: %q", v, got)
		}
	}

	long := "sess_abcd1234" // 13 chars
	got := scrubSecretText("before "+long+" LIMIT 10", nil, []string{long})
	if strings.Contains(got, long) || !strings.Contains(got, secretMask) || !strings.Contains(got, "LIMIT 10") {
		t.Fatalf("long secret not masked cleanly: %q", got)
	}
	if got != "before "+secretMask+" LIMIT 10" {
		t.Fatalf("unexpected scrub: %q", got)
	}

	// 8-char threshold is inclusive.
	eight := "abcdefgh"
	got = scrubSecretText("x "+eight+" y", nil, []string{eight})
	if got != "x "+secretMask+" y" {
		t.Fatalf("8-char value should be scrubbed, got %q", got)
	}
}

func TestScrubConfigTokensTokenBoundary(t *testing.T) {
	ids := []string{"901", "707", "PROD", "spc_alpha", "mysql"}
	errText := "remote rejected dsId=901 envType=PROD space=spc_alpha db=mysql env=707"
	got := scrubConfigTokens(errText, ids)
	for _, id := range ids {
		if strings.Contains(got, id) {
			t.Fatalf("error still contains %q: %q", id, got)
		}
	}
	if !strings.Contains(got, "dsId="+secretMask) || !strings.Contains(got, "envType="+secretMask) {
		t.Fatalf("expected token-boundary masks, got %q", got)
	}

	// Inside a longer digit / letter run, leave it alone.
	row := "customer_id=1190177654321 request=aabbcc PRODUCTION mysqladmin"
	got = scrubConfigTokens(row, ids)
	if got != row {
		t.Fatalf("token-boundary replaced inside a longer run: %q", got)
	}

	// 1–2 character config values are skipped even in errors.
	got = scrubConfigTokens("code=AB x=1", []string{"AB", "1", "x"})
	if got != "code=AB x=1" {
		t.Fatalf("short config tokens should be skipped: %q", got)
	}
}

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

func TestRememberCookieValueSkipsShortAndNames(t *testing.T) {
	var secrets []string
	rememberCookieValue(&secrets, "0")
	rememberCookieValue(&secrets, "ok")
	rememberCookieValue(&secrets, "abcdefg")
	rememberCookieValue(&secrets, "sess_abcd1234")
	rememberSecret(&secrets, "tips=0; sess_abcd1234=1") // whole header may be registered
	for _, v := range secrets {
		if v == "0" || v == "ok" || v == "abcdefg" || v == "tips" || v == "sess" {
			t.Fatalf("short cookie value or cookie name was registered: %q in %v", v, secrets)
		}
	}
	found := false
	for _, v := range secrets {
		if v == "sess_abcd1234" {
			found = true
		}
	}
	if !found {
		t.Fatalf("long cookie value missing: %v", secrets)
	}
}

func TestScrubExplicitSecretTextStillMasksShortParams(t *testing.T) {
	// Approval previews must still mask a classified short secret such as "token".
	const param = "token"
	in := `{"password":"token","token":"visible-key-collision"}`
	got := scrubExplicitSecretText(in, nil, []string{param})
	if strings.Contains(got, `"password":"token"`) || strings.Contains(got, `"token":"`) {
		t.Fatalf("explicit short secret was not masked: %s", got)
	}
	if !strings.Contains(got, secretMask) {
		t.Fatal("expected mask")
	}
	// The default result-row path must not substring-scrub this 5-char value.
	row := `{"note":"token-flag","limit":"LIMIT 10"}`
	got = scrubSecretText(row, nil, []string{param})
	if got != row {
		t.Fatalf("result path should skip 5-char incidental values: %q", got)
	}
}
