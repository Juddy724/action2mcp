package browser

import (
	"testing"
)

func TestMergeCapturedCredsSupportsTwoStepAndIgnoresEmptyOverwrite(t *testing.T) {
	var c CapturedCreds
	// Step 1: username-only submission
	c = mergeCapturedCreds(c, "alice@example.com", "", "https://login.example.com/step1")
	if c.Username != "alice@example.com" || c.Password != "" {
		t.Fatalf("after step1: %+v", c)
	}
	// Step 2: password-only page submission must keep step 1 username
	c = mergeCapturedCreds(c, "", "s3cr3t!", "https://login.example.com/step2")
	if c.Username != "alice@example.com" || c.Password != "s3cr3t!" || c.LoginURL != "https://login.example.com/step2" {
		t.Fatalf("after step2: %+v", c)
	}
	// User corrects password on retry
	c = mergeCapturedCreds(c, "alice_new", "correct_pass", "https://login.example.com/step2")
	if c.Username != "alice_new" || c.Password != "correct_pass" {
		t.Fatalf("after retry: %+v", c)
	}
}

func TestShouldDropOriginCookie(t *testing.T) {
	appCookie := Cookie{Name: "sid", Domain: "app.corp.example.com", Path: "/"}
	subCookie := Cookie{Name: "sub", Domain: ".sub.app.corp.example.com", Path: "/"}
	parentCookie := Cookie{Name: "corp_sso", Domain: ".corp.example.com", Path: "/"}
	wecomCookie := Cookie{Name: "wwrtx", Domain: ".work.weixin.qq.com", Path: "/"}

	origin := "https://app.corp.example.com"

	// includeParentCookies = false (used during cold SSO re-login check)
	if !shouldDropOriginCookie(appCookie, origin, false) {
		t.Fatal("expected exact host cookie to be dropped")
	}
	if !shouldDropOriginCookie(subCookie, origin, false) {
		t.Fatal("expected subdomain cookie to be dropped")
	}
	if shouldDropOriginCookie(parentCookie, origin, false) {
		t.Fatal("expected parent domain SSO cookie to be preserved when includeParentCookies=false")
	}
	if shouldDropOriginCookie(wecomCookie, origin, false) {
		t.Fatal("expected external WeCom cookie to be preserved")
	}

	// includeParentCookies = true (used when clearing site state for fresh manual login)
	if !shouldDropOriginCookie(parentCookie, origin, true) {
		t.Fatal("expected parent domain cookie to be dropped when includeParentCookies=true")
	}
	if shouldDropOriginCookie(wecomCookie, origin, true) {
		t.Fatal("expected external WeCom cookie to still be preserved when includeParentCookies=true")
	}
}
