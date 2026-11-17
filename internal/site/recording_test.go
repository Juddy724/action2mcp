package site

import (
	"action2mcp/internal/recording"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func wecomRecordingExample() (recording.Recording, []recording.Request) {
	rec := recording.Recording{ID: 4, Name: "CRM 业务查询", StartURL: "https://crm.corp.example.com/v2/?ticket=example-secret#/customer?code=example-secret"}
	urls := []string{
		"https://crm.corp.example.com/v2/",
		"https://login.work.weixin.qq.com/wwlogin/sso/login?redirect_uri=example-secret",
		"https://bridge.example.net/api/weworkcore/connect/oauth2/loginAndAuthorize?code=example-secret",
		"https://auth.corp.example.com/oauth2/wecom?token=example-secret",
		"https://auth.corp.example.com/sso/oauth/callback?code=example-secret&state=example-secret",
		"https://crm.corp.example.com/v2/?code=example-secret",
	}
	requests := make([]recording.Request, 0, len(urls))
	for i, raw := range urls {
		requests = append(requests, recording.Request{Seq: i + 1, Method: "GET", URL: raw, ResourceType: "Document", Status: 302, Noise: true,
			ReqHeaders: map[string]string{"Cookie": "example-secret"}, RespHeaders: map[string]string{"Set-Cookie": "example-secret"},
			ReqBody: "example-secret", RespBody: "example-secret"})
	}
	requests[len(requests)-1].Status = 200
	return rec, requests
}
func TestDetectWeComLoginExample(t *testing.T) {
	rec, requests := wecomRecordingExample()
	// The detector orders a copy, since body fetches may finish out of sequence.
	requests[1], requests[3] = requests[3], requests[1]
	before := js(requests)
	got := detectWeComLogin(rec, requests)
	want := &Site{Origin: "https://crm.corp.example.com", Name: rec.Name, Method: MethodSSO,
		EntryURL: "https://crm.corp.example.com/v2/", SSOHosts: "auth.corp.example.com,bridge.example.net", Status: "unknown"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	if js(requests) != before {
		t.Fatal("detection changed its input requests")
	}
	if strings.Contains(js(got), "example-secret") || strings.Contains(js(got), "?") || strings.Contains(js(got), "#") {
		t.Fatal("detection retained OAuth parameters or request secrets")
	}
}

func TestDetectWeComLoginEvidence(t *testing.T) {
	cases := []struct {
		name, raw, kind, mime, method string
		want                          bool
	}{
		{name: "login host", raw: "https://login.work.weixin.qq.com/wwlogin/sso/login", kind: "Document", want: true},
		{name: "open wwlogin", raw: "https://open.work.weixin.qq.com/wwlogin/sso/login", kind: "Document", want: true},
		{name: "open QR iframe", raw: "https://open.work.weixin.qq.com/wwopen/sso/qrConnect?code=example-secret", kind: "Document", want: true},
		{name: "open OAuth", raw: "https://open.work.weixin.qq.com/connect/oauth2/authorize", kind: "Fetch", want: true},
		{name: "admin login", raw: "https://work.weixin.qq.com/wework_admin/wwlogin/sso/login", kind: "Document", want: true},
		{name: "missing resource metadata", raw: "https://login.work.weixin.qq.com/wwlogin/sso/login", want: true},
		{name: "OAuth without WeCom", raw: "https://sso.example.com/oauth2/callback", kind: "Document"},
		{name: "ordinary business request", raw: "https://app.example.com/api/customers", kind: "Fetch"},
		{name: "WeCom static image", raw: "https://login.work.weixin.qq.com/wwlogin/logo.png", kind: "Image"},
		{name: "WeCom static script", raw: "https://open.work.weixin.qq.com/wwlogin/sdk.js", kind: "Script"},
		{name: "static extension without metadata", raw: "https://login.work.weixin.qq.com/wwlogin/sdk.js"},
		{name: "login URL loaded as image", raw: "https://login.work.weixin.qq.com/wwlogin/sso/login", kind: "Image"},
		{name: "image MIME without extension", raw: "https://login.work.weixin.qq.com/wwlogin/logo", kind: "Other", mime: "image/png"},
		{name: "script MIME without metadata", raw: "https://login.work.weixin.qq.com/wwlogin/sdk", mime: "application/javascript"},
		{name: "WeCom analytics ping", raw: "https://login.work.weixin.qq.com/wwlogin/sso/login", kind: "Ping"},
		{name: "preflight", raw: "https://login.work.weixin.qq.com/wwlogin/sso/login", kind: "Fetch", method: "OPTIONS"},
		{name: "WeCom mentioned in query", raw: "https://app.example.com/help?url=https://login.work.weixin.qq.com/wwlogin/sso/login", kind: "Document"},
		{name: "spoofed host suffix", raw: "https://login.work.weixin.qq.com.example.com/wwlogin/sso/login", kind: "Document"},
		{name: "open host unrelated path", raw: "https://open.work.weixin.qq.com/help", kind: "Document"},
		{name: "work host unrelated path", raw: "https://work.weixin.qq.com/help", kind: "Document"},
		{name: "non HTTP scheme", raw: "ftp://login.work.weixin.qq.com/wwlogin/sso/login", kind: "Document"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			method := tc.method
			if method == "" {
				method = "GET"
			}
			got := detectWeComLogin(recording.Recording{StartURL: "https://app.example.com/"}, []recording.Request{{
				URL: tc.raw, ResourceType: tc.kind, RespMime: tc.mime, Method: method}})
			if (got != nil) != tc.want {
				t.Fatalf("detected=%v, want %v", got != nil, tc.want)
			}
		})
	}
}

func TestDetectWeComBusinessFallback(t *testing.T) {
	for _, start := range []string{"", "about:blank", "https://login.work.weixin.qq.com/wwlogin/sso/login", "https://auth.corp.example.com/oauth2/wecom"} {
		t.Run(start, func(t *testing.T) {
			_, requests := wecomRecordingExample()
			requests = append(requests, recording.Request{Seq: 6, Method: "GET", URL: "https://crm.corp.example.com/oauth2/callback?code=example-secret", ResourceType: "Document"})
			// This document host has fewer requests; the SSO and CDN hosts have more.
			requests = append(requests, recording.Request{Seq: 7, Method: "GET", URL: "https://other.example.com/home", ResourceType: "Document"})
			for i := 0; i < 10; i++ {
				requests = append(requests,
					recording.Request{Seq: 8 + i, Method: "GET", URL: "https://crm.corp.example.com/api/customers", ResourceType: "Fetch"},
					recording.Request{Seq: 8 + i, Method: "GET", URL: "https://auth.corp.example.com/oauth2/wecom", ResourceType: "Document"})
				for j := 0; j < 2; j++ {
					requests = append(requests, recording.Request{Seq: 8 + i, Method: "GET", URL: "https://cdn.example.com/app.js", ResourceType: "Script"})
				}
			}
			got := detectWeComLogin(recording.Recording{StartURL: start}, requests)
			if got == nil || got.Origin != "https://crm.corp.example.com" || got.Name != "crm.corp.example.com" {
				t.Fatalf("wrong business origin/name: %+v", got)
			}
		})
	}
	if got := detectWeComLogin(recording.Recording{}, []recording.Request{{URL: "https://login.work.weixin.qq.com/wwlogin/sso/login", ResourceType: "Document"}}); got != nil {
		t.Fatal("created a site without a business origin")
	}
}

func TestDetectWeComIntermediateHosts(t *testing.T) {
	rec, requests := wecomRecordingExample()
	requests = append(requests,
		recording.Request{Seq: 1, URL: "https://unrelated.example.com/oauth2/callback", ResourceType: "Document"},
		recording.Request{Seq: 2, URL: "https://gateway.example.com/redirect", ResourceType: "Document", Status: 302},
		recording.Request{Seq: 3, URL: "https://metrics.example.com/collect", ResourceType: "Fetch"},
		recording.Request{Seq: 3, URL: "https://unrelated-api.example.com/api/associations", ResourceType: "Fetch"},
		recording.Request{Seq: 3, URL: "https://assets.example.com/oauth2/logo.png", ResourceType: "Image"},
		recording.Request{Seq: 4, URL: "https://BRIDGE.EXAMPLE.NET/api/weworkcore/connect/oauth2/loginAndAuthorize?code=example-secret", ResourceType: "Document"},
		recording.Request{Seq: 7, URL: "https://later.example.com/oauth2/callback", ResourceType: "Document"})
	// The unrelated request occurs before the business document opening this login episode.
	requests[0].Seq = 2
	requests[len(requests)-7].Seq = 1
	got := detectWeComLogin(rec, requests)
	if got == nil || got.SSOHosts != "auth.corp.example.com,bridge.example.net,gateway.example.com" {
		t.Fatalf("wrong intermediate hosts: %+v", got)
	}
}

func TestWeComLoginSanitizedEntry(t *testing.T) {
	for _, start := range []string{
		"https://user:example-secret@APP.example.com/v2/?code=example-secret#/?access_token=example-secret",
		"https://APP.example.com/v2/?#fragment",
	} {
		got := detectWeComLogin(recording.Recording{Name: start, StartURL: start}, []recording.Request{{URL: "https://login.work.weixin.qq.com/wwlogin/sso/login"}})
		if got == nil || got.EntryURL != "https://app.example.com/v2/" || got.Name != got.EntryURL || got.Origin != "https://app.example.com" {
			t.Fatalf("unsafe entry/name/origin: %+v", got)
		}
	}
}

func TestMergeDetectedWeComSite(t *testing.T) {
	rec, requests := wecomRecordingExample()
	detected := detectWeComLogin(rec, requests)
	t.Run("create", func(t *testing.T) {
		got, action := mergeWeComSite(detected, nil)
		if action != "created" || !reflect.DeepEqual(got, detected) || got == detected {
			t.Fatal("did not create an independent site candidate")
		}
	})
	t.Run("merge and preserve customization", func(t *testing.T) {
		existing := &Site{ID: 12, Origin: detected.Origin, Name: "自定义名称", Method: MethodSSO,
			EntryURL: detected.Origin + "/custom-login", CheckURL: detected.Origin + "/api/me", SuccessURL: "/dashboard$",
			SSOHosts: "SSO.example.com,https://BRIDGE.EXAMPLE.NET/oauth2?code=example-secret," + detected.Host(), KeepaliveMin: 5, Status: "valid"}
		before := *existing
		got, action := mergeWeComSite(detected, existing)
		want := before
		want.SSOHosts = "auth.corp.example.com,bridge.example.net,sso.example.com"
		if action != "updated" || !reflect.DeepEqual(got, &want) || !reflect.DeepEqual(existing, &before) {
			t.Fatalf("merge overwrote configuration or input: action=%s got=%+v", action, got)
		}
		if strings.Contains(js(got), "example-secret") {
			t.Fatal("merged hosts retained OAuth parameters")
		}
		again, action := mergeWeComSite(detected, got)
		if action != "unchanged" || !reflect.DeepEqual(again, got) {
			t.Fatal("merge is not idempotent")
		}
	})
	for _, method := range []string{MethodForm, MethodManual} {
		t.Run("preserve "+method, func(t *testing.T) {
			existing := &Site{ID: 12, Origin: detected.Origin, Method: method, SSOHosts: "custom.example.com",
				Form: FormLogin{Mode: "replay", PasswordRef: "secret.site_password", Request: &LoginRequest{Body: "{{secret.site_password}}"}}}
			before := js(existing)
			got, action := mergeWeComSite(detected, existing)
			if action != "suggestion" || got != nil || js(existing) != before {
				t.Fatal("detection replaced an explicit login method")
			}
		})
	}
}
func js(v any) string { b, _ := json.Marshal(v); return string(b) }
