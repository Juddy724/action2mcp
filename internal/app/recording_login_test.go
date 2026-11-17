package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func wecomRecordingExample() (Recording, []ReqRecord) {
	rec := Recording{ID: 4, Name: "CRM 业务查询", StartURL: "https://crm.corp.example.com/v2/?ticket=example-secret#/customer?code=example-secret"}
	urls := []string{
		"https://crm.corp.example.com/v2/",
		"https://login.work.weixin.qq.com/wwlogin/sso/login?redirect_uri=example-secret",
		"https://bridge.example.net/api/weworkcore/connect/oauth2/loginAndAuthorize?code=example-secret",
		"https://auth.corp.example.com/oauth2/wecom?token=example-secret",
		"https://auth.corp.example.com/sso/oauth/callback?code=example-secret&state=example-secret",
		"https://crm.corp.example.com/v2/?code=example-secret",
	}
	requests := make([]ReqRecord, 0, len(urls))
	for i, raw := range urls {
		requests = append(requests, ReqRecord{Seq: i + 1, Method: "GET", URL: raw, ResourceType: "Document", Status: 302, Noise: true,
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
			got := detectWeComLogin(Recording{StartURL: "https://app.example.com/"}, []ReqRecord{{
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
			requests = append(requests, ReqRecord{Seq: 6, Method: "GET", URL: "https://crm.corp.example.com/oauth2/callback?code=example-secret", ResourceType: "Document"})
			// This document host has fewer requests; the SSO and CDN hosts have more.
			requests = append(requests, ReqRecord{Seq: 7, Method: "GET", URL: "https://other.example.com/home", ResourceType: "Document"})
			for i := 0; i < 10; i++ {
				requests = append(requests,
					ReqRecord{Seq: 8 + i, Method: "GET", URL: "https://crm.corp.example.com/api/customers", ResourceType: "Fetch"},
					ReqRecord{Seq: 8 + i, Method: "GET", URL: "https://auth.corp.example.com/oauth2/wecom", ResourceType: "Document"})
				for j := 0; j < 2; j++ {
					requests = append(requests, ReqRecord{Seq: 8 + i, Method: "GET", URL: "https://cdn.example.com/app.js", ResourceType: "Script"})
				}
			}
			got := detectWeComLogin(Recording{StartURL: start}, requests)
			if got == nil || got.Origin != "https://crm.corp.example.com" || got.Name != "crm.corp.example.com" {
				t.Fatalf("wrong business origin/name: %+v", got)
			}
		})
	}
	if got := detectWeComLogin(Recording{}, []ReqRecord{{URL: "https://login.work.weixin.qq.com/wwlogin/sso/login", ResourceType: "Document"}}); got != nil {
		t.Fatal("created a site without a business origin")
	}
}

func TestDetectWeComIntermediateHosts(t *testing.T) {
	rec, requests := wecomRecordingExample()
	requests = append(requests,
		ReqRecord{Seq: 1, URL: "https://unrelated.example.com/oauth2/callback", ResourceType: "Document"},
		ReqRecord{Seq: 2, URL: "https://gateway.example.com/redirect", ResourceType: "Document", Status: 302},
		ReqRecord{Seq: 3, URL: "https://metrics.example.com/collect", ResourceType: "Fetch"},
		ReqRecord{Seq: 3, URL: "https://unrelated-api.example.com/api/associations", ResourceType: "Fetch"},
		ReqRecord{Seq: 3, URL: "https://assets.example.com/oauth2/logo.png", ResourceType: "Image"},
		ReqRecord{Seq: 4, URL: "https://BRIDGE.EXAMPLE.NET/api/weworkcore/connect/oauth2/loginAndAuthorize?code=example-secret", ResourceType: "Document"},
		ReqRecord{Seq: 7, URL: "https://later.example.com/oauth2/callback", ResourceType: "Document"})
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
		got := detectWeComLogin(Recording{Name: start, StartURL: start}, []ReqRecord{{URL: "https://login.work.weixin.qq.com/wwlogin/sso/login"}})
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

func TestRecordingStopDetectsWeComLogin(t *testing.T) {
	for _, reason := range []string{"console", "overlay", "command", "browser-closed", "shutdown"} {
		t.Run(reason, func(t *testing.T) {
			st, vault, _ := testVault(t)
			defer st.db.Close()
			rec, requests := wecomRecordingExample()
			id, err := st.CreateRecording(rec.Name, rec.StartURL)
			if err != nil {
				t.Fatal(err)
			}
			for _, q := range requests {
				q.RecordingID = id
				if err := st.InsertRequest(&q); err != nil {
					t.Fatal(err)
				}
			}
			app := &App{store: st, vault: vault, recID: id, recName: rec.Name}
			var logs bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&logs)
			defer log.SetOutput(previous)
			info, err := app.StopRecording(reason)
			if err != nil || info.LoginDetection == nil || info.LoginDetection.Action != "created" {
				t.Fatalf("stop did not auto-detect: %v %+v", err, info)
			}
			site := st.SiteByOrigin("https://crm.corp.example.com")
			if site == nil || site.Method != MethodSSO || site.SSOHosts != "auth.corp.example.com,bridge.example.net" {
				t.Fatalf("site not persisted: %+v", site)
			}
			if app.lastStop != info || !strings.Contains(logs.String(), fmt.Sprintf("录制 #%d 检测到企业微信扫码登录，已在登录中心添加网站 crm.corp.example.com", id)) {
				t.Fatal("missing stop status or Chinese serve log")
			}
			if strings.Contains(js(info)+js(site)+logs.String(), "example-secret") {
				t.Fatal("OAuth secrets leaked into configuration, status or logs")
			}
		})
	}
}

func TestDetectRecordingLoginAPI(t *testing.T) {
	st, vault, _ := testVault(t)
	defer st.db.Close()
	app := &App{store: st, vault: vault}
	handler := app.Handler()
	rec, requests := wecomRecordingExample()
	id, err := st.CreateRecording(rec.Name, rec.StartURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range requests {
		q.RecordingID = id
		if err := st.InsertRequest(&q); err != nil {
			t.Fatal(err)
		}
	}
	call := func(id int64, wantStatus int) RecordingLoginResult {
		t.Helper()
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, fmt.Sprintf("http://localhost/api/recordings/%d/detect-login", id), nil))
		if w.Code != wantStatus {
			t.Fatalf("status=%d want=%d", w.Code, wantStatus)
		}
		if strings.Contains(w.Body.String(), "example-secret") || strings.Contains(w.Body.String(), "secret.site_password") {
			t.Fatal("detection endpoint leaked request or form data")
		}
		var result RecordingLoginResult
		if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	call(id, 409)
	call(id+100, 404)
	st.FinishRecording(id)
	if r := call(id, 200); !r.Detected || r.Action != "created" || r.SiteID == 0 {
		t.Fatalf("old recording not detected: %+v", r)
	}
	if r := call(id, 200); r.Action != "unchanged" || len(st.ListSites()) != 1 {
		t.Fatal("repeated detection created a duplicate site")
	}
	site := st.ListSites()[0]
	site.SSOHosts = "custom.example.com"
	if err := st.SaveSite(site); err != nil {
		t.Fatal(err)
	}
	if r := call(id, 200); r.Action != "updated" {
		t.Fatal("existing SSO site not updated")
	}
	for _, method := range []string{MethodForm, MethodManual} {
		site, _ = st.GetSite(site.ID)
		site.Method = method
		site.Form.PasswordRef = "secret.site_password"
		if err := st.SaveSite(site); err != nil {
			t.Fatal(err)
		}
		before := js(site)
		if r := call(id, 200); r.Action != "suggestion" || !r.Detected {
			t.Fatal("expected a suggestion for an existing explicit login method")
		}
		after, _ := st.GetSite(site.ID)
		if js(after) != before {
			t.Fatal("existing explicit login configuration was modified")
		}
	}
	emptyID, err := st.CreateRecording("普通录制", "https://other.example.com/")
	if err != nil {
		t.Fatal(err)
	}
	st.FinishRecording(emptyID)
	if r := call(emptyID, 200); r.Detected || r.Action != "none" || len(st.ListSites()) != 1 {
		t.Fatal("negative detection changed the login center")
	}
}
