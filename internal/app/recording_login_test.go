package app

import (
	"action2mcp/internal/recording"
	sitecfg "action2mcp/internal/site"

	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestDetectRecordingLoginAPI(t *testing.T) {
	st, vault, _ := testVault(t)
	defer st.DB().Close()
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
	for _, method := range []string{sitecfg.MethodForm, sitecfg.MethodManual} {
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
