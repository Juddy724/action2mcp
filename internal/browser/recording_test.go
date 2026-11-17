package browser

import (
	"action2mcp/internal/recording"
	sitecfg "action2mcp/internal/site"
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	_ "modernc.org/sqlite"
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
func TestRecordingStopDetectsWeComLogin(t *testing.T) {
	for _, reason := range []string{"console", "overlay", "command", "browser-closed", "shutdown"} {
		t.Run(reason, func(t *testing.T) {
			st := testRecordingStore(t)
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
			app := New(Options{Repository: st, DetectRecordingLogin: sitecfg.NewRecordingDetector(st).Detect})
			app.recID, app.recName = id, rec.Name
			var logs bytes.Buffer
			previous := log.Writer()
			log.SetOutput(&logs)
			defer log.SetOutput(previous)
			info, err := app.StopRecording(reason)
			if err != nil || info.LoginDetection == nil || info.LoginDetection.Action != "created" {
				t.Fatalf("stop did not auto-detect: %v %+v", err, info)
			}
			site := st.SiteByOrigin("https://crm.corp.example.com")
			if site == nil || site.Method != sitecfg.MethodSSO || site.SSOHosts != "auth.corp.example.com,bridge.example.net" {
				t.Fatalf("site not persisted: %+v", site)
			}
			if !reflect.DeepEqual(app.lastStop, info) || !strings.Contains(logs.String(), fmt.Sprintf("录制 #%d 检测到企业微信扫码登录，已在登录中心添加网站 crm.corp.example.com", id)) {
				t.Fatal("missing stop status or Chinese serve log")
			}
			if strings.Contains(js(info)+js(site)+logs.String(), "example-secret") {
				t.Fatal("OAuth secrets leaked into configuration, status or logs")
			}
		})
	}
}

type recordingTestStore struct {
	*recording.Store
	*sitecfg.Repository
	db *sql.DB
}

func (s recordingTestStore) AllCookies() []Cookie    { return nil }
func (s recordingTestStore) SaveCookies([]Cookie)    {}
func (s recordingTestStore) ReplaceCookies([]Cookie) {}
func testRecordingStore(t *testing.T) *recordingTestStore {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(`CREATE TABLE IF NOT EXISTS recordings(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, start_url TEXT, status TEXT, created_at TEXT, ended_at TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS requests(id INTEGER PRIMARY KEY AUTOINCREMENT, recording_id INTEGER REFERENCES recordings(id) ON DELETE CASCADE, seq INTEGER, method TEXT, url TEXT, resource_type TEXT,
  req_headers TEXT, req_body TEXT, status INTEGER, resp_headers TEXT, resp_body TEXT, resp_mime TEXT, noise INTEGER, noise_reason TEXT, ts TEXT);
CREATE TABLE IF NOT EXISTS request_notes(
  request_id INTEGER PRIMARY KEY REFERENCES requests(id) ON DELETE CASCADE,
  recording_id INTEGER NOT NULL REFERENCES recordings(id) ON DELETE CASCADE,
  purpose TEXT NOT NULL,
  category TEXT NOT NULL CHECK(category IN ('query','write','auth','config','page','noise')),
  useful INTEGER CHECK(useful IN (0,1)),
  noise_override INTEGER CHECK(noise_override IN (0,1)),
  source TEXT NOT NULL CHECK(source IN ('agent','user')),
  updated_at TEXT NOT NULL,
  group_key TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS sites(id INTEGER PRIMARY KEY AUTOINCREMENT, origin TEXT UNIQUE, config TEXT, status TEXT DEFAULT 'unknown', last_login_at TEXT DEFAULT '', last_check_at TEXT DEFAULT '', last_error TEXT DEFAULT '', login_count INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT);
ALTER TABLE recordings ADD COLUMN summary TEXT DEFAULT '';`); err != nil {
		t.Fatal(err)
	}
	return &recordingTestStore{recording.NewStore(db), sitecfg.NewRepository(db), db}
}
func js(v any) string { b, _ := json.Marshal(v); return string(b) }
