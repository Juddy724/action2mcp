package execution

import (
	"action2mcp/internal/domain"
	"action2mcp/internal/vault"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type executionTransport func(*http.Request) (*http.Response, error)

func (f executionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type sessionPort struct {
	events  *[]string
	session Session
	wait    bool
	err     error
}

func (s sessionPort) Begin(string) (Session, error) {
	*s.events = append(*s.events, "begin")
	return s.session, s.err
}
func (s sessionPort) ReloginWS(string) (bool, error) {
	*s.events = append(*s.events, "ws-login")
	return s.wait, s.err
}

type loginSession struct {
	events    *[]string
	bad       bool
	secondWhy string
	checks    int
}

func (s *loginSession) Origin() string      { return "http://example.com" }
func (s *loginSession) DisplayName() string { return "test site" }
func (s *loginSession) NotLoggedIn(status int, body, contentType string, hops []string, raw string) (bool, string) {
	*s.events = append(*s.events, "classify")
	s.checks++
	if s.checks > 1 {
		return s.bad, s.secondWhy
	}
	return s.bad, "expired"
}
func (s *loginSession) MarkValid()     { *s.events = append(*s.events, "valid") }
func (s *loginSession) Relogin() error { *s.events = append(*s.events, "login"); return nil }
func (s *loginSession) Invalid(msg string) error {
	*s.events = append(*s.events, "invalid")
	return &LoginErr{msg}
}
func response(status int) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": []string{"text/plain"}}, Body: io.NopCloser(strings.NewReader("ok"))}
}

func TestHTTPSessionPortOrderAndProfileRefresh(t *testing.T) {
	events := []string{}
	session := &loginSession{events: &events}
	calls := 0
	engine := New(Options{Vault: &vault.Vault{}, ConsolePort: 19000, Sessions: sessionPort{events: &events, session: session},
		Cookies: func(string) ([]Cookie, string) {
			events = append(events, "cookies")
			return []Cookie{{Name: "sid", Value: "old", Domain: "example.com", Session: true}}, "本地登录态快照"
		},
		ProfileCookies: func() ([]Cookie, error) {
			events = append(events, "profile")
			return []Cookie{{Name: "sid", Value: "fresh", Domain: "example.com", Session: true}}, nil
		},
		ReplaceCookies: func(c []Cookie) {
			events = append(events, "replace")
			if len(c) != 1 || c[0].Value != "fresh" {
				t.Fatal("wrong cookie snapshot")
			}
		},
		HTTPClient: &http.Client{Transport: executionTransport(func(r *http.Request) (*http.Response, error) {
			calls++
			events = append(events, "wire")
			want := "sid=old"
			status := 401
			if calls == 2 {
				want = "sid=fresh"
				status = 200
			}
			if r.Header.Get("Cookie") != want {
				t.Fatal("wrong retry cookie")
			}
			return response(status), nil
		})}})
	p, err := engine.Prepare(&Tool{Method: "GET", URL: "http://example.com/data"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	res, err := engine.Send(p)
	if err != nil || res.Status != 200 || res.Relogged {
		t.Fatalf("result=%+v err=%v", res, err)
	}
	want := []string{"begin", "cookies", "wire", "profile", "replace", "wire", "classify", "valid"}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("order=%v want=%v", events, want)
	}
}

func TestHTTPReloginPortAndSecondForbiddenException(t *testing.T) {
	for _, allowed := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid", true: "403-exception"}[allowed], func(t *testing.T) {
			events := []string{}
			why := "still expired"
			if allowed {
				why = "接口返回 HTTP 403"
			}
			session := &loginSession{events: &events, bad: true, secondWhy: why}
			calls := 0
			e := New(Options{Vault: &vault.Vault{}, Sessions: sessionPort{events: &events, session: session}, Cookies: func(string) ([]Cookie, string) { events = append(events, "cookies"); return nil, "browser" }, HTTPClient: &http.Client{Transport: executionTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				events = append(events, "wire")
				data, _ := io.ReadAll(r.Body)
				if string(data) != "frozen" {
					t.Fatal("retry rerendered request")
				}
				status := 401
				if calls == 2 {
					status = 403
				}
				return response(status), nil
			})}})
			p, err := e.Prepare(&Tool{Method: "POST", URL: "http://example.com/data", Body: "{{value}}", Params: []domain.Param{{Name: "value", Type: "string"}}}, map[string]any{"value": "frozen"})
			if err != nil {
				t.Fatal(err)
			}
			res, err := e.Send(p)
			if allowed {
				if err != nil || !res.Relogged || res.Status != 403 {
					t.Fatalf("result=%+v err=%v", res, err)
				}
			} else {
				var login *LoginErr
				if !errors.As(err, &login) && (err == nil || !strings.Contains(err.Error(), "自动登录后")) {
					t.Fatalf("expected scrubbed login failure: %v", err)
				}
			}
			tail := "invalid"
			if allowed {
				tail = "classify"
			}
			want := []string{"begin", "cookies", "wire", "classify", "login", "cookies", "wire", "classify"}
			if !allowed {
				want = append(want, tail)
			}
			if !reflect.DeepEqual(events, want) {
				t.Fatalf("order=%v want=%v", events, want)
			}
		})
	}
}
func TestGuardAndPendingSessionFailBeforeCredentialOrTransportCallbacks(t *testing.T) {
	for _, blocked := range []bool{true, false} {
		events := []string{}
		e := New(Options{Vault: &vault.Vault{}, ConsolePort: 19000, Sessions: sessionPort{events: &events, err: errors.New("pending login")}, Cookies: func(string) ([]Cookie, string) { t.Fatal("cookies read after rejected request"); return nil, "" }, HTTPClient: &http.Client{Transport: executionTransport(func(*http.Request) (*http.Response, error) { t.Fatal("sent rejected request"); return nil, nil })}})
		raw := "http://example.com/data"
		if blocked {
			raw = "http://127.0.0.1:19000/mcp"
		}
		p, err := e.Prepare(&Tool{Method: "GET", URL: raw}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = e.Send(p); err == nil {
			t.Fatal("request not rejected")
		}
		want := 0
		if !blocked {
			want = 1
		}
		if len(events) != want {
			t.Fatalf("callback order: %v", events)
		}
	}
}

type consolePort struct{ events *[]string }

func (c consolePort) Refresh(t *Tool, args map[string]any) (*Tool, error) {
	*c.events = append(*c.events, "refresh")
	fresh := *t
	fresh.URL = "http://example.com/refreshed"
	return &fresh, nil
}
func (c consolePort) Preview(t *Tool, args map[string]any) (string, string, []string, bool) {
	*c.events = append(*c.events, "preview")
	return "console", "alias", []string{"env-live"}, true
}
func TestConsolePortDisplayAndFrozenFingerprint(t *testing.T) {
	events := []string{}
	e := New(Options{Console: consolePort{&events}})
	tool := &Tool{Method: "POST", URL: "http://example.com/old", Body: "body"}
	tool.BindConsole(ConsoleBinding{ID: 12})
	p, err := e.Prepare(tool, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(events, []string{"refresh", "preview"}) || p.request.URL != "http://example.com/refreshed" || !strings.Contains(p.Preview.URL, "console") {
		t.Fatal("console port did not refresh before freezing")
	}
	hash := p.Fingerprint()
	p.Preview.Body = "changed display"
	p.PreviewHash = "untrusted display hash"
	if p.Fingerprint() != hash {
		t.Fatal("mutable preview changed frozen fingerprint")
	}
	if e.ScrubPrepared("env-live", p, true) != vault.Mask || e.ScrubPrepared("env-live", p, false) != "env-live" {
		t.Fatal("configuration redaction broadened to result data")
	}
	p.request.Body += " "
	if p.Fingerprint() == hash {
		t.Fatal("modified frozen request passed integrity check")
	}
}
func TestWSReloginPortPreservesEarlyReturnAndFailure(t *testing.T) {
	events := []string{}
	sentinel := errors.New("login failed")
	e := New(Options{Sessions: sessionPort{events: &events, err: sentinel}})
	p := &PreparedCall{request: domain.RequestPreview{URL: "ws://example.com/data"}}
	stats := wsSessionStats{}
	if err := e.reloginForWS(p, &stats); !errors.Is(err, sentinel) || stats.relogins != 1 {
		t.Fatal("relogin failure not propagated")
	}
	e.sessions = sessionPort{events: &events, wait: false}
	p.subs = []credentialSubstitution{{ref: "header.token"}}
	e.header = func(string, string) (string, error) {
		t.Fatal("provider early-return unexpectedly waited for headers")
		return "", nil
	}
	if err := e.reloginForWS(p, &stats); err != nil || stats.relogins != 2 {
		t.Fatal("relogin early return changed")
	}
}
func TestPreparationClockAndReviewRedactionRemainFrozen(t *testing.T) {
	clockCalls := 0
	e := New(Options{Now: func() time.Time { clockCalls++; return time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC) }})
	tool := &Tool{Method: "POST", URL: "http://example.com/data", Body: `{"date":"{{date}}","token":"{{label}}"}`, Params: []domain.Param{{Name: "date", Type: "string", Default: "@today"}, {Name: "label", Type: "string"}}}
	prior, err := e.Prepare(tool, map[string]any{"label": "previous-secret"})
	if err != nil {
		t.Fatal(err)
	}
	next, err := e.Prepare(tool, map[string]any{"label": "replacement-secret"})
	if err != nil {
		t.Fatal(err)
	}
	if clockCalls != 2 || !strings.Contains(prior.request.Body, "2026-11-17") {
		t.Fatal("preparation did not freeze one clock snapshot")
	}
	hash := next.Fingerprint()
	e.ReviewPreview(next, prior, true)
	if next.Fingerprint() != hash || e.ScrubPrepared("previous-secret replacement-secret", next, false) != vault.Mask+" "+vault.Mask {
		t.Fatal("confirmation lost historical redaction or mutated execution")
	}
}

func TestPreparedRawSecretsNeverRewrittenByDisplay(t *testing.T) {
	e := New(Options{})
	for _, kind := range []string{"json", "form", "query"} {
		for _, label := range []any{float64(23), "token"} {
			t.Run(kind+"/"+domain.ArgumentText(label), func(t *testing.T) {
				tool := &Tool{Method: "POST", URL: "http://example.com/data", Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"password":{{label}},"token":"private-static-value"}`, Params: []domain.Param{{Name: "label", Type: "int"}}}
				expected := `{"password":23,"token":"private-static-value"}`
				if label == "token" {
					tool.Params[0].Type = "string"
					tool.Body = `{"password":"{{label}}","token":"private-static-value"}`
					expected = `{"password":"token","token":"private-static-value"}`
				}
				if kind == "form" {
					tool.Headers["Content-Type"] = "application/x-www-form-urlencoded"
					tool.Body = "password={{label}}&token=private-static-value"
					expected = "password=" + domain.ArgumentText(label) + "&token=private-static-value"
				}
				if kind == "query" {
					tool.URL += "?password={{label}}&token=private-static-value"
					tool.Body = ""
					expected = ""
				}
				p, err := e.Prepare(tool, map[string]any{"label": label})
				if err != nil {
					t.Fatal(err)
				}
				expectedURL := strings.ReplaceAll(tool.URL, "{{label}}", domain.ArgumentText(label))
				if p.request.Body != expected || p.request.URL != expectedURL {
					t.Fatal("redaction modified frozen raw request")
				}
				if !strings.Contains(strings.Join(p.secretValues, " "), "private-static-value") || strings.Contains(p.Preview.Body+p.Preview.URL, "private-static-value") {
					t.Fatal("literal secret was not separately captured and masked")
				}
			})
		}
	}
	for _, scheme := range []string{"http", "https", "ws", "wss", "odd+transport", "odd_scheme"} {
		raw := " " + scheme + "://demo:private-password-value@example.com/api "
		p, err := e.Prepare(&Tool{Method: "POST", URL: raw}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if p.request.URL != raw || p.Preview.URL != strings.Replace(raw, "private-password-value", vault.Mask, 1) || !strings.Contains(strings.Join(p.secretValues, " "), "private-password-value") {
			t.Fatal("whitespace URL or userinfo redaction changed")
		}
	}
}
