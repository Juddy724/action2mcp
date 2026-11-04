// demosso: fake 企业微信 SSO + three internal sites for Action2MCP e2e tests.
//
//	SSO  http://127.0.0.10:9100  (cookie wwsso, 7 days; /qr page = "scan" + confirm)
//	A    http://127.0.0.11:9201  (SSO login; JSON API returns 401 when not logged in)
//	B    http://127.0.0.12:9202  (form login with CSRF; API returns 401 {"code":"NOT_LOGIN"})
//	C    http://127.0.0.13:9203  (ZenTao-like: 200 + <script>top.location=login</script>, 企业微信登录 button)
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func tok() string { b := make([]byte, 12); rand.Read(b); return hex.EncodeToString(b) }

type sessions struct {
	mu sync.Mutex
	m  map[string]string // token -> user
}

func (s *sessions) new(user string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := tok()
	s.m[t] = user
	return t
}
func (s *sessions) get(r *http.Request, name string) string {
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[c.Value]
}
func (s *sessions) clear() { s.mu.Lock(); s.m = map[string]string{}; s.mu.Unlock() }

var (
	sso   = &sessions{m: map[string]string{}}
	codes = &sessions{m: map[string]string{}}
	sa    = &sessions{m: map[string]string{}}
	sb    = &sessions{m: map[string]string{}}
	sc    = &sessions{m: map[string]string{}}

	bPass   atomic.Value
	stats   sync.Map // name -> *int64
	csrfMu  sync.Mutex
	bCSRF   = map[string]string{} // b_pre -> token
	ssoBase = "http://127.0.0.10:9100"
)

func inc(n string) {
	v, _ := stats.LoadOrStore(n, new(int64))
	atomic.AddInt64(v.(*int64), 1)
}

func page(w http.ResponseWriter, title, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><head><meta charset="utf-8"><title>%s</title></head><body style="font-family:sans-serif;padding:30px">%s</body></html>`, title, body)
}
func js(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// ---------------- SSO ----------------
func ssoMux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		inc("sso_authorize")
		redir := r.URL.Query().Get("redirect_uri")
		if u := sso.get(r, "wwsso"); u != "" {
			code := codes.new(u)
			sep := "?"
			if strings.Contains(redir, "?") {
				sep = "&"
			}
			http.Redirect(w, r, redir+sep+"code="+code, 302)
			return
		}
		http.Redirect(w, r, "/qr?redirect_uri="+url.QueryEscape(redir), 302)
	})
	m.HandleFunc("/qr", func(w http.ResponseWriter, r *http.Request) {
		inc("sso_qr")
		redir := r.URL.Query().Get("redirect_uri")
		page(w, "企业微信登录", `<h2>企业微信扫码登录（模拟）</h2><div style="width:160px;height:160px;background:repeating-linear-gradient(45deg,#000 0 6px,#fff 6px 12px)"></div>
<p>请使用企业微信扫描二维码</p><form method="post" action="/confirm"><input type="hidden" name="redirect_uri" value="`+html.EscapeString(redir)+`"><button id="confirm" type="submit">（模拟）手机上确认登录</button></form>`)
	})
	m.HandleFunc("/confirm", func(w http.ResponseWriter, r *http.Request) {
		inc("sso_confirm")
		r.ParseForm()
		t := sso.new("zhangsan")
		http.SetCookie(w, &http.Cookie{Name: "wwsso", Value: t, Path: "/", Expires: time.Now().Add(7 * 24 * time.Hour), HttpOnly: true})
		redir := r.PostForm.Get("redirect_uri")
		if redir == "" {
			page(w, "已登录", "企业微信已登录")
			return
		}
		code := codes.new("zhangsan")
		sep := "?"
		if strings.Contains(redir, "?") {
			sep = "&"
		}
		http.Redirect(w, r, redir+sep+"code="+code, 302)
	})
	m.HandleFunc("/__admin/expire", func(w http.ResponseWriter, r *http.Request) { sso.clear(); js(w, 200, map[string]any{"ok": true}) })
	m.HandleFunc("/__stats", func(w http.ResponseWriter, r *http.Request) {
		out := map[string]int64{}
		stats.Range(func(k, v any) bool { out[k.(string)] = atomic.LoadInt64(v.(*int64)); return true })
		js(w, 200, out)
	})
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if u := sso.get(r, "wwsso"); u != "" {
			page(w, "企业微信", "已登录："+u)
			return
		}
		http.Redirect(w, r, "/qr", 302)
	})
	return m
}

func ssoCallback(s *sessions, cookie, name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		codes.mu.Lock()
		u := codes.m[code]
		delete(codes.m, code)
		codes.mu.Unlock()
		if u == "" {
			http.Error(w, "bad code", 400)
			return
		}
		inc(name + "_sso_login")
		http.SetCookie(w, &http.Cookie{Name: cookie, Value: s.new(u), Path: "/", HttpOnly: true})
		next := r.URL.Query().Get("next")
		if next == "" {
			next = "/"
		}
		http.Redirect(w, r, next, 302)
	}
}

// ---------------- A: SSO site, JSON API ----------------
func aMux() *http.ServeMux {
	base := "http://127.0.0.11:9201"
	m := http.NewServeMux()
	m.HandleFunc("/sso/login", func(w http.ResponseWriter, r *http.Request) {
		cb := base + "/sso/callback?next=" + url.QueryEscape(r.URL.Query().Get("next"))
		http.Redirect(w, r, ssoBase+"/authorize?appid=a&redirect_uri="+url.QueryEscape(cb), 302)
	})
	m.HandleFunc("/sso/callback", ssoCallback(sa, "a_session", "a"))
	m.HandleFunc("/api/orders", func(w http.ResponseWriter, r *http.Request) {
		inc("a_api")
		u := sa.get(r, "a_session")
		if u == "" {
			js(w, 401, map[string]any{"code": 401, "msg": "未登录"})
			return
		}
		q := r.URL.Query().Get("q")
		js(w, 200, map[string]any{"code": 0, "user": u, "orders": []map[string]any{{"id": "A-1001", "customer": q, "amount": 128}}})
	})
	m.HandleFunc("/api/report", func(w http.ResponseWriter, r *http.Request) { // GET API that redirects to login when logged out
		if sa.get(r, "a_session") == "" {
			http.Redirect(w, r, "/sso/login?next=/api/report", 302)
			return
		}
		js(w, 200, map[string]any{"report": "ok"})
	})
	m.HandleFunc("/__admin/expire", func(w http.ResponseWriter, r *http.Request) { sa.clear(); js(w, 200, map[string]any{"ok": true}) })
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		u := sa.get(r, "a_session")
		if u == "" {
			http.Redirect(w, r, "/sso/login?next=/", 302)
			return
		}
		page(w, "A 系统", `<h2>A 系统 · 订单</h2><p>当前用户：`+u+`</p><input id="q" value="ACME"><button id="search" onclick="fetch('/api/orders?q='+encodeURIComponent(document.getElementById('q').value)).then(r=>r.json()).then(j=>document.getElementById('out').textContent=JSON.stringify(j))">查询</button><pre id="out"></pre>`)
	})
	return m
}

// ---------------- B: form login with CSRF ----------------
func bLoginPage(w http.ResponseWriter, r *http.Request, msg string) {
	pre := tok()
	t := tok()
	csrfMu.Lock()
	bCSRF[pre] = t
	csrfMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "b_pre", Value: pre, Path: "/", HttpOnly: true})
	errHTML := ""
	if msg != "" {
		errHTML = `<p id="err" style="color:red">` + msg + `</p>`
	}
	page(w, "B 系统登录", `<h2>B 系统登录</h2>`+errHTML+`<form method="post" action="/login"><input type="hidden" name="csrf_token" value="`+t+`">
账号 <input name="account" id="account"><br>密码 <input type="password" name="password" id="password"><br><button type="submit" id="loginbtn">登录</button></form>`)
}

func bMux() *http.ServeMux {
	m := http.NewServeMux()
	m.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) { bLoginPage(w, r, "") })
	m.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		inc("b_login_post")
		r.ParseForm()
		pc, _ := r.Cookie("b_pre")
		csrfMu.Lock()
		want := ""
		if pc != nil {
			want = bCSRF[pc.Value]
			delete(bCSRF, pc.Value)
		}
		csrfMu.Unlock()
		if want == "" || r.PostForm.Get("csrf_token") != want {
			inc("b_login_badcsrf")
			w.WriteHeader(403)
			bLoginPage(w, r, "页面已过期（CSRF 校验失败），请重新登录")
			return
		}
		if r.PostForm.Get("account") != "alice" || r.PostForm.Get("password") != bPass.Load().(string) {
			inc("b_login_fail")
			bLoginPage(w, r, "用户名或密码错误")
			return
		}
		inc("b_login_ok")
		http.SetCookie(w, &http.Cookie{Name: "b_sid", Value: sb.new("alice"), Path: "/", HttpOnly: true})
		http.Redirect(w, r, "/", 302)
	})
	m.HandleFunc("/api/tickets", func(w http.ResponseWriter, r *http.Request) {
		inc("b_api")
		u := sb.get(r, "b_sid")
		if u == "" {
			js(w, 401, map[string]any{"code": "NOT_LOGIN", "msg": "请先登录"})
			return
		}
		js(w, 200, map[string]any{"code": 0, "user": u, "tickets": []map[string]any{{"id": 7, "title": "打印机坏了", "status": r.URL.Query().Get("status")}}})
	})
	m.HandleFunc("/api/profile", func(w http.ResponseWriter, r *http.Request) { // deliberately echoes the password (leak test)
		if sb.get(r, "b_sid") == "" {
			js(w, 401, map[string]any{"code": "NOT_LOGIN"})
			return
		}
		js(w, 200, map[string]any{"user": "alice", "debug_password": bPass.Load().(string)})
	})
	m.HandleFunc("/__admin/expire", func(w http.ResponseWriter, r *http.Request) { sb.clear(); js(w, 200, map[string]any{"ok": true}) })
	m.HandleFunc("/__admin/setpass", func(w http.ResponseWriter, r *http.Request) {
		bPass.Store(r.URL.Query().Get("p"))
		js(w, 200, map[string]any{"ok": true})
	})
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		u := sb.get(r, "b_sid")
		if u == "" {
			http.Redirect(w, r, "/login", 302)
			return
		}
		page(w, "B 系统", `<h2>B 系统 · 工单</h2><p>当前用户：`+u+`</p><button id="load" onclick="fetch('/api/tickets?status=open').then(r=>r.json()).then(j=>document.getElementById('out').textContent=JSON.stringify(j))">加载工单</button><pre id="out"></pre>`)
	})
	return m
}

// ---------------- C: ZenTao-like ----------------
func cMux() *http.ServeMux {
	base := "http://127.0.0.13:9203"
	m := http.NewServeMux()
	m.HandleFunc("/user-login.html", func(w http.ResponseWriter, r *http.Request) {
		page(w, "用户登录 - 禅道", `<h2>禅道（模拟）</h2><form method="post" action="/user-login.html">账号 <input name="account"><br>密码 <input type="password" name="password"><br><button type="submit">登录</button></form>
<p><a id="wwlogin" href="/sso/login">企业微信登录</a></p>`)
	})
	m.HandleFunc("/sso/login", func(w http.ResponseWriter, r *http.Request) {
		cb := base + "/sso/callback"
		http.Redirect(w, r, ssoBase+"/authorize?appid=c&redirect_uri="+url.QueryEscape(cb), 302)
	})
	m.HandleFunc("/sso/callback", ssoCallback(sc, "zentaosid", "c"))
	m.HandleFunc("/my-task.json", func(w http.ResponseWriter, r *http.Request) {
		inc("c_api")
		if sc.get(r, "zentaosid") == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<html><head><meta charset="utf-8"></head><body><script>top.location='/user-login.html';</script></body></html>`)
			return
		}
		js(w, 200, map[string]any{"status": "success", "data": `{"tasks":[{"id":42,"name":"修复登录"}]}`})
	})
	m.HandleFunc("/__admin/expire", func(w http.ResponseWriter, r *http.Request) { sc.clear(); js(w, 200, map[string]any{"ok": true}) })
	m.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if sc.get(r, "zentaosid") == "" {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprint(w, `<html><head><meta charset="utf-8"></head><body><script>top.location='/user-login.html';</script></body></html>`)
			return
		}
		page(w, "我的地盘 - 禅道", "<h2>我的地盘</h2><p>欢迎 zhangsan</p>")
	})
	return m
}

func main() {
	bPass.Store("S3cr3t&pw!")
	srv := map[string]*http.ServeMux{"127.0.0.10:9100": ssoMux(), "127.0.0.11:9201": aMux(), "127.0.0.12:9202": bMux(), "127.0.0.13:9203": cMux()}
	for addr, m := range srv {
		go func(addr string, m *http.ServeMux) {
			log.Printf("listen %s", addr)
			log.Fatal(http.ListenAndServe(addr, logged(addr, m)))
		}(addr, m)
	}
	select {}
}

func logged(name string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/favicon.ico" {
			http.NotFound(w, r)
			return
		}
		log.Printf("%s %s %s", name, r.Method, r.URL.RequestURI())
		h.ServeHTTP(w, r)
	})
}
