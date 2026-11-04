// democrm: a tiny fake CRM used for end-to-end testing of Action2MCP.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
)

var (
	mu       sync.Mutex
	sessions = map[string]string{} // session -> xsrf
)

type Customer struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Phone  string `json:"phone"`
	Level  string `json:"level"`
	Region string `json:"region"`
}

var customers = []Customer{
	{1, "张三贸易有限公司", "13800000001", "VIP", "华东"},
	{2, "李四科技", "13800000002", "普通", "华北"},
	{3, "王五餐饮", "13800000003", "VIP", "华南"},
	{4, "张记五金", "13800000004", "普通", "华东"},
	{5, "赵六物流", "13800000005", "重点", "西南"},
}

func rid() string { b := make([]byte, 12); rand.Read(b); return hex.EncodeToString(b) }

func authed(r *http.Request) (string, bool) {
	c, err := r.Cookie("crm_session")
	if err != nil {
		return "", false
	}
	mu.Lock()
	defer mu.Unlock()
	x, ok := sessions[c.Value]
	return x, ok
}

func js(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

const loginHTML = `<!doctype html><html><head><meta charset="utf-8"><title>DemoCRM 登录</title><link rel="stylesheet" href="/static/style.css"></head>
<body><div class="box"><h1>DemoCRM</h1><input id="u" placeholder="用户名" value=""><input id="p" type="password" placeholder="密码"><button id="login">登录</button><div id="msg"></div></div>
<script>
document.getElementById('login').onclick=async()=>{
  const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u.value,password:p.value})});
  if(r.ok){location.href='/'}else{msg.textContent='登录失败'}
};
</script></body></html>`

const appHTML = `<!doctype html><html><head><meta charset="utf-8"><title>DemoCRM 客户管理</title><link rel="stylesheet" href="/static/style.css"><script src="/static/app.js"></script></head>
<body><div class="box wide"><img src="/static/logo.png" width="24"> <b>DemoCRM 客户管理</b> <span id="who"></span>
<div><input id="kw" placeholder="客户名称关键字"><button id="search">查询</button></div>
<table id="tbl"></table></div>
<script>
function xsrf(){const m=document.cookie.match(/XSRF-TOKEN=([^;]+)/);return m?decodeURIComponent(m[1]):''}
fetch('/api/config');fetch('/api/dict?type=region');fetch('/api/permission/list');
fetch('/api/user/info').then(r=>r.json()).then(j=>who.textContent='当前用户：'+j.name);
navigator.sendBeacon('/collect?ev=pv',JSON.stringify({page:location.pathname}));
document.getElementById('search').onclick=async()=>{
  fetch('/collect?ev=click_search',{method:'POST',body:'{}'});
  const r=await fetch('/api/customer/search',{method:'POST',headers:{'Content-Type':'application/json','X-XSRF-TOKEN':xsrf()},body:JSON.stringify({keyword:kw.value,page:1,pageSize:10})});
  const j=await r.json();
  tbl.innerHTML='<tr><th>ID</th><th>名称</th><th>电话</th><th>等级</th></tr>'+(j.data||[]).map(c=>'<tr><td>'+c.id+'</td><td>'+c.name+'</td><td>'+c.phone+'</td><td>'+c.level+'</td></tr>').join('');
  document.body.dataset.searched=String(j.total);
};
</script></body></html>`

// 1x1 png
var png = []byte{0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0x0d, 0x49, 0x48, 0x44, 0x52, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6, 0, 0, 0, 0x1f, 0x15, 0xc4, 0x89, 0, 0, 0, 0x0d, 0x49, 0x44, 0x41, 0x54, 0x78, 0x9c, 0x63, 0xf8, 0xcf, 0xc0, 0xf0, 0x1f, 0, 5, 0, 1, 0xff, 0x89, 0x99, 0x3d, 0x1d, 0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0xae, 0x42, 0x60, 0x82}

func main() {
	addr := flag.String("addr", "127.0.0.1:9000", "listen address")
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, loginHTML)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authed(r); !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, appHTML)
	})
	mux.HandleFunc("GET /static/style.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		fmt.Fprint(w, `body{font-family:sans-serif;background:#f3f4f6}.box{margin:60px auto;width:320px;background:#fff;padding:24px;border-radius:8px}.wide{width:640px}input{display:block;margin:8px 0;padding:6px;width:100%}td,th{padding:4px 8px;border-bottom:1px solid #eee}`)
	})
	mux.HandleFunc("GET /static/app.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		fmt.Fprint(w, `window.CRM_VERSION="1.0";`)
	})
	mux.HandleFunc("GET /static/logo.png", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(png)
	})
	mux.HandleFunc("POST /api/login", func(w http.ResponseWriter, r *http.Request) {
		var in struct{ Username, Password string }
		json.NewDecoder(r.Body).Decode(&in)
		if in.Username != "demo" || in.Password != "demo123" {
			js(w, 401, map[string]any{"code": 401, "msg": "用户名或密码错误"})
			return
		}
		s, x := rid(), rid()
		mu.Lock()
		sessions[s] = x
		mu.Unlock()
		// session cookie: no Expires, HttpOnly — like many real systems
		http.SetCookie(w, &http.Cookie{Name: "crm_session", Value: s, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
		http.SetCookie(w, &http.Cookie{Name: "XSRF-TOKEN", Value: x, Path: "/", SameSite: http.SameSiteLaxMode})
		log.Printf("login ok session=%s…", s[:6])
		js(w, 200, map[string]any{"code": 0})
	})
	mux.HandleFunc("GET /api/config", func(w http.ResponseWriter, r *http.Request) {
		js(w, 200, map[string]any{"theme": "light", "version": "1.0"})
	})
	mux.HandleFunc("GET /api/dict", func(w http.ResponseWriter, r *http.Request) {
		js(w, 200, []string{"华东", "华北", "华南", "西南"})
	})
	mux.HandleFunc("GET /api/permission/list", func(w http.ResponseWriter, r *http.Request) { js(w, 200, []string{"customer:read"}) })
	mux.HandleFunc("GET /api/user/info", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authed(r); !ok {
			js(w, 401, map[string]any{"code": 401})
			return
		}
		js(w, 200, map[string]any{"name": "演示用户"})
	})
	mux.HandleFunc("/collect", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204) })
	mux.HandleFunc("POST /api/customer/search", func(w http.ResponseWriter, r *http.Request) {
		x, ok := authed(r)
		if !ok {
			log.Printf("search REJECTED: no valid session cookie")
			js(w, 401, map[string]any{"code": 401, "msg": "未登录或会话已过期"})
			return
		}
		if r.Header.Get("X-XSRF-TOKEN") != x {
			log.Printf("search REJECTED: bad xsrf token")
			js(w, 403, map[string]any{"code": 403, "msg": "CSRF 校验失败"})
			return
		}
		var in struct {
			Keyword  string `json:"keyword"`
			Page     int    `json:"page"`
			PageSize int    `json:"pageSize"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			js(w, 400, map[string]any{"code": 400, "msg": "bad json: " + err.Error()})
			return
		}
		out := []Customer{}
		for _, c := range customers {
			if strings.Contains(c.Name, in.Keyword) {
				out = append(out, c)
			}
		}
		log.Printf("search OK keyword=%q page=%d pageSize=%d -> %d", in.Keyword, in.Page, in.PageSize, len(out))
		js(w, 200, map[string]any{"code": 0, "total": len(out), "data": out})
	})
	log.Printf("DemoCRM on http://%s  (demo / demo123)", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
