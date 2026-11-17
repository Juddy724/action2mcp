package console

import (
	"action2mcp/internal/credential"
	"action2mcp/internal/domain"
	"action2mcp/internal/recording"
	sitecfg "action2mcp/internal/site"
	"action2mcp/internal/vault"
	"errors"
	"net"
	"net/http"
	"strings"
)

func isLoopback(r *http.Request) bool {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		h = r.RemoteAddr
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

type siteView struct {
	*sitecfg.Site
	Pending    bool     `json:"pending"`
	PendingMsg string   `json:"pending_msg,omitempty"`
	Cooldown   string   `json:"cooldown,omitempty"`
	Relogins   int      `json:"relogins"`
	Tools      []string `json:"tools"`
	Creds      []string `json:"creds"`
}

func (a *Server) siteViews() []siteView {
	tools, _ := a.store.ListTools()
	out := []siteView{}
	for _, s := range a.store.ListSites() {
		v := siteView{Site: s, Tools: []string{}, Creds: []string{}}
		state := a.login().Snapshot(s.Origin)
		v.Pending, v.PendingMsg, v.Relogins, v.Cooldown = state.Pending, state.PendingMsg, state.Relogins, state.Cooldown

		for _, t := range tools {
			if credential.SameSite(credential.Origin(t.URL), s.Origin) {
				v.Tools = append(v.Tools, t.Name)
			}
		}
		for name := range a.vault.ForSite(s.Origin) {
			v.Creds = append(v.Creds, name)
		}
		// never send the recorded login body with real values (it only has {{...}} refs anyway)
		if s.Form.Request != nil {
			r := *s.Form.Request
			r.Body = a.vault.Scrub(r.Body)
			v.Site.Form.Request = &r
		}
		out = append(out, v)
	}
	return out
}

func (a *Server) vaultUsage() map[string][]string {
	use := map[string][]string{}
	tools, _ := a.store.ListTools()
	for _, t := range tools {
		for _, ref := range t.RenderRefs() {
			_, n, _ := strings.Cut(ref, ".")
			use[n] = append(use[n], "工具 "+t.Name)
		}
	}
	for _, s := range a.store.ListSites() {
		for _, ref := range []string{s.Form.UsernameRef, s.Form.PasswordRef} {
			if _, n, ok := strings.Cut(ref, "."); ok {
				use[n] = append(use[n], "登录 "+s.DisplayName())
			}
		}
	}
	ms, _ := a.store.ListMiddleware()
	for _, m := range ms {
		if m.Config.PasswordRef != "" {
			use[m.Config.PasswordRef] = append(use[m.Config.PasswordRef], "中间件 "+m.Name)
		}
	}
	return use
}

func (a *Server) registerV2(mux *http.ServeMux) {
	// ---------- 配置管理 ----------
	mux.HandleFunc("GET /api/vault", func(w http.ResponseWriter, r *http.Request) {
		use := a.vaultUsage()
		type item struct {
			vault.VaultItem
			UsedBy []string `json:"used_by"`
		}
		out := []item{}
		for _, it := range a.vault.List() {
			u := use[it.Name]
			if u == nil {
				u = []string{}
			}
			out = append(out, item{it, u})
		}
		writeJSON(w, 200, map[string]any{"items": out, "can_reveal": isLoopback(r)})
	})
	saveVault := func(w http.ResponseWriter, r *http.Request, id int64) {
		var in struct {
			vault.VaultItem
			Value     string `json:"value"`
			KeepValue bool   `json:"keep_value"`
		}
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		it := in.VaultItem
		it.ID = id
		if err := a.vault.Save(&it, in.Value, in.KeepValue); err != nil {
			writeErr(w, 400, err)
			return
		}
		a.login().ResetSiteFailures()
		got, _ := a.vault.GetByID(it.ID)
		writeJSON(w, 200, got)
	}
	mux.HandleFunc("POST /api/vault", func(w http.ResponseWriter, r *http.Request) { saveVault(w, r, 0) })
	mux.HandleFunc("PUT /api/vault/{id}", func(w http.ResponseWriter, r *http.Request) { saveVault(w, r, pathID(r)) })
	mux.HandleFunc("DELETE /api/vault/{id}", func(w http.ResponseWriter, r *http.Request) {
		if err := a.vault.Delete(pathID(r)); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/vault/{id}/reveal", func(w http.ResponseWriter, r *http.Request) {
		if !isLoopback(r) {
			writeErr(w, 403, errors.New("只能在本机的控制台查看配置值"))
			return
		}
		v, err := a.vault.Reveal(pathID(r))
		if err != nil {
			writeErr(w, 404, err)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		writeJSON(w, 200, map[string]any{"value": v})
	})

	// ---------- 登录中心 ----------
	mux.HandleFunc("GET /api/sites", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, a.siteViews())
	})
	saveSite := func(w http.ResponseWriter, r *http.Request, id int64) {
		var s sitecfg.Site
		if err := readJSON(r, &s); err != nil {
			writeErr(w, 400, err)
			return
		}
		s.ID = id
		if id != 0 {
			old, err := a.store.GetSite(id)
			if err != nil {
				writeErr(w, 404, errors.New("站点不存在"))
				return
			}
			// the recorded login request is not editable in the UI; keep it (switching to "fill" just stops using it)
			if s.Form.Request == nil && old.Form.Request != nil {
				s.Form.Request = old.Form.Request
			}
		}
		if s.Form.Request != nil {
			s.Form.Request.Body = a.vault.ToRefs(s.Form.Request.Body)
		}
		if err := a.store.SaveSite(&s); err != nil {
			writeErr(w, 400, err)
			return
		}
		a.login().ResetSiteFailures()
		writeJSON(w, 200, s)
	}
	mux.HandleFunc("POST /api/sites", func(w http.ResponseWriter, r *http.Request) { saveSite(w, r, 0) })
	mux.HandleFunc("PUT /api/sites/{id}", func(w http.ResponseWriter, r *http.Request) { saveSite(w, r, pathID(r)) })
	mux.HandleFunc("DELETE /api/sites/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := pathID(r)
		if s, err := a.store.GetSite(id); err == nil && s != nil {
			_ = a.login().ClearSiteHeaders(s.Origin)
		}
		a.store.DeleteSite(id)
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/sites/{id}/relogin", func(w http.ResponseWriter, r *http.Request) {
		s, err := a.store.GetSite(pathID(r))
		if err != nil {
			writeErr(w, 404, errors.New("站点不存在"))
			return
		}
		a.login().ResetSiteFailures()
		if err := a.login().Relogin(s, a.login().Generation(s.Origin), true, true); err != nil {
			writeJSON(w, 200, map[string]any{"ok": false, "error": a.vault.Scrub(err.Error())})
			return
		}
		ok, msg := a.login().CheckSite(s)
		writeJSON(w, 200, map[string]any{"ok": true, "check": ok, "check_msg": msg})
	})
	mux.HandleFunc("POST /api/sites/{id}/check", func(w http.ResponseWriter, r *http.Request) {
		s, err := a.store.GetSite(pathID(r))
		if err != nil {
			writeErr(w, 404, errors.New("站点不存在"))
			return
		}
		ok, msg := a.login().CheckSite(s)
		writeJSON(w, 200, map[string]any{"ok": ok, "msg": msg})
	})
	mux.HandleFunc("POST /api/sites/{id}/open", func(w http.ResponseWriter, r *http.Request) {
		s, err := a.store.GetSite(pathID(r))
		if err != nil {
			writeErr(w, 404, errors.New("站点不存在"))
			return
		}
		if err := a.login().OpenLoginWindow(s); err != nil {
			writeErr(w, 500, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.Handle("POST /api/sites/{id}/cancel", a.approvalOnly(func(w http.ResponseWriter, r *http.Request) {
		var in map[string]any
		if err := readJSON(r, &in); err != nil && r.ContentLength > 0 {
			writeErr(w, 400, err)
			return
		}
		s, err := a.store.GetSite(pathID(r))
		if err != nil {
			writeErr(w, 404, errors.New("站点不存在"))
			return
		}
		if err := a.login().CancelLogin(s); err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}))

	// ---------- 录制：保存为登录配置 ----------
	mux.HandleFunc("POST /api/recordings/{id}/detect-login", func(w http.ResponseWriter, r *http.Request) {
		rec, err := a.store.GetRecording(pathID(r))
		if err != nil {
			writeErr(w, 404, errors.New("录制不存在"))
			return
		}
		if rec.Status == "recording" {
			writeErr(w, 409, errors.New("请先结束录制，再加入登录中心"))
			return
		}
		res, err := a.detectRecordingLogin(*rec)
		if err != nil {
			writeErr(w, 500, errors.New("识别登录失败，请稍后重试"))
			return
		}
		writeJSON(w, 200, res)
	})
	mux.HandleFunc("POST /api/requests/{id}/save-login", func(w http.ResponseWriter, r *http.Request) {
		q, err := a.store.GetRequest(pathID(r))
		if err != nil {
			writeErr(w, 404, errors.New("请求不存在"))
			return
		}
		var in struct {
			UsernameName string `json:"username_name"`
			PasswordName string `json:"password_name"`
		}
		readJSON(r, &in)
		res, err := a.analysis().SaveLogin(q, strings.TrimSpace(in.UsernameName), strings.TrimSpace(in.PasswordName))
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		writeJSON(w, 200, res)
	})
}

func (a *Server) detectRecordingLogin(rec recording.Recording) (*domain.RecordingLoginResult, error) {
	return sitecfg.NewRecordingDetector(a.store).Detect(rec)
}
