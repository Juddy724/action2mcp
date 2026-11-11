package main

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

var autoMWSecret = regexp.MustCompile(`^mw_[0-9a-f]{8}_password$`)

type mwView struct {
	*Middleware
	PasswordSet bool     `json:"password_set"`
	Packs       []string `json:"packs"`
	Summary     string   `json:"summary"`
	KindLabel   string   `json:"kind_label"`
}

type mwInput struct {
	Middleware
	Password      string `json:"password"`       // write-only
	ClearPassword bool   `json:"clear_password"` // remove the password
}

var mwTestSeq int64

func (a *App) mwViews() []mwView {
	ms, _ := a.store.ListMiddleware()
	packs, _ := a.store.ListPacks()
	byMW := map[int64][]string{}
	for _, p := range packs {
		for _, id := range p.MiddlewareIDs {
			label := p.Name
			if !p.Enabled {
				label += "（未开启）"
			}
			byMW[id] = append(byMW[id], label)
		}
	}
	out := []mwView{}
	for _, m := range ms {
		v := mwView{Middleware: m, Packs: byMW[m.ID], Summary: a.mwSummary(m), KindLabel: m.kindLabel()}
		if v.Packs == nil {
			v.Packs = []string{}
		}
		if m.Config.PasswordRef != "" {
			val, _ := a.vault.Lookup(m.Config.PasswordRef)
			v.PasswordSet = val != ""
		}
		out = append(out, v)
	}
	return out
}

func (a *App) vaultIDByName(name string) int64 {
	for _, it := range a.vault.List() {
		if it.Name == name {
			return it.ID
		}
	}
	return 0
}

// prepareMW merges the input with the stored middleware (password ref is kept unless changed).
func (a *App) prepareMW(in *mwInput, id int64) (*Middleware, error) {
	m := in.Middleware
	m.ID = id
	m.Name = strings.TrimSpace(m.Name)
	ref := strings.TrimSpace(m.Config.PasswordRef)
	if id != 0 {
		old, err := a.store.GetMiddleware(id)
		if err != nil {
			return nil, errors.New("中间件不存在")
		}
		if ref == "" && !in.ClearPassword {
			ref = old.Config.PasswordRef
		}
		m.CreatedAt = old.CreatedAt
	}
	if in.ClearPassword && in.Password == "" {
		ref = ""
	}
	if ref != "" {
		if !vaultNameRe.MatchString(ref) {
			return nil, errors.New("密码配置项名称只能包含字母、数字和下划线")
		}
		if _, ok := a.vault.Lookup(ref); !ok && in.Password == "" {
			return nil, errors.New("配置管理里没有名为 " + ref + " 的配置项")
		}
	}
	m.Config.PasswordRef = ref
	return &m, nil
}

func (a *App) registerMW(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/middleware", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{
			"items": a.mwViews(), "perm_defs": mwPermDefs, "perm_defs_sql_console": mwSQLConsolePerms,
			"type_labels": mwTypeLabel, "mq_kinds": mqKindLabel,
		})
	})
	save := func(w http.ResponseWriter, r *http.Request, id int64) {
		var in mwInput
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		m, err := a.prepareMW(&in, id)
		if err != nil {
			writeErr(w, 400, err)
			return
		}
		if err := m.normalize(); err != nil {
			writeErr(w, 400, err)
			return
		}
		createdRef := ""
		if in.Password != "" {
			if m.Config.PasswordRef == "" {
				m.Config.PasswordRef = newMWSecretName()
				createdRef = m.Config.PasswordRef
			}
			if err := a.vault.Upsert(m.Config.PasswordRef, "secret", in.Password, "", "中间件「"+m.Name+"」的密码"); err != nil {
				writeErr(w, 400, err)
				return
			}
		}
		if err := a.store.SaveMiddleware(m); err != nil {
			if createdRef != "" {
				a.vault.Delete(a.vaultIDByName(createdRef))
			}
			writeErr(w, 400, err)
			return
		}
		a.mwPoolDrop(m.ID)
		a.broadcastToolsChanged()
		for _, v := range a.mwViews() {
			if v.ID == m.ID {
				writeJSON(w, 200, v)
				return
			}
		}
		writeJSON(w, 200, map[string]any{"id": m.ID})
	}
	mux.HandleFunc("POST /api/middleware", func(w http.ResponseWriter, r *http.Request) { save(w, r, 0) })
	mux.HandleFunc("PUT /api/middleware/{id}", func(w http.ResponseWriter, r *http.Request) { save(w, r, pathID(r)) })
	mux.HandleFunc("DELETE /api/middleware/{id}", func(w http.ResponseWriter, r *http.Request) {
		id := pathID(r)
		m, err := a.store.GetMiddleware(id)
		if err != nil {
			writeErr(w, 404, errors.New("中间件不存在"))
			return
		}
		a.mwPoolDrop(id)
		if err := a.store.DeleteMiddleware(id); err != nil {
			writeErr(w, 400, err)
			return
		}
		// remove the auto-created password item when nothing else uses it
		if ref := m.Config.PasswordRef; autoMWSecret.MatchString(ref) && len(a.vaultUsage()[ref]) == 0 {
			a.vault.Delete(a.vaultIDByName(ref))
		}
		a.broadcastToolsChanged()
		writeJSON(w, 200, map[string]any{"ok": true})
	})
	mux.HandleFunc("POST /api/middleware/test", func(w http.ResponseWriter, r *http.Request) {
		var in mwInput
		if err := readJSON(r, &in); err != nil {
			writeErr(w, 400, err)
			return
		}
		m := in.Middleware
		if m.ID != 0 {
			old, err := a.store.GetMiddleware(m.ID)
			if err != nil {
				writeErr(w, 404, errors.New("中间件不存在"))
				return
			}
			if m.Type == "" { // test the saved config
				m = *old
			} else if strings.TrimSpace(m.Config.PasswordRef) == "" && !in.ClearPassword {
				m.Config.PasswordRef = old.Config.PasswordRef
			}
		}
		if m.Name == "" {
			m.Name = "未命名"
		}
		if err := m.normalize(); err != nil {
			writeJSON(w, 200, map[string]any{"ok": false, "error": err.Error()})
			return
		}
		if in.Password != "" {
			pw := in.Password
			m.pwOverride = &pw
		} else if in.ClearPassword {
			empty := ""
			m.pwOverride = &empty
		}
		pw, _ := a.mwPassword(&m)
		m.ID = -atomic.AddInt64(&mwTestSeq, 1) // separate client cache, dropped right after
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		start := time.Now()
		msg, err := a.TestMiddleware(ctx, &m)
		a.mwPoolDrop(m.ID)
		if err != nil {
			writeJSON(w, 200, map[string]any{"ok": false, "error": a.scrubErr(err, pw), "ms": time.Since(start).Milliseconds()})
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true, "msg": msg, "ms": time.Since(start).Milliseconds()})
	})
	mux.HandleFunc("GET /api/middleware/audit", func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		writeJSON(w, 200, a.store.ListAudit(r.URL.Query().Get("mw"), limit))
	})
	mux.HandleFunc("DELETE /api/middleware/audit", func(w http.ResponseWriter, r *http.Request) {
		a.store.db.Exec(`DELETE FROM mw_audit`)
		writeJSON(w, 200, map[string]any{"ok": true})
	})
}
