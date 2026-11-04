package main

import (
	"encoding/json"
	"errors"
	"strings"
	"time"
)

type exportTool struct {
	Name        string            `json:"name"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	Method      string            `json:"method"`
	URL         string            `json:"url"`
	Headers     map[string]string `json:"headers"`
	Body        string            `json:"body"`
	Params      []Param           `json:"params"`
	CredHeaders []string          `json:"cred_headers"`
}

type exportPack struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
	Scenarios   string   `json:"scenarios,omitempty"`
	Tools       []string `json:"tools"`
	Middleware  []string `json:"middleware,omitempty"`
}

// exportMW is a 中间件 definition. The password is never exported, only the name of its 配置管理 item.
type exportMW struct {
	Name   string   `json:"name"`
	Type   string   `json:"type"`
	Config MWConfig `json:"config"`
}

type exportFile struct {
	Format     string       `json:"format"`
	Version    int          `json:"version"`
	ExportedAt string       `json:"exported_at"`
	Note       string       `json:"note"`
	Tools      []exportTool `json:"tools"`
	Packs      []exportPack `json:"packs"`
	Sites      []exportSite `json:"sites,omitempty"`
	Vault      []exportVar  `json:"vault,omitempty"`
	Middleware []exportMW   `json:"middleware,omitempty"`
}

// exportSite is a 登录配置 (no cookies, no passwords – only {{secret.X}} references).
type exportSite struct {
	Origin string     `json:"origin"`
	Config siteConfig `json:"config"`
}

// exportVar lists the names of 配置管理 items so they can be filled in after import. Never values.
type exportVar struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Site string `json:"site,omitempty"`
	Note string `json:"note,omitempty"`
}

func (a *App) Export() ([]byte, error) {
	tools, err := a.store.ListTools()
	if err != nil {
		return nil, err
	}
	packs, _ := a.store.ListPacks()
	f := exportFile{Format: "action2mcp", Version: 1, ExportedAt: time.Now().Format(time.RFC3339),
		Note: "只包含工具定义、流程包、登录配置和配置项名称，不包含任何 Cookie / Token / 登录态，也不包含配置项的值（密码等）；中间件只包含连接地址、权限和密码配置项的名称，不包含密码。导入后请在「配置管理」里填写配置值，并用自己的账号登录一次。", Tools: []exportTool{}, Packs: []exportPack{}}
	mws, _ := a.store.ListMiddleware()
	mwNames := map[int64]string{}
	for _, m := range mws {
		mwNames[m.ID] = m.Name
		f.Middleware = append(f.Middleware, exportMW{m.Name, m.Type, m.Config})
	}
	names := map[int64]string{}
	for _, t := range tools {
		names[t.ID] = t.Name
		h := map[string]string{}
		for k, v := range t.Headers {
			if !IsCredHeader(k) {
				h[k] = v
			}
		}
		for k, v := range h {
			h[k] = a.vault.Scrub(a.vault.ToRefs(v))
		}
		f.Tools = append(f.Tools, exportTool{t.Name, t.Title, t.Description, t.Method, a.vault.Scrub(a.vault.ToRefs(t.URL)), h, a.vault.Scrub(a.vault.ToRefs(t.Body)), t.Params, t.CredHeaders})
	}
	for _, p := range packs {
		ep := exportPack{Name: p.Name, Description: p.Description, Enabled: p.Enabled, Scenarios: p.Scenarios, Tools: []string{}}
		for _, id := range p.ToolIDs {
			if n, ok := names[id]; ok {
				ep.Tools = append(ep.Tools, n)
			}
		}
		ep.Middleware = []string{}
		for _, id := range p.MiddlewareIDs {
			if n, ok := mwNames[id]; ok {
				ep.Middleware = append(ep.Middleware, n)
			}
		}
		f.Packs = append(f.Packs, ep)
	}
	for _, st := range a.store.ListSites() {
		c := st.config()
		if c.Form.Request != nil {
			r := *c.Form.Request
			r.Body = a.vault.Scrub(a.vault.ToRefs(r.Body))
			r.URL = a.vault.Scrub(r.URL)
			hh := map[string]string{}
			for k, v := range r.Headers {
				if !IsCredHeader(k) {
					hh[k] = a.vault.Scrub(v)
				}
			}
			r.Headers = hh
			c.Form.Request = &r
		}
		f.Sites = append(f.Sites, exportSite{st.Origin, c})
	}
	for _, it := range a.vault.List() {
		f.Vault = append(f.Vault, exportVar{it.Name, it.Type, it.Site, it.Note})
	}
	return json.MarshalIndent(f, "", "  ")
}

type ImportResult struct {
	ToolsAdded   int      `json:"tools_added"`
	ToolsUpdated int      `json:"tools_updated"`
	PacksAdded   int      `json:"packs_added"`
	PacksUpdated int      `json:"packs_updated"`
	SitesAdded   int      `json:"sites_added"`
	SitesUpdated int      `json:"sites_updated"`
	MWAdded      int      `json:"middleware_added"`
	MWUpdated    int      `json:"middleware_updated"`
	VaultToFill  []string `json:"vault_to_fill"`
}

func (a *App) Import(b []byte) (*ImportResult, error) {
	var f exportFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, errors.New("文件不是有效的 .a2m 文件")
	}
	if f.Format != "action2mcp" {
		return nil, errors.New("文件不是 Action2MCP 导出的 .a2m 文件")
	}
	res := &ImportResult{VaultToFill: []string{}}
	preVault := map[string]bool{}
	for _, it := range a.vault.List() {
		preVault[it.Name] = true
	}
	mwRefs := map[string]bool{}
	for _, em := range f.Middleware {
		mwRefs[em.Config.PasswordRef] = true
	}
	for _, ev := range f.Vault {
		if !vaultNameRe.MatchString(ev.Name) || mwRefs[ev.Name] {
			continue
		}
		note := ev.Note
		if note == "" {
			note = "导入的配置项"
		}
		if a.vault.EnsureName(ev.Name, ev.Type, ev.Site, strings.TrimSuffix(note, "（录制时保存）")+"（待填写）") {
			res.VaultToFill = append(res.VaultToFill, ev.Name)
		}
	}
	ids := map[string]int64{}
	for _, et := range f.Tools {
		t := &Tool{Name: et.Name, Title: et.Title, Description: et.Description, Method: et.Method, URL: et.URL, Headers: et.Headers, Body: et.Body, Params: et.Params, CredHeaders: et.CredHeaders}
		if err := t.Normalize(); err != nil {
			return res, errors.New(et.Name + ": " + err.Error())
		}
		if old, err := a.store.GetToolByName(t.Name); err == nil {
			t.ID = old.ID
			res.ToolsUpdated++
		} else {
			res.ToolsAdded++
		}
		for _, ref := range t.RenderRefs() {
			_, n, _ := strings.Cut(ref, ".")
			typ := "plain"
			if strings.HasPrefix(ref, "secret.") {
				typ = "secret"
			}
			if a.vault.EnsureName(n, typ, originOf(t.URL), "导入的工具引用（待填写）") {
				res.VaultToFill = append(res.VaultToFill, n)
			}
		}
		if err := a.store.SaveTool(t); err != nil {
			return res, err
		}
		a.store.EnsureSite(t.URL)
		ids[t.Name] = t.ID
	}
	for _, es := range f.Sites {
		s := a.store.SiteByOrigin(es.Origin)
		if s != nil {
			res.SitesUpdated++
		} else {
			s = &Site{Origin: es.Origin}
			res.SitesAdded++
		}
		s.applyConfig(es.Config)
		if err := a.store.SaveSite(s); err != nil {
			return res, errors.New(es.Origin + ": " + err.Error())
		}
	}
	mwIDs := map[string]int64{}
	for _, em := range f.Middleware {
		m := &Middleware{Name: em.Name, Type: em.Type, Config: em.Config}
		old, err := a.store.GetMiddlewareByName(em.Name)
		if err == nil {
			m.ID = old.ID
			m.Config.PasswordRef = old.Config.PasswordRef // keep the local password
			res.MWUpdated++
		} else {
			ref := em.Config.PasswordRef
			if ref != "" {
				if !vaultNameRe.MatchString(ref) || preVault[ref] {
					ref = newMWSecretName() // the name is taken by something else here
				}
				m.Config.PasswordRef = ref
				if a.vault.EnsureName(ref, "secret", "", "中间件「"+em.Name+"」的密码（待填写）") {
					res.VaultToFill = append(res.VaultToFill, ref)
				}
			}
			res.MWAdded++
		}
		if err := a.store.SaveMiddleware(m); err != nil {
			return res, errors.New("中间件 " + em.Name + ": " + err.Error())
		}
		a.mwPoolDrop(m.ID)
		mwIDs[m.Name] = m.ID
	}
	packs, _ := a.store.ListPacks()
	byName := map[string]*Pack{}
	for _, p := range packs {
		byName[p.Name] = p
	}
	for _, ep := range f.Packs {
		p := &Pack{Name: ep.Name, Description: ep.Description, Enabled: ep.Enabled, Scenarios: ep.Scenarios, ToolIDs: []int64{}}
		if old := byName[ep.Name]; old != nil {
			p.ID = old.ID
			if p.Scenarios == "" {
				p.Scenarios = old.Scenarios
			}
			res.PacksUpdated++
		} else {
			res.PacksAdded++
		}
		for _, n := range ep.Tools {
			if id, ok := ids[n]; ok {
				p.ToolIDs = append(p.ToolIDs, id)
			} else if t, err := a.store.GetToolByName(n); err == nil {
				p.ToolIDs = append(p.ToolIDs, t.ID)
			}
		}
		if ep.Middleware != nil {
			p.MiddlewareIDs = []int64{}
			for _, n := range ep.Middleware {
				if id, ok := mwIDs[n]; ok {
					p.MiddlewareIDs = append(p.MiddlewareIDs, id)
				} else if m, err := a.store.GetMiddlewareByName(n); err == nil {
					p.MiddlewareIDs = append(p.MiddlewareIDs, m.ID)
				}
			}
		}
		if err := a.store.SavePack(p); err != nil {
			return res, err
		}
	}
	return res, nil
}
