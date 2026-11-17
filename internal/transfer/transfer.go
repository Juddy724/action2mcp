// Package transfer exports and imports tools, packs, middleware and sites as a portable, secret-free JSON document.
package transfer

import (
	"action2mcp/internal/credential"
	"action2mcp/internal/domain"
	"action2mcp/internal/execution"
	"action2mcp/internal/mwconfig"

	sitecfg "action2mcp/internal/site"
	"action2mcp/internal/store"
	"action2mcp/internal/vault"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// transferRepository is the catalog surface used by export/import.
type Repository interface {
	ListSites() []*sitecfg.Site
	ImportTool(t *execution.Tool) (bool, error)
	EnsureSite(rawURL string) *sitecfg.Site
	SiteByOrigin(origin string) *sitecfg.Site
	SaveSite(s *sitecfg.Site) error
	GetMiddlewareByName(name string) (*mwconfig.Middleware, error)
	SaveMiddleware(m *mwconfig.Middleware) error
	ListPacks() ([]*store.Pack, error)
	GetToolByName(name string) (*execution.Tool, error)
	SavePack(p *store.Pack) error
	ListTools() ([]*execution.Tool, error)
	ListMiddleware() ([]*mwconfig.Middleware, error)
}

// transferSecrets turns values into vault references and only creates empty
// placeholders on import; secret values never leave or enter through a file.
type Secrets interface {
	Scrub(s string) string
	ToRefs(s string) string
	List() []vault.VaultItem
	EnsureName(name string, typ string, site string, note string) bool
}

type Options struct {
	Repository       Repository
	Secrets          Secrets
	MarkSecretParams func(t *execution.Tool)
	DropDriver       func(middlewareID int64)
}

// transferService exports and imports tools, packs, middleware and sites as a
// portable, secret-free JSON document.
type Service struct {
	repo             Repository
	secrets          Secrets
	markSecretParams func(t *execution.Tool)
	dropDriver       func(middlewareID int64)
}

func New(o Options) *Service {
	return &Service{repo: o.Repository, secrets: o.Secrets, markSecretParams: o.MarkSecretParams, dropDriver: o.DropDriver}
}

type exportTool struct {
	Approval    string               `json:"approval"`
	Name        string               `json:"name"`
	Title       string               `json:"title"`
	Description string               `json:"description"`
	Method      string               `json:"method"`
	URL         string               `json:"url"`
	Headers     map[string]string    `json:"headers"`
	Body        string               `json:"body"`
	Params      []domain.Param       `json:"params"`
	CredHeaders []string             `json:"cred_headers"`
	Config      execution.ToolConfig `json:"config,omitempty"`
}

type exportPack struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Enabled     bool     `json:"enabled"`
	Scenarios   string   `json:"scenarios,omitempty"`
	Guide       *string  `json:"guide,omitempty"`
	Tools       []string `json:"tools"`
	Middleware  []string `json:"middleware,omitempty"`
}

// exportMW is a 中间件 definition. The password is never exported, only the name of its 配置管理 item.
type exportMW struct {
	Name   string            `json:"name"`
	Type   string            `json:"type"`
	Config mwconfig.MWConfig `json:"config"`
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
	Origin string         `json:"origin"`
	Config sitecfg.Config `json:"config"`
}

// exportVar lists the names of 配置管理 items so they can be filled in after import. Never values.
type exportVar struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Site string `json:"site,omitempty"`
	Note string `json:"note,omitempty"`
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

func (a *Service) Export() ([]byte, error) {
	tools, err := a.repo.ListTools()
	if err != nil {
		return nil, err
	}
	packs, _ := a.repo.ListPacks()
	f := exportFile{Format: "action2mcp", Version: 1, ExportedAt: time.Now().Format(time.RFC3339),
		Note: "只包含工具定义、流程包、登录配置和配置项名称，不包含任何 Cookie / Token / 登录态，也不包含配置项的值（密码等）；中间件只包含连接地址、权限和密码配置项的名称，不包含密码。流程包使用说明会一并导出，请不要在里面写密码或 Cookie；配置管理里已有的密文会在导出时替换成 ******。导入后请在「配置管理」里填写配置值，并用自己的账号登录一次。", Tools: []exportTool{}, Packs: []exportPack{}}
	mws, _ := a.repo.ListMiddleware()
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
			if credential.IsCredHeader(k) && !(execution.IsWSMethod(t.Method) && (strings.Contains(v, "{{header.") || strings.Contains(v, "{{cookie.") || strings.Contains(v, "{{secret.") || strings.Contains(v, "{{cfg."))) {
				continue
			}
			h[k] = v
		}
		for k, v := range h {
			h[k] = a.secrets.Scrub(a.secrets.ToRefs(v))
		}
		cfg := t.Config
		for i, m := range cfg.Messages {
			cfg.Messages[i] = a.secrets.Scrub(a.secrets.ToRefs(m))
		}
		f.Tools = append(f.Tools, exportTool{t.Approval, t.Name, t.Title, t.Description, t.Method, a.secrets.Scrub(a.secrets.ToRefs(t.URL)), h, a.secrets.Scrub(a.secrets.ToRefs(t.Body)), t.Params, t.CredHeaders, cfg})
	}
	for _, p := range packs {
		guide := a.secrets.Scrub(strings.TrimSpace(p.Guide))
		ep := exportPack{Name: p.Name, Description: p.Description, Enabled: p.Enabled, Scenarios: p.Scenarios, Guide: &guide, Tools: []string{}}
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
	for _, st := range a.repo.ListSites() {
		c := st.SnapshotConfig()
		if c.Form.Request != nil {
			r := *c.Form.Request
			r.Body = a.secrets.Scrub(a.secrets.ToRefs(r.Body))
			r.URL = a.secrets.Scrub(r.URL)
			hh := map[string]string{}
			for k, v := range r.Headers {
				if !credential.IsCredHeader(k) {
					hh[k] = a.secrets.Scrub(v)
				}
			}
			r.Headers = hh
			c.Form.Request = &r
		}
		f.Sites = append(f.Sites, exportSite{st.Origin, c})
	}
	for _, it := range a.secrets.List() {
		f.Vault = append(f.Vault, exportVar{it.Name, it.Type, it.Site, it.Note})
	}
	return json.MarshalIndent(f, "", "  ")
}

func (a *Service) Import(b []byte) (*ImportResult, error) {
	var f exportFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, errors.New("文件不是有效的 .a2m 文件")
	}
	if f.Format != "action2mcp" {
		return nil, errors.New("文件不是 Action2MCP 导出的 .a2m 文件")
	}
	res := &ImportResult{VaultToFill: []string{}}
	preVault := map[string]bool{}
	for _, it := range a.secrets.List() {
		preVault[it.Name] = true
	}
	mwRefs := map[string]bool{}
	for _, em := range f.Middleware {
		mwRefs[em.Config.PasswordRef] = true
	}
	for _, ev := range f.Vault {
		if !credential.ValidName(ev.Name) || mwRefs[ev.Name] {
			continue
		}
		note := ev.Note
		if note == "" {
			note = "导入的配置项"
		}
		if a.secrets.EnsureName(ev.Name, ev.Type, ev.Site, strings.TrimSuffix(note, "（录制时保存）")+"（待填写）") {
			res.VaultToFill = append(res.VaultToFill, ev.Name)
		}
	}
	ids := map[string]int64{}
	for _, et := range f.Tools {
		t := &execution.Tool{Approval: et.Approval, Name: et.Name, Title: et.Title, Description: et.Description, Method: et.Method, URL: et.URL, Headers: et.Headers, Body: et.Body, Params: et.Params, CredHeaders: et.CredHeaders, Config: et.Config}
		if err := t.Normalize(); err != nil {
			return res, errors.New(et.Name + ": " + err.Error())
		}
		for _, ref := range t.RenderRefs() {
			_, n, _ := strings.Cut(ref, ".")
			typ := "plain"
			if strings.HasPrefix(ref, "secret.") {
				typ = "secret"
			}
			if a.secrets.EnsureName(n, typ, credential.Origin(t.URL), "导入的工具引用（待填写）") {
				res.VaultToFill = append(res.VaultToFill, n)
			}
		}
		a.markSecretParams(t)
		updated, err := a.repo.ImportTool(t)
		if err != nil {
			return res, err
		}
		if updated {
			res.ToolsUpdated++
		} else {
			res.ToolsAdded++
		}
		a.repo.EnsureSite(t.URL)
		ids[t.Name] = t.ID
	}
	for _, es := range f.Sites {
		s := a.repo.SiteByOrigin(es.Origin)
		if s != nil {
			res.SitesUpdated++
		} else {
			s = &sitecfg.Site{Origin: es.Origin}
			res.SitesAdded++
		}
		s.ApplyConfig(es.Config)
		if err := a.repo.SaveSite(s); err != nil {
			return res, errors.New(es.Origin + ": " + err.Error())
		}
	}
	mwIDs := map[string]int64{}
	for _, em := range f.Middleware {
		m := &mwconfig.Middleware{Name: em.Name, Type: em.Type, Config: em.Config}
		old, err := a.repo.GetMiddlewareByName(em.Name)
		if err == nil {
			m.ID = old.ID
			m.Config.PasswordRef = old.Config.PasswordRef // keep the local password
			res.MWUpdated++
		} else {
			ref := em.Config.PasswordRef
			if ref != "" {
				if !credential.ValidName(ref) || preVault[ref] {
					ref = mwconfig.NewSecretName() // the name is taken by something else here
				}
				m.Config.PasswordRef = ref
				if a.secrets.EnsureName(ref, "secret", "", "中间件「"+em.Name+"」的密码（待填写）") {
					res.VaultToFill = append(res.VaultToFill, ref)
				}
			}
			res.MWAdded++
		}
		if err := a.repo.SaveMiddleware(m); err != nil {
			return res, errors.New("中间件 " + em.Name + ": " + err.Error())
		}
		a.dropDriver(m.ID)
		mwIDs[m.Name] = m.ID
	}
	packs, _ := a.repo.ListPacks()
	byName := map[string]*store.Pack{}
	for _, p := range packs {
		byName[p.Name] = p
	}
	for _, ep := range f.Packs {
		p := &store.Pack{Name: ep.Name, Description: ep.Description, Enabled: ep.Enabled, Scenarios: ep.Scenarios, ToolIDs: []int64{}}
		if old := byName[ep.Name]; old != nil {
			p.ID = old.ID
			if p.Scenarios == "" {
				p.Scenarios = old.Scenarios
			}
			if ep.Guide == nil {
				p.Guide = old.Guide
			} else {
				p.Guide = *ep.Guide
			}
			res.PacksUpdated++
		} else {
			if ep.Guide != nil {
				p.Guide = *ep.Guide
			}
			res.PacksAdded++
		}
		for _, n := range ep.Tools {
			if id, ok := ids[n]; ok {
				p.ToolIDs = append(p.ToolIDs, id)
			} else if t, err := a.repo.GetToolByName(n); err == nil {
				p.ToolIDs = append(p.ToolIDs, t.ID)
			}
		}
		if ep.Middleware != nil {
			p.MiddlewareIDs = []int64{}
			for _, n := range ep.Middleware {
				if id, ok := mwIDs[n]; ok {
					p.MiddlewareIDs = append(p.MiddlewareIDs, id)
				} else if m, err := a.repo.GetMiddlewareByName(n); err == nil {
					p.MiddlewareIDs = append(p.MiddlewareIDs, m.ID)
				}
			}
		}
		if err := a.repo.SavePack(p); err != nil {
			return res, err
		}
	}
	return res, nil
}
