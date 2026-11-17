// Package catalog is the single write path for recorded tools.
package catalog

import (
	"action2mcp/internal/analysis"
	"action2mcp/internal/execution"
	"action2mcp/internal/mcp"
	"action2mcp/internal/site"
	"errors"
	"strings"
)

type Repository interface {
	SaveTool(t *execution.Tool) error
	EnsureSite(rawURL string) *site.Site
}

type Secrets interface {
	ToRefs(s string) string
	Lookup(name string) (string, bool)
}

type Options struct {
	Repository       Repository
	Secrets          Secrets
	MarkSecretParams func(t *execution.Tool)
	ToolsChanged     func()
}

// toolCatalog is the single write path for recorded tools: vault references,
// normalization, reserved names, secret flags, the site row and list_changed.
type Service struct {
	repo             Repository
	secrets          Secrets
	markSecretParams func(t *execution.Tool)
	toolsChanged     func()
}

func New(o Options) *Service {
	return &Service{repo: o.Repository, secrets: o.Secrets, markSecretParams: o.MarkSecretParams, toolsChanged: o.ToolsChanged}
}

// persistTool stores a tool the same way POST/PUT /api/tools does: vault refs,
// normalization, reserved names, and a site row. It broadcasts tools/list_changed.
func (a *Service) Persist(t *execution.Tool) error {
	// values that live in 配置管理 are stored as {{secret.X}} / {{cfg.X}}, never as plain text
	t.URL = a.secrets.ToRefs(t.URL)
	t.Body = a.secrets.ToRefs(t.Body)
	for k, v := range t.Headers {
		t.Headers[k] = a.secrets.ToRefs(v)
	}
	for i, m := range t.Config.Messages {
		t.Config.Messages[i] = a.secrets.ToRefs(m)
	}
	if err := a.Validate(t); err != nil {
		return err
	}
	a.markSecretParams(t)
	t.AllowDisableGuard = true
	if err := a.repo.SaveTool(t); err != nil {
		return err
	}
	a.repo.EnsureSite(t.URL)
	a.toolsChanged()
	return nil
}

func (a *Service) Validate(t *execution.Tool) error {
	if err := t.Normalize(); err != nil {
		return err
	}
	if mcp.IsEntryTool(t.Name) {
		return errors.New("工具名 " + t.Name + " 是阶梯模式的入口工具名，已被保留，请换一个名字")
	}
	if analysis.IsTool(t.Name) {
		return errors.New("工具名 " + t.Name + " 是内置录制分析工具名，已被保留，请换一个名字")
	}
	for _, ref := range t.RenderRefs() {
		_, n, _ := strings.Cut(ref, ".")
		if _, ok := a.secrets.Lookup(n); !ok {
			return errors.New("模板引用了不存在的配置项 " + n + "，请先在「配置管理」中添加")
		}
	}
	return nil
}
