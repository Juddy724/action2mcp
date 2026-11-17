package app

import (
	"action2mcp/internal/execution"
	"action2mcp/internal/mcp"
	"strings"
)

type Tool = execution.Tool
type Cookie = execution.Cookie

func (a *App) executor() *execution.Engine {
	return execution.New(execution.Options{Vault: a.vault, ConsolePort: a.cfg.Port, HTTPClient: a.httpClient, Cookies: a.CookiesFor, ProfileCookies: a.browserRuntime().ReadProfileCookies, ReplaceCookies: a.store.ReplaceCookies, Header: a.loginRuntime().GetSiteHeader, Sessions: executionSessions{a}, Console: executionConsole{a}, Now: a.prepareNow, Debug: debugf})
}

type executionSessions struct{ app *App }

func (s executionSessions) Begin(raw string) (execution.Session, error) {
	return s.app.loginRuntime().Begin(raw)
}
func (s executionSessions) ReloginWS(raw string) (bool, error) {
	if s.app.wsReloginHook != nil {
		return false, s.app.wsReloginHook()
	}
	return s.app.loginRuntime().ReloginWS(raw)
}

type executionConsole struct{ app *App }

func (c executionConsole) Refresh(t *Tool, args map[string]any) (*Tool, error) {
	t, _, _, err := c.app.middlewares().RefreshSQLConsoleTool(t, args)
	return t, err
}
func (c executionConsole) Preview(t *Tool, args map[string]any) (string, string, []string, bool) {
	b := t.ConsoleBinding()
	mw, err := c.app.store.GetMiddleware(b.ID)
	if err != nil {
		return "", "", nil, false
	}
	alias := b.Alias
	if arg := mcp.ArgString(args, "database"); strings.TrimSpace(arg) != "" {
		alias = arg
	}
	ds, _ := mw.LookupDatasource(alias)
	return mw.Name, alias, ds.ConfigHideValues(&mw.Config), true
}
