package app

import (
	"action2mcp/internal/execution"
	"action2mcp/internal/login"
	"action2mcp/internal/mwtools"
	"net/http"
)

func (a *App) loginRuntime() *login.Service {
	a.loginOnce.Do(func() {
		a.loginService = login.New(login.Options{
			Repository: a.store, HeaderDB: a.store.DB(), Vault: a.vault,
			Browsers: a.browserRuntime(), Quit: a.quit,
			ConsolePort:        func() int { return a.cfg.Port },
			HTTPClient:         func() *http.Client { return a.httpClient },
			MiddlewareBindings: a.loginMiddlewareBindings,
			// Resolve execution only after construction, preserving lazy wiring.
			Probe: func(t *Tool, m, u string, h map[string]string, b string, c []Cookie, src string) (*execution.CallResult, error) {
				return a.executor().Call(t, m, u, h, b, c, src)
			},
		})
	})
	return a.loginService
}
func (a *App) loginMiddlewareBindings() []login.MiddlewareBinding {
	ms, err := a.store.ListMiddleware()
	if err != nil {
		return nil
	}
	var out []login.MiddlewareBinding
	for _, m := range ms {
		if m.Type == "websocket" {
			out = append(out, login.MiddlewareBinding{URL: m.Config.URL, Names: mwtools.HeaderRefs(m)})
		}
	}
	return out
}
