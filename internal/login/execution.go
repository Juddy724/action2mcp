package login

import (
	"action2mcp/internal/credential"
	"action2mcp/internal/execution"
	sitecfg "action2mcp/internal/site"
	"errors"
)

type executionSession struct {
	app        *Service
	site       *sitecfg.Site
	generation int64
}

func (s executionSession) Origin() string { return s.site.Origin }

func (s executionSession) DisplayName() string { return s.site.DisplayName() }

func (s executionSession) NotLoggedIn(status int, body, ctype string, hops []string, raw string) (bool, string) {
	return s.site.NotLoggedIn(status, body, ctype, hops, raw)
}

func (s executionSession) MarkValid() { s.app.markValid(s.site, false) }

func (s executionSession) Relogin() error { return s.app.Relogin(s.site, s.generation, false, true) }

func (s executionSession) Invalid(msg string) error {
	s.app.repo.SetSiteStatus(s.site.ID, "invalid", msg, false)
	return &LoginErr{Msg: msg}
}
func (s *Service) Begin(raw string) (execution.Session, error) {
	site := s.repo.EnsureSite(raw)
	if site == nil {
		return nil, nil
	}
	st := s.state(site.Origin)
	gen := s.siteGen(st)
	if err := s.pendingErr(site, st); err != nil {
		return nil, err
	}
	return executionSession{s, site, gen}, nil
}
func (s *Service) ReloginWS(raw string) (bool, error) {
	site := s.repo.EnsureSite(credential.Origin(raw))
	if site == nil {
		return false, errors.New("找不到站点登录配置")
	}
	st := s.state(site.Origin)
	return true, s.Relogin(site, s.siteGen(st), false, true)
}
