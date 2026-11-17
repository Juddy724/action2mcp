package site

import (
	"action2mcp/internal/credential"
	"regexp"
)

// ---------- browser based login (WeCom SSO / form fill) ----------

type PageInfo struct {
	Href  string `json:"h"`
	Ready string `json:"r"`
	Pass  bool   `json:"p"`
	Text  string `json:"t"`
}

func (s *Site) LoggedInPage(pi PageInfo) bool {
	if s.SuccessURL != "" {
		if re, err := regexp.Compile(s.SuccessURL); err == nil && re.MatchString(pi.Href) && pi.Ready == "complete" {
			return true
		}
		return false
	}
	h := HostOf(pi.Href)
	if h == "" || !credential.SameSite("http://"+h, s.Origin) {
		return false
	}
	if s.IsLoginURL(pi.Href) || pi.Pass || pi.Ready != "complete" {
		return false
	}
	if !s.Detect.NoDefaults && len(pi.Text) < 300 && shortNotLoginRe.MatchString(pi.Text) {
		return false
	}
	return true
}
