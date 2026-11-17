package execution

import (
	"action2mcp/internal/vault"
	"net/http"
	"time"
)

// Sessions mediates login state without transferring its locks or generations.
// Begin takes the generation snapshot and checks pending login before the first request.
type Sessions interface {
	Begin(rawURL string) (Session, error)
	// ReloginWS reports whether the provider requires post-login header harvesting.
	ReloginWS(rawURL string) (waitHeaders bool, err error)
}
type Session interface {
	Origin() string
	DisplayName() string
	NotLoggedIn(status int, body, contentType string, hops []string, rawURL string) (bool, string)
	MarkValid()
	Relogin() error
	Invalid(message string) error
}

// Console refreshes a generated SQL tool and supplies display-only configuration.
// It cannot access the frozen request, substitutions or credential state.
type Console interface {
	Refresh(*Tool, map[string]any) (*Tool, error)
	Preview(*Tool, map[string]any) (name, alias string, hide []string, ok bool)
}
type Options struct {
	Vault          *vault.Vault
	ConsolePort    int
	HTTPClient     *http.Client
	Cookies        func(string) ([]Cookie, string)
	ProfileCookies func() ([]Cookie, error)
	ReplaceCookies func([]Cookie)
	Header         func(string, string) (string, error)
	Sessions       Sessions
	Console        Console
	Now            func() time.Time
	Debug          func(string, ...any)
}

// Engine owns tool preparation, credential binding, security policy and HTTP/WS
// execution. Browser/login state and persistence remain behind explicit ports.
type Engine struct {
	vault          *vault.Vault
	guard          HTTPGuard
	httpClient     *http.Client
	cookies        func(string) ([]Cookie, string)
	profileCookies func() ([]Cookie, error)
	replaceCookies func([]Cookie)
	header         func(string, string) (string, error)
	sessions       Sessions
	console        Console
	prepareNow     func() time.Time
	debug          func(string, ...any)
}

func New(o Options) *Engine {
	return &Engine{vault: o.Vault, guard: HTTPGuard{ConsolePort: o.ConsolePort}, httpClient: o.HTTPClient, cookies: o.Cookies, profileCookies: o.ProfileCookies, replaceCookies: o.ReplaceCookies, header: o.Header, sessions: o.Sessions, console: o.Console, prepareNow: o.Now, debug: o.Debug}
}

// LoginErr is a login problem explained in Chinese for the AI / user.
type LoginErr struct{ Msg string }

func (e *LoginErr) Error() string { return e.Msg }
