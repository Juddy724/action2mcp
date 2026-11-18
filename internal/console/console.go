// Package console serves the local web console API over injected services.
package console

import (
	"action2mcp/internal/analysis"
	"action2mcp/internal/browser"
	"action2mcp/internal/catalog"
	"action2mcp/internal/execution"
	"action2mcp/internal/invoke"
	"action2mcp/internal/login"
	"action2mcp/internal/mcp"
	"action2mcp/internal/mcpserver"
	"action2mcp/internal/mwtools"
	"action2mcp/internal/site"
	"action2mcp/internal/store"
	"action2mcp/internal/transfer"
	"action2mcp/internal/updater"
	"action2mcp/internal/vault"
)

// consoleBrowser is the recording/browser surface the console drives.
type Browser interface {
	StartRecording(name string, startURL string) (int64, error)
	StopRecording(reason string) (*browser.StopInfo, error)
	OpenBrowser(u string) error
}

// consoleLogin is the login-center surface the console drives.
type Login interface {
	CancelLogin(site *site.Site) error
	CheckSite(site *site.Site) (bool, string)
	ClearAllSiteHeaders() error
	ClearSiteHeaders(rawURL string) error
	Generation(origin string) int64
	OpenLoginWindow(site *site.Site) error
	Relogin(site *site.Site, seenGen int64, force bool, interactive bool) error
	ResetSiteFailures()
	SmartOpenLogin(site *site.Site, force bool) (*login.OpenLoginResult, error)
	Snapshot(origin string) login.Snapshot
}

// consoleOptions wires the local web console. Store and Vault are the
// console's own administration subjects; every runtime collaborator is a
// lazily resolved service or callback, never the App.
type Options struct {
	Port         int
	Store        *store.Store
	Vault        *vault.Vault
	Sessions     *mcp.Manager
	Quit         <-chan struct{}
	Status       func() any
	Shutdown     func()
	Exit         func()
	Browser      func() Browser
	Login        func() Login
	Engine       func() *execution.Engine
	Analysis     func() *analysis.Service
	Middlewares  func() *mwtools.Service
	Approvals    func() *invoke.Gateway
	Transfer     func() *transfer.Service
	Tools        func() *catalog.Service
	MCPServer    func() *mcpserver.Server
	Updater      func() *updater.Service
	Restart      func(exePath string) error
	ToolsChanged func()
	DropDriver   func(middlewareID int64)
}

type Server struct {
	port         int
	store        *store.Store
	vault        *vault.Vault
	sessions     *mcp.Manager
	quit         <-chan struct{}
	status       func() any
	shutdown     func()
	exit         func()
	browser      func() Browser
	login        func() Login
	engine       func() *execution.Engine
	analysis     func() *analysis.Service
	middlewares  func() *mwtools.Service
	approvals    func() *invoke.Gateway
	transfer     func() *transfer.Service
	tools        func() *catalog.Service
	mcpServer    func() *mcpserver.Server
	updater      func() *updater.Service
	restart      func(exePath string) error
	toolsChanged func()
	dropDriver   func(middlewareID int64)
}

func New(o Options) *Server {
	return &Server{port: o.Port, store: o.Store, vault: o.Vault, sessions: o.Sessions, quit: o.Quit,
		status: o.Status, shutdown: o.Shutdown, exit: o.Exit, browser: o.Browser, login: o.Login, engine: o.Engine,
		analysis: o.Analysis, middlewares: o.Middlewares, approvals: o.Approvals, transfer: o.Transfer, tools: o.Tools,
		mcpServer: o.MCPServer, updater: o.Updater, restart: o.Restart, toolsChanged: o.ToolsChanged, dropDriver: o.DropDriver}
}
