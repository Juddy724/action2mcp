package app

import (
	"action2mcp/internal/browser"

	"action2mcp/internal/site"
	"path/filepath"
)

type StopInfo = browser.StopInfo

func (a *App) browserRuntime() *browser.Manager {
	a.browserOnce.Do(func() {
		a.browserManager = browser.New(browser.Options{
			ProfileDir: filepath.Join(a.dataDir, "browser-profile"),
			Config: func() browser.LaunchConfig {
				return browser.LaunchConfig{BrowserPath: a.cfg.Browser, BrowserArgs: a.cfg.BrowserArgs, NoSandbox: a.cfg.NoSandbox}
			},
			Quit: a.quit, Repository: a.store, Capture: a.store,
			Classify: a.store.ClassifyRecorded,
			// Defer login resolution: login construction also leases this manager.
			// Resolving method values here would re-enter browserOnce and deadlock.
			TrackHarvestHop: func(k, u string) { a.loginRuntime().TrackHarvestHop(k, u) },
			HarvestRequestHeader: func(k, u, n, v string) error {
				return a.loginRuntime().HarvestRequestHeader(k, u, n, v)
			},
			DetectRecordingLogin: site.NewRecordingDetector(a.store).Detect,
		})
	})
	return a.browserManager
}
func (a *App) CookiesFor(rawURL string) ([]Cookie, string) {
	return a.browserRuntime().CookiesFor(rawURL)
}
