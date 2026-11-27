package updater

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"0.6.2", "0.6.2", 0},
		{"v0.6.3", "0.6.2", 1},
		{"0.6.10", "0.6.2", 1},
		{"0.7.0", "0.6.99", 1},
		{"0.6.1", "0.6.2", -1},
		{"1.0.0", "0.9.9", 1},
	}
	for _, tc := range cases {
		if got := CompareVersions(tc.a, tc.b); got != tc.want {
			t.Fatalf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestCheckNowETagAndApplyUpdateAtomicReplace(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake binary test runs on unix")
	}

	tmpDir := t.TempDir()
	dataDir := filepath.Join(tmpDir, "data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	sentinelFile := filepath.Join(dataDir, "a2m.db")
	if err := os.WriteFile(sentinelFile, []byte("keep-my-data"), 0o644); err != nil {
		t.Fatal(err)
	}

	exePath := filepath.Join(tmpDir, "a2m")
	oldScript := "#!/bin/sh\necho \"Action2MCP 0.6.2\"\n"
	if err := os.WriteFile(exePath, []byte(oldScript), 0o755); err != nil {
		t.Fatal(err)
	}

	// Build a valid release zip containing a subdirectory Action2MCP-0.6.3-macOS-AppleSilicon/a2m
	newScript := "#!/bin/sh\necho \"Action2MCP 0.6.3\"\n"
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	zf, err := zw.Create("Action2MCP-0.6.3-macOS-AppleSilicon/a2m")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zf.Write([]byte(newScript)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zipBytes := zipBuf.Bytes()
	sum := sha256.Sum256(zipBytes)
	sumHex := hex.EncodeToString(sum[:])

	var apiHits, etag304Hits atomic.Int32
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/releases/latest":
			apiHits.Add(1)
			if r.Header.Get("If-None-Match") == `"etag-v063"` {
				etag304Hits.Add(1)
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"etag-v063"`)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v0.6.3",
				"name":     "Action2MCP v0.6.3",
				"body":     "1. 新增版本自动检测与一键原地升级",
				"html_url": srv.URL + "/tag/v0.6.3",
				"assets": []map[string]any{
					{
						"name":                 "Action2MCP-0.6.3-macOS-AppleSilicon.zip",
						"browser_download_url": srv.URL + "/download/Action2MCP-0.6.3-macOS-AppleSilicon.zip",
						"digest":               "sha256:" + sumHex,
					},
				},
			})
		case "/download/Action2MCP-0.6.3-macOS-AppleSilicon.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	u := New(Options{
		CurrentVersion: "0.6.2",
		APIURL:         srv.URL + "/releases/latest",
		HTTPClient:     srv.Client(),
		ExecutablePath: func() (string, error) { return exePath, nil },
		GOOS:           "darwin",
		GOARCH:         "arm64",
	})

	info, err := u.CheckNow()
	if err != nil {
		t.Fatalf("CheckNow: %v", err)
	}
	if !info.Available || info.LatestVersion != "0.6.3" {
		t.Fatalf("unexpected UpdateInfo: %+v", info)
	}

	// Second check must send If-None-Match and receive 304 Not Modified while keeping Available=true
	info2, err := u.CheckNow()
	if err != nil {
		t.Fatalf("CheckNow 2: %v", err)
	}
	if !info2.Available || etag304Hits.Load() != 1 {
		t.Fatalf("expected 304 hit, got hits=%d info=%+v", etag304Hits.Load(), info2)
	}

	// ApplyUpdate must download, verify SHA-256, run `a2m version`, replace exePath in-place,
	// leave no extra files, and keep data/ untouched!
	applied, gotExe, err := u.ApplyUpdate()
	if err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}
	if applied.LatestVersion != "0.6.3" || gotExe == "" {
		t.Fatalf("unexpected apply result: %+v exe=%q", applied, gotExe)
	}

	gotBytes, err := os.ReadFile(exePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotBytes) != newScript {
		t.Fatalf("executable was not replaced: got %q", string(gotBytes))
	}

	// Ensure data/a2m.db is untouched and no extra files or directories exist in tmpDir
	dataBytes, err := os.ReadFile(sentinelFile)
	if err != nil || string(dataBytes) != "keep-my-data" {
		t.Fatalf("data file was modified or lost: %v %q", err, string(dataBytes))
	}
	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 { // only "a2m" and "data"
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected only [a2m, data] in root dir, got %v", names)
	}
}

func TestCheckNowRateLimitFallbackToRedirect(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/releases/latest":
			w.WriteHeader(http.StatusForbidden) // Simulate GitHub 403 rate limit
			_, _ = w.Write([]byte(`{"message":"API rate limit exceeded"}`))
		case "/web/releases/latest":
			w.Header().Set("Location", srv.URL+"/Juddy724/action2mcp/releases/tag/v0.6.5")
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	u := New(Options{
		CurrentVersion: "0.6.2",
		APIURL:         srv.URL + "/api/releases/latest",
		WebReleaseURL:  srv.URL + "/web/releases/latest",
		HTTPClient:     srv.Client(),
		GOOS:           "darwin",
		GOARCH:         "arm64",
	})

	info, err := u.CheckNow()
	if err != nil {
		t.Fatalf("expected redirect fallback to succeed on 403, got err: %v", err)
	}
	if !info.Available || info.LatestVersion != "0.6.5" || info.AssetName != "Action2MCP-0.6.5-macOS-AppleSilicon.zip" {
		t.Fatalf("unexpected fallback UpdateInfo: %+v", info)
	}
}

func TestDecidePreferredSourceLatencyMatrix(t *testing.T) {
	// Only Gitee reachable -> Gitee
	if got := decidePreferredSource(false, probeResult{ok: true, rtt: 80}, probeResult{ok: false}); got != SourceGitee {
		t.Fatalf("expected gitee when only gitee reachable, got %q", got)
	}
	// Only GitHub reachable -> GitHub
	if got := decidePreferredSource(true, probeResult{ok: false}, probeResult{ok: true, rtt: 120}); got != SourceGitHub {
		t.Fatalf("expected github when only github reachable, got %q", got)
	}
	// Domestic host with both reachable -> Gitee
	if got := decidePreferredSource(true, probeResult{ok: true, rtt: 90 * 1e6}, probeResult{ok: true, rtt: 180 * 1e6}); got != SourceGitee {
		t.Fatalf("expected gitee on domestic host, got %q", got)
	}
	// International host with both reachable -> GitHub
	if got := decidePreferredSource(false, probeResult{ok: true, rtt: 300 * 1e6}, probeResult{ok: true, rtt: 90 * 1e6}); got != SourceGitHub {
		t.Fatalf("expected github on international host, got %q", got)
	}
	// UTC/en_US server physically in China (fast Gitee, slow GitHub) -> Gitee
	if got := decidePreferredSource(false, probeResult{ok: true, rtt: 60 * 1e6}, probeResult{ok: true, rtt: 900 * 1e6}); got != SourceGitee {
		t.Fatalf("expected gitee when gitee is fast and github is slow, got %q", got)
	}
}

func TestDualSourceRoutingAndDownloadFailover(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script fake binary test runs on unix")
	}

	tmpDir := t.TempDir()
	exePath := filepath.Join(tmpDir, "a2m")
	if err := os.WriteFile(exePath, []byte("#!/bin/sh\necho \"Action2MCP 0.7.8\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	newScript := "#!/bin/sh\necho \"Action2MCP 0.7.9\"\n"
	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	zf, err := zw.Create("Action2MCP-0.7.9-macOS-AppleSilicon/a2m")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zf.Write([]byte(newScript)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zipBytes := zipBuf.Bytes()

	var giteeHits, githubHits atomic.Int32
	var giteeDown, giteeReturnHTML atomic.Bool

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gitee/api/releases/latest":
			giteeHits.Add(1)
			if giteeDown.Load() {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v0.7.9",
				"name":     "Action2MCP v0.7.9",
				"body":     "支持国内 Gitee 与国际 GitHub 双源更新",
				"assets": []map[string]any{
					{
						"name":                 "Action2MCP-0.7.9-macOS-AppleSilicon.zip",
						"browser_download_url": srv.URL + "/gitee/download/Action2MCP-0.7.9-macOS-AppleSilicon.zip",
					},
				},
			})
		case "/gitee/download/Action2MCP-0.7.9-macOS-AppleSilicon.zip":
			if giteeReturnHTML.Load() {
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				_, _ = w.Write([]byte("<html><body>请登录 Gitee 后下载</body></html>"))
				return
			}
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipBytes)
		case "/github/api/releases/latest":
			githubHits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tag_name": "v0.7.9",
				"name":     "Action2MCP v0.7.9",
				"body":     "Dual-source update",
				"html_url": "https://github.com/Juddy724/action2mcp/releases/tag/v0.7.9",
				"assets": []map[string]any{
					{
						"name":                 "Action2MCP-0.7.9-macOS-AppleSilicon.zip",
						"browser_download_url": srv.URL + "/github/download/Action2MCP-0.7.9-macOS-AppleSilicon.zip",
					},
				},
			})
		case "/github/download/Action2MCP-0.7.9-macOS-AppleSilicon.zip":
			w.Header().Set("Content-Type", "application/zip")
			_, _ = w.Write(zipBytes)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	// 1. Domestic region picks Gitee
	domestic := New(Options{
		CurrentVersion: "0.7.8",
		Source:         SourceAuto,
		RegionDetector: func() string { return SourceGitee },
		APIURL:         srv.URL + "/github/api/releases/latest",
		GiteeAPIURL:    srv.URL + "/gitee/api/releases/latest",
		HTTPClient:     srv.Client(),
		ExecutablePath: func() (string, error) { return exePath, nil },
		GOOS:           "darwin",
		GOARCH:         "arm64",
	})
	info, err := domestic.CheckNow()
	if err != nil {
		t.Fatalf("domestic CheckNow: %v", err)
	}
	if info.Source != SourceGitee || !info.Available || info.LatestVersion != "0.7.9" {
		t.Fatalf("expected Gitee source, got %+v", info)
	}
	if info.ReleaseURL != "https://gitee.com/tricycle/action2mcp/releases/tag/v0.7.9" {
		t.Fatalf("expected default Gitee release URL, got %q", info.ReleaseURL)
	}
	if giteeHits.Load() != 1 || githubHits.Load() != 0 {
		t.Fatalf("expected 1 gitee hit and 0 github hits, got gitee=%d github=%d", giteeHits.Load(), githubHits.Load())
	}

	// 2. If Gitee returns HTML login page on download, auto mode fails over to fallback URL cleanly
	giteeReturnHTML.Store(true)
	domestic.mu.Lock()
	domestic.last.FallbackAssetURL = srv.URL + "/github/download/Action2MCP-0.7.9-macOS-AppleSilicon.zip"
	domestic.mu.Unlock()
	if _, _, err := domestic.ApplyUpdate(); err != nil {
		t.Fatalf("expected HTML download failover to succeed, got %v", err)
	}
	gotBin, _ := os.ReadFile(exePath)
	if string(gotBin) != newScript {
		t.Fatalf("expected binary upgraded via fallback, got %q", string(gotBin))
	}

	// 3. If Gitee API fails (e.g. private/404), auto mode falls back to GitHub
	giteeDown.Store(true)
	info2, err := domestic.CheckNow()
	if err != nil {
		t.Fatalf("expected fallback to GitHub when Gitee fails, got %v", err)
	}
	if info2.Source != SourceGitHub || info2.LatestVersion != "0.7.9" {
		t.Fatalf("expected GitHub fallback, got %+v", info2)
	}

	// 4. International region goes straight to GitHub
	prevGitee := giteeHits.Load()
	intl := New(Options{
		CurrentVersion: "0.7.8",
		Source:         SourceAuto,
		RegionDetector: func() string { return SourceGitHub },
		APIURL:         srv.URL + "/github/api/releases/latest",
		GiteeAPIURL:    srv.URL + "/gitee/api/releases/latest",
		HTTPClient:     srv.Client(),
		GOOS:           "darwin",
		GOARCH:         "arm64",
	})
	info3, err := intl.CheckNow()
	if err != nil {
		t.Fatalf("intl CheckNow: %v", err)
	}
	if info3.Source != SourceGitHub || giteeHits.Load() != prevGitee {
		t.Fatalf("expected direct GitHub hit for international region, got %+v", info3)
	}
}

func TestProbePrefersGiteeWhenHeadUnauthorizedButGetOK(t *testing.T) {
	var giteeHead, giteeGet, githubHead atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gitee/api/releases/latest":
			// Match Gitee's real /api/v5/repos/.../releases/latest behavior.
			if r.Method == http.MethodHead {
				giteeHead.Add(1)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			giteeGet.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"tag_name":"v0.7.9"}`))
		case "/github/releases/latest":
			githubHead.Add(1)
			w.Header().Set("Location", "https://github.com/Juddy724/action2mcp/releases/tag/v0.7.9")
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	u := New(Options{
		CurrentVersion: "0.7.8",
		Source:         SourceAuto,
		GiteeAPIURL:    srv.URL + "/gitee/api/releases/latest",
		WebReleaseURL:  srv.URL + "/github/releases/latest",
		HTTPClient:     srv.Client(),
	})
	giteeURL := srv.URL + "/gitee/api/releases/latest"
	githubURL := srv.URL + "/github/releases/latest"
	giteeRes := u.probeEndpoint(giteeURL, SourceGitee)
	githubRes := u.probeEndpoint(githubURL, SourceGitHub)
	if !giteeRes.ok {
		t.Fatalf("expected Gitee reachable after HEAD 401 + GET 200, got %+v", giteeRes)
	}
	if !githubRes.ok {
		t.Fatalf("expected GitHub reachable via HEAD 302, got %+v", githubRes)
	}
	if giteeHead.Load() != 1 || giteeGet.Load() != 1 {
		t.Fatalf("gitee probe hits head=%d get=%d", giteeHead.Load(), giteeGet.Load())
	}
	if githubHead.Load() != 1 {
		t.Fatalf("expected GitHub HEAD probe, got %d", githubHead.Load())
	}
	if got := decidePreferredSource(true, giteeRes, githubRes); got != SourceGitee {
		t.Fatalf("expected domestic auto mode to keep Gitee, got %q", got)
	}
}
