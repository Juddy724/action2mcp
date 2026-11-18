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

