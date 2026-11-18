// Package updater checks GitHub Releases periodically and performs atomic in-place binary upgrades.
package updater

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultRepo     = "Juddy724/action2mcp"
	DefaultInterval = 10 * time.Minute
)

type UpdateInfo struct {
	Available      bool   `json:"available"`
	CurrentVersion string `json:"current_version"`
	LatestVersion  string `json:"latest_version,omitempty"`
	ReleaseName    string `json:"release_name,omitempty"`
	ReleaseNotes   string `json:"release_notes,omitempty"`
	ReleaseURL     string `json:"release_url,omitempty"`
	AssetName      string `json:"asset_name,omitempty"`
	AssetURL       string `json:"asset_url,omitempty"`
	AssetSHA256    string `json:"asset_sha256,omitempty"`
	CheckedAt      string `json:"checked_at,omitempty"`
}

type Options struct {
	CurrentVersion string
	Repo           string
	APIURL         string // Optional override for unit tests
	WebReleaseURL  string // Optional override for redirect fallback tests
	Interval       time.Duration
	HTTPClient     *http.Client
	ExecutablePath func() (string, error)
	GOOS           string
	GOARCH         string
}

type Service struct {
	opts       Options
	mu         sync.RWMutex
	etag       string
	last       UpdateInfo
	updatingMu sync.Mutex
	updating   bool
}

func New(o Options) *Service {
	if o.Repo == "" {
		if env := strings.TrimSpace(os.Getenv("A2M_UPDATE_REPO")); env != "" {
			o.Repo = env
		} else {
			o.Repo = DefaultRepo
		}
	}
	if o.APIURL == "" {
		o.APIURL = strings.TrimSpace(os.Getenv("A2M_UPDATE_API_URL"))
	}
	if o.Interval <= 0 {
		o.Interval = DefaultInterval
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 30 * time.Second}
	}
	if o.ExecutablePath == nil {
		o.ExecutablePath = os.Executable
	}
	if o.GOOS == "" {
		o.GOOS = runtime.GOOS
	}
	if o.GOARCH == "" {
		o.GOARCH = runtime.GOARCH
	}
	return &Service{
		opts: o,
		last: UpdateInfo{CurrentVersion: CleanVersion(o.CurrentVersion)},
	}
}

// CleanupStaleFiles removes any leftover temporary or .old binaries from a previous upgrade.
func CleanupStaleFiles(exePath string) {
	if exePath == "" {
		var err error
		exePath, err = os.Executable()
		if err != nil {
			return
		}
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = resolved
	}
	dir := filepath.Dir(exePath)
	base := filepath.Base(exePath)
	_ = os.Remove(filepath.Join(dir, base+".old"))
	_ = os.Remove(filepath.Join(dir, ".a2m.new"))
	_ = os.Remove(filepath.Join(dir, ".a2m.new.exe"))
	_ = os.Remove(filepath.Join(dir, ".a2m-update.tmp.zip"))
}

func (s *Service) Snapshot() UpdateInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.last
}

func (s *Service) Loop(quit <-chan struct{}) {
	// Perform an initial check shortly after startup, then every 10 minutes.
	initTimer := time.NewTimer(5 * time.Second)
	defer initTimer.Stop()
	select {
	case <-quit:
		return
	case <-initTimer.C:
		_, _ = s.CheckNow()
	}

	ticker := time.NewTicker(s.opts.Interval)
	defer ticker.Stop()
	for {
		select {
		case <-quit:
			return
		case <-ticker.C:
			_, _ = s.CheckNow()
		}
	}
}

type ghRelease struct {
	TagName string `json:"tag_name"`
	Name    string `json:"name"`
	Body    string `json:"body"`
	HTMLURL string `json:"html_url"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		URL                string `json:"url"`
		Digest             string `json:"digest"`
	} `json:"assets"`
}

func (s *Service) CheckNow() (UpdateInfo, error) {
	apiURL := s.opts.APIURL
	if apiURL == "" {
		apiURL = "https://api.github.com/repos/" + s.opts.Repo + "/releases/latest"
	}

	s.mu.RLock()
	etag := s.etag
	s.mu.RUnlock()

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return s.Snapshot(), err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Action2MCP-Updater/"+CleanVersion(s.opts.CurrentVersion))
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := s.opts.HTTPClient.Do(req)
	if err != nil {
		if fb, ferr := s.checkViaRedirectFallback(); ferr == nil {
			return fb, nil
		}
		return s.Snapshot(), err
	}
	defer resp.Body.Close()

	nowStr := time.Now().Format("2006-01-02 15:04:05")
	if resp.StatusCode == http.StatusNotModified {
		s.mu.Lock()
		s.last.CheckedAt = nowStr
		out := s.last
		s.mu.Unlock()
		return out, nil
	}

	if resp.StatusCode != http.StatusOK {
		if fb, ferr := s.checkViaRedirectFallback(); ferr == nil {
			return fb, nil
		}
		return s.Snapshot(), fmt.Errorf("GitHub API 返回 HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return s.Snapshot(), err
	}
	var rel ghRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return s.Snapshot(), err
	}

	info := s.buildUpdateInfo(rel, nowStr)
	newETag := strings.TrimSpace(resp.Header.Get("ETag"))

	s.mu.Lock()
	if newETag != "" {
		s.etag = newETag
	}
	s.last = info
	s.mu.Unlock()
	return info, nil
}

func (s *Service) checkViaRedirectFallback() (UpdateInfo, error) {
	webURL := s.opts.WebReleaseURL
	if webURL == "" {
		webURL = "https://github.com/" + s.opts.Repo + "/releases/latest"
	}
	noRedir := *s.opts.HTTPClient
	noRedir.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	req, err := http.NewRequest("HEAD", webURL, nil)
	if err != nil {
		return s.Snapshot(), err
	}
	req.Header.Set("User-Agent", "Action2MCP-Updater/"+CleanVersion(s.opts.CurrentVersion))
	resp, err := noRedir.Do(req)
	if err != nil {
		return s.Snapshot(), err
	}
	resp.Body.Close()
	loc := resp.Header.Get("Location")
	idx := strings.LastIndex(loc, "/tag/")
	if idx < 0 {
		return s.Snapshot(), errors.New("未找到最新版本的重定向标签")
	}
	tag := strings.TrimSpace(loc[idx+len("/tag/"):])
	if tag == "" {
		return s.Snapshot(), errors.New("重定向标签为空")
	}
	ver := CleanVersion(tag)
	suffix := PlatformAssetSuffix(s.opts.GOOS, s.opts.GOARCH)
	assetName := fmt.Sprintf("Action2MCP-%s-%s.zip", ver, suffix)
	assetURL := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", s.opts.Repo, tag, assetName)

	rel := ghRelease{
		TagName: tag,
		Name:    "Action2MCP " + tag,
		HTMLURL: fmt.Sprintf("https://github.com/%s/releases/tag/%s", s.opts.Repo, tag),
	}
	rel.Assets = append(rel.Assets, struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
		URL                string `json:"url"`
		Digest             string `json:"digest"`
	}{
		Name:               assetName,
		BrowserDownloadURL: assetURL,
	})
	info := s.buildUpdateInfo(rel, time.Now().Format("2006-01-02 15:04:05"))
	s.mu.Lock()
	s.last = info
	s.mu.Unlock()
	return info, nil
}

func (s *Service) buildUpdateInfo(rel ghRelease, checkedAt string) UpdateInfo {
	cur := CleanVersion(s.opts.CurrentVersion)
	latest := CleanVersion(rel.TagName)
	avail := latest != "" && CompareVersions(latest, cur) > 0

	suffix := strings.ToLower(PlatformAssetSuffix(s.opts.GOOS, s.opts.GOARCH))
	var assetName, assetURL, assetSHA string
	for _, a := range rel.Assets {
		ln := strings.ToLower(a.Name)
		if suffix != "" && strings.Contains(ln, suffix) && strings.HasSuffix(ln, ".zip") {
			assetName = a.Name
			assetURL = a.BrowserDownloadURL
			if assetURL == "" {
				assetURL = a.URL
			}
			assetSHA = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(a.Digest)), "sha256:")
			break
		}
	}
	if assetURL == "" && latest != "" && suffix != "" {
		rawSuffix := PlatformAssetSuffix(s.opts.GOOS, s.opts.GOARCH)
		assetName = fmt.Sprintf("Action2MCP-%s-%s.zip", latest, rawSuffix)
		assetURL = fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", s.opts.Repo, rel.TagName, assetName)
	}

	return UpdateInfo{
		Available:      avail,
		CurrentVersion: cur,
		LatestVersion:  latest,
		ReleaseName:    rel.Name,
		ReleaseNotes:   strings.TrimSpace(rel.Body),
		ReleaseURL:     rel.HTMLURL,
		AssetName:      assetName,
		AssetURL:       assetURL,
		AssetSHA256:    assetSHA,
		CheckedAt:      checkedAt,
	}
}

// ApplyUpdate downloads the release archive for the current platform, verifies its checksum and binary,
// and atomically replaces the current executable in-place without touching data/ or leaving extra copies.
func (s *Service) ApplyUpdate() (UpdateInfo, string, error) {
	s.updatingMu.Lock()
	if s.updating {
		s.updatingMu.Unlock()
		return s.Snapshot(), "", errors.New("正在下载并更新中，请稍候")
	}
	s.updating = true
	s.updatingMu.Unlock()
	defer func() {
		s.updatingMu.Lock()
		s.updating = false
		s.updatingMu.Unlock()
	}()

	info := s.Snapshot()
	if !info.Available || info.AssetURL == "" {
		fresh, err := s.CheckNow()
		if err != nil && !fresh.Available {
			return fresh, "", fmt.Errorf("检查最新版本失败：%v", err)
		}
		info = fresh
	}
	if !info.Available {
		return info, "", errors.New("当前已经是最新版本（v" + info.CurrentVersion + "）")
	}
	if info.AssetURL == "" {
		return info, "", fmt.Errorf("未找到适用于当前系统（%s/%s）的安装包", s.opts.GOOS, s.opts.GOARCH)
	}

	exePath, err := s.opts.ExecutablePath()
	if err != nil {
		return info, "", fmt.Errorf("无法定位当前程序路径：%v", err)
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = resolved
	}
	CleanupStaleFiles(exePath)

	exeDir := filepath.Dir(exePath)
	tmpZip := filepath.Join(exeDir, ".a2m-update.tmp.zip")
	defer os.Remove(tmpZip)

	dlClient := *s.opts.HTTPClient
	if dlClient.Timeout < 5*time.Minute {
		dlClient.Timeout = 5 * time.Minute
	}
	req, err := http.NewRequest("GET", info.AssetURL, nil)
	if err != nil {
		return info, "", err
	}
	req.Header.Set("User-Agent", "Action2MCP-Updater/"+info.CurrentVersion)
	resp, err := dlClient.Do(req)
	if err != nil {
		return info, "", fmt.Errorf("下载新版本失败：%v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return info, "", fmt.Errorf("下载新版本失败：HTTP %d", resp.StatusCode)
	}

	zf, err := os.OpenFile(tmpZip, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return info, "", fmt.Errorf("创建临时文件失败（请检查程序目录写权限）：%v", err)
	}
	h := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(zf, h), io.LimitReader(resp.Body, 250<<20))
	closeErr := zf.Close()
	if copyErr != nil {
		return info, "", fmt.Errorf("下载中断：%v", copyErr)
	}
	if closeErr != nil {
		return info, "", closeErr
	}

	if len(info.AssetSHA256) == 64 {
		gotSum := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(gotSum, info.AssetSHA256) {
			return info, "", fmt.Errorf("安装包 SHA-256 校验失败（预期 %s，实际 %s）", info.AssetSHA256[:12], gotSum[:12])
		}
	}

	wantBin := "a2m"
	tmpBinName := ".a2m.new"
	if s.opts.GOOS == "windows" {
		wantBin = "a2m.exe"
		tmpBinName = ".a2m.new.exe"
	}
	tmpBin := filepath.Join(exeDir, tmpBinName)
	defer os.Remove(tmpBin)

	if err := extractBinaryFromZip(tmpZip, wantBin, tmpBin); err != nil {
		return info, "", err
	}

	if s.opts.GOOS == "darwin" {
		_ = exec.Command("xattr", "-d", "com.apple.quarantine", tmpBin).Run()
	}

	// Verify the new binary can start and report its version before replacing the live executable.
	if out, err := exec.Command(tmpBin, "version").CombinedOutput(); err != nil {
		return info, "", fmt.Errorf("新版本程序自检失败：%v (%s)", err, strings.TrimSpace(string(out)))
	}

	if err := replaceExecutableAtomically(exePath, tmpBin, s.opts.GOOS); err != nil {
		return info, "", err
	}

	log.Printf("已完成版本替换：v%s -> v%s (%s)", info.CurrentVersion, info.LatestVersion, exePath)
	return info, exePath, nil
}

func extractBinaryFromZip(zipPath, wantBin, destPath string) error {
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("解压安装包失败：%v", err)
	}
	defer zr.Close()

	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		if strings.EqualFold(filepath.Base(f.Name), wantBin) {
			rc, err := f.Open()
			if err != nil {
				return fmt.Errorf("读取安装包内程序失败：%v", err)
			}
			out, err := os.OpenFile(destPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o755)
			if err != nil {
				rc.Close()
				return fmt.Errorf("写入新版本程序失败：%v", err)
			}
			_, copyErr := io.Copy(out, io.LimitReader(rc, 250<<20))
			rc.Close()
			closeErr := out.Close()
			if copyErr != nil {
				return fmt.Errorf("写出新版本程序失败：%v", copyErr)
			}
			if closeErr != nil {
				return closeErr
			}
			return os.Chmod(destPath, 0o755)
		}
	}
	return fmt.Errorf("安装包中未找到可执行文件 %s", wantBin)
}

func replaceExecutableAtomically(exePath, tmpBin, goos string) error {
	if goos == "windows" {
		oldPath := exePath + ".old"
		_ = os.Remove(oldPath)
		if err := os.Rename(exePath, oldPath); err != nil {
			return fmt.Errorf("重命名旧版本程序失败：%v", err)
		}
		if err := os.Rename(tmpBin, exePath); err != nil {
			_ = os.Rename(oldPath, exePath)
			return fmt.Errorf("替换新版本程序失败：%v", err)
		}
		return nil
	}
	// On macOS / Linux, os.Rename atomically unlinks the old directory entry and binds exePath
	// to the new inode, avoiding macOS Apple Silicon CDHash SIGKILL (137) and Linux ETXTBSY.
	if err := os.Rename(tmpBin, exePath); err != nil {
		return fmt.Errorf("替换程序文件失败：%v", err)
	}
	return nil
}

func PlatformAssetSuffix(goos, goarch string) string {
	switch goos {
	case "darwin":
		if goarch == "arm64" {
			return "macOS-AppleSilicon"
		}
		return "macOS-Intel"
	case "linux":
		return "Linux-x64"
	case "windows":
		return "Windows-x64"
	default:
		return ""
	}
}

func CleanVersion(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(strings.TrimPrefix(v, "v"), "V")
	return strings.TrimSpace(v)
}

// CompareVersions compares two semantic version strings (e.g. "0.6.3" vs "0.6.2").
// Returns 1 if a > b, -1 if a < b, 0 if equal.
func CompareVersions(a, b string) int {
	pa := parseVersionParts(a)
	pb := parseVersionParts(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var va, vb int
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va > vb {
			return 1
		}
		if va < vb {
			return -1
		}
	}
	return 0
}

func parseVersionParts(v string) []int {
	v = CleanVersion(v)
	if idx := strings.IndexAny(v, "-+"); idx >= 0 {
		v = v[:idx]
	}
	if v == "" {
		return nil
	}
	segs := strings.Split(v, ".")
	out := make([]int, 0, len(segs))
	for _, s := range segs {
		n, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil {
			n = 0
		}
		out = append(out, n)
	}
	return out
}
