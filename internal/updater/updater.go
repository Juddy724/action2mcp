// Package updater checks Gitee (domestic) and GitHub (international) Releases periodically
// and performs atomic in-place binary upgrades.
package updater

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	DefaultRepo      = "Juddy724/action2mcp"
	DefaultGiteeRepo = "tricycle/action2mcp"
	DefaultInterval  = 10 * time.Minute

	SourceAuto   = "auto"
	SourceGitee  = "gitee"
	SourceGitHub = "github"

	regionCacheTTL = 30 * time.Minute
	probeTimeout   = 3 * time.Second
)

type UpdateInfo struct {
	Available        bool   `json:"available"`
	CurrentVersion   string `json:"current_version"`
	LatestVersion    string `json:"latest_version,omitempty"`
	ReleaseName      string `json:"release_name,omitempty"`
	ReleaseNotes     string `json:"release_notes,omitempty"`
	ReleaseURL       string `json:"release_url,omitempty"`
	AssetName        string `json:"asset_name,omitempty"`
	AssetURL         string `json:"asset_url,omitempty"`
	FallbackAssetURL string `json:"fallback_asset_url,omitempty"`
	AssetSHA256      string `json:"asset_sha256,omitempty"`
	Source           string `json:"source,omitempty"`       // "gitee" or "github"
	SourceLabel      string `json:"source_label,omitempty"` // Human-readable mirror label
	CheckedAt        string `json:"checked_at,omitempty"`
}

type Options struct {
	CurrentVersion     string
	Repo               string // GitHub owner/repo
	GiteeRepo          string // Gitee owner/repo
	Source             string // "auto" (default), "gitee", or "github"
	SourceFunc         func() string
	RegionDetector     func() string // Optional override for unit tests; returns SourceGitee or SourceGitHub
	APIURL             string        // Optional GitHub API override for unit tests
	WebReleaseURL      string        // Optional GitHub web redirect override for unit tests
	AtomURL            string        // Optional GitHub releases Atom feed override for unit tests
	GiteeAPIURL        string        // Optional Gitee API override for unit tests
	GiteeWebReleaseURL string        // Optional Gitee web redirect override for unit tests
	GiteeToken         string        // Optional Gitee personal access token (A2M_GITEE_TOKEN)
	Interval           time.Duration
	HTTPClient         *http.Client
	ExecutablePath     func() (string, error)
	GOOS               string
	GOARCH             string
}

type Service struct {
	opts           Options
	mu             sync.RWMutex
	etags          map[string]string
	last           UpdateInfo
	updatingMu     sync.Mutex
	updating       bool
	regionMu       sync.Mutex
	cachedRegion   string
	cachedRegionAt time.Time
	githubOnlyMode bool
}

func New(o Options) *Service {
	// Keep backwards compatibility with unit tests that only pass a mock GitHub APIURL/WebReleaseURL
	// without configuring Gitee test endpoints or a region detector.
	githubOnly := (o.APIURL != "" || o.WebReleaseURL != "") &&
		o.GiteeAPIURL == "" && o.GiteeWebReleaseURL == "" &&
		o.Source == "" && o.SourceFunc == nil && o.RegionDetector == nil

	if o.Repo == "" {
		if env := strings.TrimSpace(os.Getenv("A2M_UPDATE_REPO")); env != "" {
			o.Repo = env
		} else {
			o.Repo = DefaultRepo
		}
	}
	if o.GiteeRepo == "" {
		if env := strings.TrimSpace(os.Getenv("A2M_UPDATE_GITEE_REPO")); env != "" {
			o.GiteeRepo = env
		} else {
			o.GiteeRepo = DefaultGiteeRepo
		}
	}
	if o.Source == "" {
		if env := strings.TrimSpace(os.Getenv("A2M_UPDATE_SOURCE")); env != "" {
			o.Source = NormalizeSource(env)
		} else {
			o.Source = SourceAuto
		}
	} else {
		o.Source = NormalizeSource(o.Source)
	}
	if o.APIURL == "" {
		o.APIURL = strings.TrimSpace(os.Getenv("A2M_UPDATE_API_URL"))
	}
	if o.GiteeAPIURL == "" {
		o.GiteeAPIURL = strings.TrimSpace(os.Getenv("A2M_UPDATE_GITEE_API_URL"))
	}
	if o.GiteeToken == "" {
		o.GiteeToken = strings.TrimSpace(os.Getenv("A2M_GITEE_TOKEN"))
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
		opts:           o,
		etags:          map[string]string{},
		last:           UpdateInfo{CurrentVersion: CleanVersion(o.CurrentVersion)},
		githubOnlyMode: githubOnly,
	}
}

func NormalizeSource(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case SourceGitee, "cn", "domestic":
		return SourceGitee
	case SourceGitHub, "global", "international", "intl":
		return SourceGitHub
	default:
		return SourceAuto
	}
}

func SourceDisplayLabel(src string) string {
	switch src {
	case SourceGitee:
		return "Gitee（国内源）"
	case SourceGitHub:
		return "GitHub（国际源）"
	default:
		return ""
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

func (s *Service) effectiveSourceMode() string {
	if s.githubOnlyMode {
		return SourceGitHub
	}
	if s.opts.SourceFunc != nil {
		if v := strings.TrimSpace(s.opts.SourceFunc()); v != "" {
			return NormalizeSource(v)
		}
	}
	return NormalizeSource(s.opts.Source)
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

type releasePayload struct {
	TagName string         `json:"tag_name"`
	Name    string         `json:"name"`
	Body    string         `json:"body"`
	HTMLURL string         `json:"html_url"`
	Assets  []releaseAsset `json:"assets"`
}

type releaseAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
	URL                string `json:"url"`
	Digest             string `json:"digest"`
}

func (s *Service) CheckNow() (UpdateInfo, error) {
	mode := s.effectiveSourceMode()
	var order []string
	switch mode {
	case SourceGitee:
		order = []string{SourceGitee}
	case SourceGitHub:
		order = []string{SourceGitHub}
	default:
		primary := s.resolveAutoPrimarySource()
		if primary == SourceGitee {
			order = []string{SourceGitee, SourceGitHub}
		} else {
			order = []string{SourceGitHub, SourceGitee}
		}
	}

	var errs []string
	for _, src := range order {
		var (
			info UpdateInfo
			err  error
		)
		if src == SourceGitee {
			info, err = s.checkGitee()
		} else {
			info, err = s.checkGitHub()
		}
		if err == nil {
			return info, nil
		}
		errs = append(errs, fmt.Sprintf("%s: %v", SourceDisplayLabel(src), err))
	}
	return s.Snapshot(), errors.New(strings.Join(errs, "；"))
}

func (s *Service) resolveAutoPrimarySource() string {
	if s.opts.RegionDetector != nil {
		if detected := NormalizeSource(s.opts.RegionDetector()); detected == SourceGitee || detected == SourceGitHub {
			return detected
		}
	}

	s.regionMu.Lock()
	if s.cachedRegion != "" && time.Since(s.cachedRegionAt) < regionCacheTTL {
		res := s.cachedRegion
		s.regionMu.Unlock()
		return res
	}
	s.regionMu.Unlock()

	detected := s.probePreferredSource()

	s.regionMu.Lock()
	s.cachedRegion = detected
	s.cachedRegionAt = time.Now()
	s.regionMu.Unlock()
	return detected
}

type probeResult struct {
	ok  bool
	rtt time.Duration
}

func (s *Service) probePreferredSource() string {
	domesticHint := isDomesticHostEnv()

	giteeProbeURL := s.opts.GiteeAPIURL
	if giteeProbeURL == "" {
		giteeProbeURL = "https://gitee.com/api/v5/repos/" + s.opts.GiteeRepo + "/releases/latest"
	}
	githubProbeURL := s.opts.WebReleaseURL
	if githubProbeURL == "" {
		if s.opts.APIURL != "" {
			githubProbeURL = s.opts.APIURL
		} else {
			githubProbeURL = "https://github.com/" + s.opts.Repo + "/releases/latest"
		}
	}

	var (
		wg        sync.WaitGroup
		giteeRes  probeResult
		githubRes probeResult
	)
	wg.Add(2)
	go func() {
		defer wg.Done()
		giteeRes = s.probeEndpoint(giteeProbeURL, SourceGitee)
	}()
	go func() {
		defer wg.Done()
		githubRes = s.probeEndpoint(githubProbeURL, SourceGitHub)
	}()
	wg.Wait()

	return decidePreferredSource(domesticHint, giteeRes, githubRes)
}

func decidePreferredSource(domesticHint bool, giteeRes, githubRes probeResult) string {
	if giteeRes.ok && !githubRes.ok {
		return SourceGitee
	}
	if githubRes.ok && !giteeRes.ok {
		return SourceGitHub
	}
	if giteeRes.ok && githubRes.ok {
		if domesticHint {
			if giteeRes.rtt > 1500*time.Millisecond && giteeRes.rtt > githubRes.rtt*3 {
				return SourceGitHub
			}
			return SourceGitee
		}
		if giteeRes.rtt < 150*time.Millisecond && githubRes.rtt > 400*time.Millisecond {
			return SourceGitee
		}
		return SourceGitHub
	}
	if domesticHint {
		return SourceGitee
	}
	return SourceGitHub
}

func (s *Service) probeEndpoint(rawURL, src string) probeResult {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()

	client := *s.opts.HTTPClient
	client.Timeout = probeTimeout
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	do := func(method string) (int, time.Duration, error) {
		req, err := http.NewRequestWithContext(ctx, method, rawURL, nil)
		if err != nil {
			return 0, 0, err
		}
		req.Header.Set("User-Agent", "Action2MCP-Updater/"+CleanVersion(s.opts.CurrentVersion))
		if src == SourceGitee && s.opts.GiteeToken != "" {
			req.Header.Set("Authorization", "token "+s.opts.GiteeToken)
		}
		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			return 0, 0, err
		}
		if method == http.MethodGet {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		}
		resp.Body.Close()
		return resp.StatusCode, time.Since(start), nil
	}

	code, rtt, err := do(http.MethodHead)
	if err != nil {
		return probeResult{}
	}
	if code >= 200 && code < 400 {
		return probeResult{ok: true, rtt: rtt}
	}
	// Gitee's releases API answers HEAD with 401, and some hosts use 405.
	// A successful GET still means the source is reachable.
	code, rtt, err = do(http.MethodGet)
	if err != nil {
		return probeResult{}
	}
	if code >= 200 && code < 400 {
		return probeResult{ok: true, rtt: rtt}
	}
	return probeResult{ok: false, rtt: rtt}
}

// isDomesticHostEnv detects mainland China timezone or locale hints without contacting any third-party service.
func isDomesticHostEnv() bool {
	tz := strings.ToLower(strings.TrimSpace(os.Getenv("TZ")))
	if tz == "" {
		if target, err := os.Readlink("/etc/localtime"); err == nil {
			tz = strings.ToLower(target)
		}
	}
	for _, marker := range []string{"asia/shanghai", "asia/chongqing", "asia/harbin", "asia/urumqi", "prc", "china standard time"} {
		if strings.Contains(tz, marker) {
			return true
		}
	}
	if name, offset := time.Now().Zone(); offset == 8*3600 {
		upper := strings.ToUpper(strings.TrimSpace(name))
		if upper == "CST" || strings.Contains(strings.ToLower(name), "china") {
			// Distinguish mainland China (CST/zh_CN) from Singapore/HK/Taipei (+0800) when TZ symlink wasn't available.
			if tz == "" {
				for _, envKey := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
					v := strings.ToLower(strings.TrimSpace(os.Getenv(envKey)))
					if strings.HasPrefix(v, "zh_cn") || strings.HasPrefix(v, "zh-cn") {
						return true
					}
				}
				// On Windows Go reports "CST" / "China Standard Time" with no /etc/localtime.
				if runtime.GOOS == "windows" && strings.Contains(strings.ToLower(name), "china") {
					return true
				}
			}
		}
	}
	for _, envKey := range []string{"LC_ALL", "LC_MESSAGES", "LANG"} {
		v := strings.ToLower(strings.TrimSpace(os.Getenv(envKey)))
		if strings.HasPrefix(v, "zh_cn") || strings.HasPrefix(v, "zh-cn") {
			return true
		}
	}
	return false
}

func (s *Service) checkGitee() (UpdateInfo, error) {
	apiURL := s.opts.GiteeAPIURL
	if apiURL == "" {
		apiURL = "https://gitee.com/api/v5/repos/" + s.opts.GiteeRepo + "/releases/latest"
	}

	s.mu.RLock()
	etag := s.etags[SourceGitee]
	lastSrc := s.last.Source
	s.mu.RUnlock()

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return s.Snapshot(), err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Action2MCP-Updater/"+CleanVersion(s.opts.CurrentVersion))
	if s.opts.GiteeToken != "" {
		req.Header.Set("Authorization", "token "+s.opts.GiteeToken)
	}
	if etag != "" && lastSrc == SourceGitee {
		req.Header.Set("If-None-Match", etag)
	}

	resp, err := s.opts.HTTPClient.Do(req)
	if err != nil {
		if fb, ferr := s.checkGiteeViaRedirectFallback(); ferr == nil {
			return fb, nil
		}
		return s.Snapshot(), err
	}
	defer resp.Body.Close()

	nowStr := time.Now().Format("2006-01-02 15:04:05")
	if resp.StatusCode == http.StatusNotModified && lastSrc == SourceGitee {
		s.mu.Lock()
		s.last.CheckedAt = nowStr
		out := s.last
		s.mu.Unlock()
		return out, nil
	}

	if resp.StatusCode != http.StatusOK {
		if fb, ferr := s.checkGiteeViaRedirectFallback(); ferr == nil {
			return fb, nil
		}
		return s.Snapshot(), fmt.Errorf("Gitee API 返回 HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return s.Snapshot(), err
	}
	var rel releasePayload
	if err := json.Unmarshal(body, &rel); err != nil {
		return s.Snapshot(), err
	}
	if strings.TrimSpace(rel.TagName) == "" {
		return s.Snapshot(), errors.New("Gitee 尚未发布 Release 版本")
	}
	if strings.TrimSpace(rel.HTMLURL) == "" {
		rel.HTMLURL = fmt.Sprintf("https://gitee.com/%s/releases/tag/%s", s.opts.GiteeRepo, rel.TagName)
	}

	info := s.buildUpdateInfo(rel, SourceGitee, nowStr)
	newETag := strings.TrimSpace(resp.Header.Get("ETag"))

	s.mu.Lock()
	if newETag != "" {
		s.etags[SourceGitee] = newETag
	}
	s.last = info
	s.mu.Unlock()
	return info, nil
}

func (s *Service) checkGiteeViaRedirectFallback() (UpdateInfo, error) {
	webURL := s.opts.GiteeWebReleaseURL
	if webURL == "" {
		if s.opts.GiteeAPIURL != "" {
			return s.Snapshot(), errors.New("Gitee API 不可用且未配置重定向地址")
		}
		webURL = "https://gitee.com/" + s.opts.GiteeRepo + "/releases/latest"
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
		return s.Snapshot(), errors.New("未找到 Gitee 最新版本的重定向标签")
	}
	tag := strings.TrimSpace(loc[idx+len("/tag/"):])
	if tag == "" {
		return s.Snapshot(), errors.New("Gitee 重定向标签为空")
	}
	ver := CleanVersion(tag)
	suffix := PlatformAssetSuffix(s.opts.GOOS, s.opts.GOARCH)
	assetName := fmt.Sprintf("Action2MCP-%s-%s.zip", ver, suffix)
	assetURL := fmt.Sprintf("https://gitee.com/%s/releases/download/%s/%s", s.opts.GiteeRepo, tag, assetName)

	rel := releasePayload{
		TagName: tag,
		Name:    "Action2MCP " + tag,
		HTMLURL: fmt.Sprintf("https://gitee.com/%s/releases/tag/%s", s.opts.GiteeRepo, tag),
		Assets:  []releaseAsset{{Name: assetName, BrowserDownloadURL: assetURL}},
	}
	info := s.buildUpdateInfo(rel, SourceGitee, time.Now().Format("2006-01-02 15:04:05"))
	s.mu.Lock()
	if info.ReleaseNotes == "" && s.last.LatestVersion == info.LatestVersion {
		info.ReleaseNotes = s.last.ReleaseNotes
	}
	s.last = info
	s.mu.Unlock()
	return info, nil
}

func (s *Service) checkGitHub() (UpdateInfo, error) {
	apiURL := s.opts.APIURL
	if apiURL == "" {
		apiURL = "https://api.github.com/repos/" + s.opts.Repo + "/releases/latest"
	}

	s.mu.RLock()
	etag := s.etags[SourceGitHub]
	lastSrc := s.last.Source
	s.mu.RUnlock()

	req, err := http.NewRequest("GET", apiURL, nil)
	if err != nil {
		return s.Snapshot(), err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "Action2MCP-Updater/"+CleanVersion(s.opts.CurrentVersion))
	if etag != "" && lastSrc == SourceGitHub {
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
	if resp.StatusCode == http.StatusNotModified && lastSrc == SourceGitHub {
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
	var rel releasePayload
	if err := json.Unmarshal(body, &rel); err != nil {
		return s.Snapshot(), err
	}

	info := s.buildUpdateInfo(rel, SourceGitHub, nowStr)
	newETag := strings.TrimSpace(resp.Header.Get("ETag"))

	s.mu.Lock()
	if newETag != "" {
		s.etags[SourceGitHub] = newETag
	}
	s.last = info
	s.mu.Unlock()
	return info, nil
}

func (s *Service) checkViaRedirectFallback() (UpdateInfo, error) {
	webURL := s.opts.WebReleaseURL
	if webURL == "" {
		if s.opts.APIURL != "" {
			return s.Snapshot(), errors.New("GitHub API 不可用且未配置重定向地址")
		}
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

	rel := releasePayload{
		TagName: tag,
		Name:    "Action2MCP " + tag,
		HTMLURL: fmt.Sprintf("https://github.com/%s/releases/tag/%s", s.opts.Repo, tag),
		Assets:  []releaseAsset{{Name: assetName, BrowserDownloadURL: assetURL}},
	}
	rel.Body = s.fetchAtomNotes(tag)
	info := s.buildUpdateInfo(rel, SourceGitHub, time.Now().Format("2006-01-02 15:04:05"))
	s.mu.Lock()
	if info.ReleaseNotes == "" && s.last.LatestVersion == info.LatestVersion {
		info.ReleaseNotes = s.last.ReleaseNotes
	}
	if info.AssetSHA256 == "" && s.last.LatestVersion == info.LatestVersion && s.last.AssetName == info.AssetName {
		info.AssetSHA256 = s.last.AssetSHA256
	}
	s.last = info
	s.mu.Unlock()
	return info, nil
}

// fetchAtomNotes reads release notes from the public releases Atom feed, which is not subject to
// the REST API rate limit. Returns "" on any failure.
func (s *Service) fetchAtomNotes(tag string) string {
	feedURL := s.opts.AtomURL
	if feedURL == "" {
		if s.opts.APIURL != "" || s.opts.WebReleaseURL != "" {
			return ""
		}
		feedURL = "https://github.com/" + s.opts.Repo + "/releases.atom"
	}
	req, err := http.NewRequest("GET", feedURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Action2MCP-Updater/"+CleanVersion(s.opts.CurrentVersion))
	resp, err := s.opts.HTTPClient.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ""
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return ""
	}
	return parseAtomNotes(data, tag)
}

type atomFeed struct {
	Entries []struct {
		Links []struct {
			Href string `xml:"href,attr"`
		} `xml:"link"`
		Content string `xml:"content"`
	} `xml:"entry"`
}

func parseAtomNotes(data []byte, tag string) string {
	var f atomFeed
	if err := xml.Unmarshal(data, &f); err != nil {
		return ""
	}
	for _, e := range f.Entries {
		for _, l := range e.Links {
			if strings.HasSuffix(l.Href, "/tag/"+tag) {
				return htmlToText(e.Content)
			}
		}
	}
	return ""
}

var (
	olBlockRe  = regexp.MustCompile(`(?is)<ol[^>]*>(.*?)</ol>`)
	liOpenRe   = regexp.MustCompile(`(?i)<li[^>]*>`)
	blockEndRe = regexp.MustCompile(`(?i)</(p|li|h[1-6]|div|ul|ol)>|<br\s*/?>`)
	tagRe      = regexp.MustCompile(`<[^>]+>`)
	blankRe    = regexp.MustCompile(`\n{2,}`)
)

func htmlToText(h string) string {
	h = olBlockRe.ReplaceAllStringFunc(h, func(block string) string {
		n := 0
		return liOpenRe.ReplaceAllStringFunc(block, func(string) string {
			n++
			return "\n" + strconv.Itoa(n) + ". "
		})
	})
	h = liOpenRe.ReplaceAllString(h, "\n• ")
	h = blockEndRe.ReplaceAllString(h, "\n")
	h = tagRe.ReplaceAllString(h, "")
	h = html.UnescapeString(h)
	lines := strings.Split(h, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(l)
	}
	h = blankRe.ReplaceAllString(strings.Join(lines, "\n"), "\n")
	return strings.TrimSpace(h)
}

func (s *Service) buildUpdateInfo(rel releasePayload, source, checkedAt string) UpdateInfo {
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
		if source == SourceGitee {
			assetURL = fmt.Sprintf("https://gitee.com/%s/releases/download/%s/%s", s.opts.GiteeRepo, rel.TagName, assetName)
		} else {
			assetURL = fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", s.opts.Repo, rel.TagName, assetName)
		}
	}

	var fallbackURL string
	if !s.githubOnlyMode && assetName != "" && rel.TagName != "" {
		if source == SourceGitee && s.opts.Repo != "" {
			fallbackURL = fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", s.opts.Repo, rel.TagName, assetName)
		} else if source == SourceGitHub && s.opts.GiteeRepo != "" {
			fallbackURL = fmt.Sprintf("https://gitee.com/%s/releases/download/%s/%s", s.opts.GiteeRepo, rel.TagName, assetName)
		}
	}

	return UpdateInfo{
		Available:        avail,
		CurrentVersion:   cur,
		LatestVersion:    latest,
		ReleaseName:      rel.Name,
		ReleaseNotes:     strings.TrimSpace(rel.Body),
		ReleaseURL:       rel.HTMLURL,
		AssetName:        assetName,
		AssetURL:         assetURL,
		FallbackAssetURL: fallbackURL,
		AssetSHA256:      assetSHA,
		Source:           source,
		SourceLabel:      SourceDisplayLabel(source),
		CheckedAt:        checkedAt,
	}
}

type downloadCandidate struct {
	url    string
	source string
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

	candidates := []downloadCandidate{{url: info.AssetURL, source: info.Source}}
	if info.FallbackAssetURL != "" && info.FallbackAssetURL != info.AssetURL && s.effectiveSourceMode() == SourceAuto {
		fbSource := SourceGitHub
		if info.Source == SourceGitHub {
			fbSource = SourceGitee
		}
		candidates = append(candidates, downloadCandidate{url: info.FallbackAssetURL, source: fbSource})
	}

	var dlErrs []string
	downloaded := false
	for i, cand := range candidates {
		err := s.downloadReleaseZip(cand.url, cand.source, info.CurrentVersion, info.AssetSHA256, tmpZip)
		if err == nil {
			downloaded = true
			if i > 0 {
				log.Printf("主更新源下载失败，已自动切换至备用源完成下载：%s", cand.url)
			}
			break
		}
		dlErrs = append(dlErrs, fmt.Sprintf("%s（%v）", SourceDisplayLabel(cand.source), err))
	}
	if !downloaded {
		hint := ""
		if info.ReleaseURL != "" {
			hint = "；也可以在浏览器打开下载页手动更新：" + info.ReleaseURL
		}
		return info, "", fmt.Errorf("下载新版本失败：%s%s", strings.Join(dlErrs, "；"), hint)
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

func (s *Service) downloadReleaseZip(assetURL, source, curVer, expectedSHA, tmpZip string) error {
	dlClient := *s.opts.HTTPClient
	if dlClient.Timeout < 5*time.Minute {
		dlClient.Timeout = 5 * time.Minute
	}
	req, err := http.NewRequest("GET", assetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "Action2MCP-Updater/"+curVer)
	if source == SourceGitee && s.opts.GiteeToken != "" {
		req.Header.Set("Authorization", "token "+s.opts.GiteeToken)
	}
	resp, err := dlClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if ct := strings.ToLower(resp.Header.Get("Content-Type")); strings.Contains(ct, "text/html") {
		return errors.New("返回了网页而非安装包（可能需要登录下载）")
	}

	zf, err := os.OpenFile(tmpZip, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("创建临时文件失败（请检查程序目录写权限）：%v", err)
	}
	h := sha256.New()
	n, copyErr := io.Copy(io.MultiWriter(zf, h), io.LimitReader(resp.Body, 250<<20))
	closeErr := zf.Close()
	if copyErr != nil {
		return fmt.Errorf("下载中断：%v", copyErr)
	}
	if closeErr != nil {
		return closeErr
	}
	if n < 4 {
		return errors.New("下载文件为空或损坏")
	}
	if !isZipFile(tmpZip) {
		return errors.New("下载内容不是有效的 ZIP 安装包")
	}
	if len(expectedSHA) == 64 {
		gotSum := hex.EncodeToString(h.Sum(nil))
		if !strings.EqualFold(gotSum, expectedSHA) {
			return fmt.Errorf("安装包 SHA-256 校验失败（预期 %s，实际 %s）", expectedSHA[:12], gotSum[:12])
		}
	}
	return nil
}

func isZipFile(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [4]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return magic[0] == 'P' && magic[1] == 'K' && (magic[2] == 3 || magic[2] == 5 || magic[2] == 7)
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
