package main

import (
	"encoding/json"
	"net/url"
	"path"
	"regexp"
	"strings"
)

var staticExt = map[string]bool{".js": true, ".mjs": true, ".css": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true,
	".webp": true, ".avif": true, ".bmp": true, ".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true, ".map": true, ".mp4": true, ".mp3": true, ".webm": true, ".wasm": true}

var analyticsHosts = []string{"google-analytics.com", "googletagmanager.com", "doubleclick.net", "googlesyndication.com", "analytics.google.com",
	"hm.baidu.com", "cnzz.com", "umeng.com", "sentry.io", "sentry-cdn", "segment.io", "segment.com", "mixpanel.com", "hotjar.com", "clarity.ms",
	"growingio.com", "sensorsdata", "facebook.net", "connect.facebook", "bat.bing.com", "amplitude.com", "newrelic.com", "nr-data.net",
	"datadoghq", "intercom.io", "fullstory.com", "zhugeio.com", "talkingdata", "arms-retcode", "aliyuncs.com/r.png", "mmstat.com", "log.mmstat", "tongji", "51.la", "crashlytics", "bugsnag", "logrocket"}

// Clear tracking words and log-upload shapes. Ambiguous segments (log, stat,
// metrics, …) are handled separately so business log APIs stay visible.
var trackingPath = regexp.MustCompile(`(?i)(^|/)(collect|track|tracking|analytics|beacon|telemetry|sentry|rum|gtag|pixel|event-log|__log|apm)(/|$|\?|\.)`)

// The final group is a segment boundary so /report/log does not match
// /report/login or /report/logistics.
var trackingCombo = regexp.MustCompile(`(?i)(?:/logs?/(?:collect|upload|report)|/report/log|/batch/collect)(?:/|$|\?|\.)`)
var ambiguousSeg = regexp.MustCompile(`(?i)(^|/)(log|logs|logging|stat|stats|metrics|monitor|perf)(/|$|\?|\.)`)

var basePath = regexp.MustCompile(`(?i)(config|dict|dictionary|enum|permission|permissions|perm|menu|menus|route|routes|i18n|locale|lang|translation|heartbeat|ping|health|captcha|version|notice|notification|unread|userinfo|user[-_/]?info|current[-_]?user|/me$|/profile$|getinfo|get[-_]?user|settings|feature[-_]?flag|toggles|options$|whoami|session/check|token/refresh|refresh[-_]?token)`)

// ClassifyNoise returns whether a request is probably noise and a short Chinese reason.
func ClassifyNoise(q *ReqRecord) (bool, string) {
	u, err := url.Parse(q.URL)
	if err != nil {
		return true, "无法解析的地址"
	}
	host := strings.ToLower(u.Host)
	p := strings.ToLower(u.Path)
	if q.Method == "OPTIONS" {
		return true, "跨域预检"
	}
	if q.ResourceType == "WebSocket" || q.Method == "WS" {
		if q.Status == 0 {
			return true, "未完成"
		}
		h := strings.ToLower(u.Hostname())
		for _, a := range analyticsHosts {
			if strings.Contains(a, "/") {
				continue
			}
			if h == a || strings.HasSuffix(h, "."+a) || strings.Contains(h, a) {
				return true, "埋点/监控"
			}
		}
		return false, ""
	}
	switch q.ResourceType {
	case "Script", "Stylesheet", "Image", "Font", "Media", "Manifest", "TextTrack":
		return true, "静态资源"
	case "Ping", "Beacon":
		return true, "埋点上报"
	}
	if staticExt[path.Ext(p)] || strings.HasSuffix(p, "favicon.ico") {
		return true, "静态资源"
	}
	for _, h := range analyticsHosts {
		if strings.Contains(host+p, h) {
			return true, "埋点/监控"
		}
	}
	business := looksLikeBusinessJSON(q)
	if !business && (trackingPath.MatchString(p) || trackingCombo.MatchString(p)) {
		return true, "埋点/日志"
	}
	if !business && ambiguousSeg.MatchString(p) && looksLikeTelemetry(q) {
		return true, "埋点/日志"
	}
	if strings.HasPrefix(q.RespMime, "image/") || strings.HasPrefix(q.RespMime, "font/") || q.RespMime == "text/css" {
		return true, "静态资源"
	}
	if q.ResourceType == "Document" && q.Method == "GET" {
		return true, "页面加载"
	}
	if !business && q.Method == "GET" && basePath.MatchString(p) {
		return true, "基础配置/用户信息"
	}
	if q.Status == 0 || q.Status >= 300 && q.Status < 400 {
		return true, "未完成或重定向"
	}
	return false, ""
}

// looksLikeBusinessJSON is the guard for 埋点/日志 and 基础配置/用户信息.
// XHR/Fetch responses that carry a list, a paging object, or a large JSON body
// are business data even when the path contains words like log.
func looksLikeBusinessJSON(q *ReqRecord) bool {
	switch strings.ToLower(strings.TrimSpace(q.ResourceType)) {
	case "xhr", "fetch":
	default:
		return false
	}
	body := strings.TrimSpace(q.RespBody)
	mime := strings.ToLower(q.RespMime)
	jsonMime := strings.Contains(mime, "json")
	looks := jsonMime || strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[")
	if !looks {
		return false
	}
	if len(body) > 1024 {
		if jsonMime || json.Valid([]byte(body)) {
			return true
		}
	}
	if body == "" {
		return false
	}
	var v any
	if json.Unmarshal([]byte(body), &v) != nil {
		return false
	}
	return jsonCarriesBusiness(v, true)
}

func jsonCarriesBusiness(v any, top bool) bool {
	switch x := v.(type) {
	case []any:
		return true
	case map[string]any:
		for _, k := range []string{"list", "records", "rows", "items", "total", "page"} {
			if _, ok := x[k]; ok {
				return true
			}
		}
		if top {
			for _, wrap := range []string{"body", "data", "result"} {
				if inner, ok := x[wrap]; ok && jsonCarriesBusiness(inner, false) {
					return true
				}
			}
		}
	}
	return false
}

// looksLikeTelemetry reports fire-and-forget responses: empty or tiny, 204, or not JSON.
func looksLikeTelemetry(q *ReqRecord) bool {
	m := strings.ToUpper(strings.TrimSpace(q.Method))
	if m != "POST" && m != "GET" {
		return false
	}
	if q.Status == 204 {
		return true
	}
	if len(q.RespBody) <= 64 {
		return true
	}
	mime := strings.ToLower(q.RespMime)
	if strings.Contains(mime, "json") {
		return false
	}
	t := strings.TrimSpace(q.RespBody)
	if (strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[")) && json.Valid([]byte(t)) {
		return false
	}
	return true
}

// classifyRecorded applies a noise_override learned from an earlier request in
// the same templated (method, host, path) group.
func (a *App) classifyRecorded(q *ReqRecord) (bool, string) {
	noise, why := ClassifyNoise(q)
	if a == nil || a.store == nil || q == nil || q.RecordingID == 0 {
		return noise, why
	}
	ov, ok, err := a.store.NoiseOverrideForGroup(q.RecordingID, q.Method, q.URL, q.Seq, q.ID)
	if err != nil || !ok {
		return noise, why
	}
	return ov, "沿用之前的标注"
}
