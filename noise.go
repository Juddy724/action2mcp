package main

import (
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

var analyticsPath = regexp.MustCompile(`(?i)(^|/)(collect|track|tracking|analytics|beacon|telemetry|metrics|stat|stats|log|logs|logging|monitor|sentry|perf|rum|gtag|pixel|event-log|__log|apm)(/|$|\?|\.)`)

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
	case "Ping":
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
	if analyticsPath.MatchString(p) {
		return true, "埋点/日志"
	}
	if strings.HasPrefix(q.RespMime, "image/") || strings.HasPrefix(q.RespMime, "font/") || q.RespMime == "text/css" {
		return true, "静态资源"
	}
	if q.ResourceType == "Document" && q.Method == "GET" {
		return true, "页面加载"
	}
	if q.Method == "GET" && basePath.MatchString(p) {
		return true, "基础配置/用户信息"
	}
	if q.Status == 0 || q.Status >= 300 && q.Status < 400 {
		return true, "未完成或重定向"
	}
	return false, ""
}
