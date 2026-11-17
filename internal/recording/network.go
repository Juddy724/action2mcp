package recording

import (
	"action2mcp/internal/cdp"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"
)

type activeRecording struct {
	id      int64
	name    string
	seq     int
	pending map[string]*pendingReq // key sessionId|requestId
	wg      sync.WaitGroup
	count   int
	useful  int
	stopped bool
}

type pendingReq struct {
	rec      *Request
	hasPost  bool
	ws       bool
	session  string
	reqID    string
	extraHdr map[string]string

	wsSent     []Frame
	wsRecv     []Frame
	wsState    string
	wsErr      string
	wsSentCut  bool
	wsRecvCut  bool
	wsFlush    time.Time
	wsNoise    bool
	wsInserted bool
}

type Frame struct {
	TS    string `json:"ts"`
	Op    int    `json:"op"`
	Text  string `json:"text,omitempty"`
	Bytes int    `json:"bytes,omitempty"`
}

type Envelope struct {
	V         int     `json:"v"`
	State     string  `json:"state,omitempty"`
	Error     string  `json:"error,omitempty"`
	Truncated bool    `json:"truncated,omitempty"`
	Frames    []Frame `json:"frames"`
}

// WebSocket is recorded from Network.webSocket* events, not as this HTTP upgrade request.
var recordTypes = map[string]bool{"XHR": true, "Fetch": true, "Document": true, "Ping": true, "Other": true, "EventSource": true, "Script": true, "Stylesheet": true, "Image": true, "Font": true}

var bodyTypes = map[string]bool{"XHR": true, "Fetch": true, "Document": true, "Other": true, "EventSource": true}

const MaxBody = 256 * 1024

func key(s, r string) string { return s + "|" + r }

func (bs *Capture) onRequest(ev cdp.Event) {
	var p struct {
		RequestID string `json:"requestId"`
		Type      string `json:"type"`
		Request   struct {
			URL             string         `json:"url"`
			Method          string         `json:"method"`
			Headers         map[string]any `json:"headers"`
			PostData        string         `json:"postData"`
			HasPostData     bool           `json:"hasPostData"`
			PostDataEntries []struct {
				Bytes string `json:"bytes"`
			} `json:"postDataEntries"`
		} `json:"request"`
		RedirectResponse *struct {
			Status int `json:"status"`
		} `json:"redirectResponse"`
	}
	json.Unmarshal(ev.Params, &p)
	hdrEarly := map[string]string{}
	for hk, hv := range p.Request.Headers {
		hdrEarly[hk] = fmt.Sprint(hv)
	}
	if p.Request.URL != "" && !strings.HasPrefix(p.Request.URL, "data:") && !strings.HasPrefix(p.Request.URL, "chrome") {
		rk := key(ev.SessionID, p.RequestID)
		bs.hooks.TrackHarvestHop(rk, p.Request.URL)
		for hk, hv := range hdrEarly {
			_ = bs.hooks.HarvestRequestHeader(rk, p.Request.URL, hk, hv)
		}
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	rec := bs.rec
	if rec == nil || rec.stopped {
		return
	}
	if bs.hooks.Ignored(ev.SessionID) {
		return
	}
	if strings.HasPrefix(p.Request.URL, "data:") || strings.HasPrefix(p.Request.URL, "chrome") || strings.HasPrefix(p.Request.URL, "devtools:") || strings.HasPrefix(p.Request.URL, "blob:") {
		return
	}
	if !recordTypes[p.Type] && p.Type != "" {
		return
	}
	k := key(ev.SessionID, p.RequestID)
	if old, ok := rec.pending[k]; ok && p.RedirectResponse != nil {
		// redirect: finalize previous hop
		old.rec.Status = p.RedirectResponse.Status
		bs.storeLocked(rec, old)
		delete(rec.pending, k)
	}
	body := p.Request.PostData
	if body == "" && len(p.Request.PostDataEntries) > 0 {
		var sb strings.Builder
		for _, e := range p.Request.PostDataEntries {
			if b, err := base64.StdEncoding.DecodeString(e.Bytes); err == nil {
				sb.Write(b)
			}
		}
		body = sb.String()
	}
	hdr := map[string]string{}
	for k, v := range p.Request.Headers {
		hdr[k] = fmt.Sprint(v)
	}
	rec.seq++
	pr := &pendingReq{session: ev.SessionID, reqID: p.RequestID, hasPost: p.Request.HasPostData && body == "", rec: &Request{
		RecordingID: rec.id, Seq: rec.seq, Method: p.Request.Method, URL: p.Request.URL, ResourceType: p.Type,
		ReqHeaders: hdr, ReqBody: captureTruncate(body, MaxBody), TS: time.Now().Format("15:04:05.000"),
	}}
	rec.pending[k] = pr
}

func (bs *Capture) onExtraInfo(ev cdp.Event) {
	var p struct {
		RequestID string         `json:"requestId"`
		Headers   map[string]any `json:"headers"`
	}
	json.Unmarshal(ev.Params, &p)
	rk := key(ev.SessionID, p.RequestID)
	for hk, hv := range p.Headers {
		if strings.HasPrefix(hk, ":") {
			continue
		}
		_ = bs.hooks.HarvestRequestHeader(rk, "", hk, fmt.Sprint(hv))
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.rec == nil {
		return
	}
	if pr, ok := bs.rec.pending[rk]; ok {
		for k, v := range p.Headers {
			if strings.HasPrefix(k, ":") {
				continue
			}
			pr.rec.ReqHeaders[k] = fmt.Sprint(v)
		}
	}
}

func (bs *Capture) onResponse(ev cdp.Event) {
	var p struct {
		RequestID string `json:"requestId"`
		Type      string `json:"type"`
		Response  struct {
			Status   int            `json:"status"`
			Headers  map[string]any `json:"headers"`
			MimeType string         `json:"mimeType"`
		} `json:"response"`
	}
	json.Unmarshal(ev.Params, &p)
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.rec == nil {
		return
	}
	if pr, ok := bs.rec.pending[key(ev.SessionID, p.RequestID)]; ok {
		pr.rec.Status = p.Response.Status
		pr.rec.RespMime = p.Response.MimeType
		h := map[string]string{}
		for k, v := range p.Response.Headers {
			h[k] = fmt.Sprint(v)
		}
		pr.rec.RespHeaders = h
		if p.Type != "" {
			pr.rec.ResourceType = p.Type
		}
	}
}

func (bs *Capture) onFinished(ev cdp.Event, failed bool) {
	var p struct {
		RequestID string `json:"requestId"`
		ErrorText string `json:"errorText"`
	}
	json.Unmarshal(ev.Params, &p)
	bs.mu.Lock()
	rec := bs.rec
	if rec == nil {
		bs.mu.Unlock()
		return
	}
	k := key(ev.SessionID, p.RequestID)
	pr, ok := rec.pending[k]
	if !ok {
		bs.mu.Unlock()
		return
	}
	delete(rec.pending, k)
	rec.wg.Add(1)
	bs.mu.Unlock()
	go func() {
		defer rec.wg.Done()
		if failed {
			if pr.rec.RespBody == "" {
				pr.rec.RespBody = "[请求失败] " + p.ErrorText
			}
		} else {
			if pr.hasPost {
				var r struct {
					PostData string `json:"postData"`
				}
				if bs.hooks.Command(pr.session, "Network.getRequestPostData", map[string]any{"requestId": pr.reqID}, &r) == nil {
					pr.rec.ReqBody = captureTruncate(r.PostData, MaxBody)
				}
			}
			if bodyTypes[pr.rec.ResourceType] && pr.rec.Method != "OPTIONS" {
				var r struct {
					Body          string `json:"body"`
					Base64Encoded bool   `json:"base64Encoded"`
				}
				if bs.hooks.Command(pr.session, "Network.getResponseBody", map[string]any{"requestId": pr.reqID}, &r) == nil {
					if r.Base64Encoded {
						if b, err := base64.StdEncoding.DecodeString(r.Body); err == nil && isText(pr.rec.RespMime) {
							pr.rec.RespBody = captureTruncate(string(b), MaxBody)
						} else {
							pr.rec.RespBody = fmt.Sprintf("[二进制内容 %d 字节]", len(r.Body)*3/4)
						}
					} else {
						pr.rec.RespBody = captureTruncate(r.Body, MaxBody)
					}
				}
			}
		}
		bs.mu.Lock()
		bs.storeLocked(rec, pr)
		bs.mu.Unlock()
	}()
}

func isText(m string) bool {
	return strings.HasPrefix(m, "text/") || strings.Contains(m, "json") || strings.Contains(m, "xml") || strings.Contains(m, "javascript")
}

func (bs *Capture) storeLocked(rec *activeRecording, pr *pendingReq) {
	pr.rec.Noise, pr.rec.NoiseReason = bs.hooks.Classify(pr.rec)
	if err := bs.repository.InsertRequest(pr.rec); err != nil {
		log.Printf("保存请求失败: %v", err)
		return
	}
	rec.count++
	if !pr.rec.Noise {
		rec.useful++
	}
}

// A WebSocket connection is one recording row. Frames stay in memory as JSON
// envelopes and are flushed on a short interval. The recording page renders them;
// saving a middleware copies the URL only, never these frames.
func (bs *Capture) onWSCreated(ev cdp.Event) {
	var p struct {
		RequestID string `json:"requestId"`
		URL       string `json:"url"`
	}
	json.Unmarshal(ev.Params, &p)
	bs.mu.Lock()
	defer bs.mu.Unlock()
	bs.wsPending(ev.SessionID, p.RequestID, p.URL, true)
}

func (bs *Capture) onWSHandshake(ev cdp.Event) {
	var p struct {
		RequestID string `json:"requestId"`
		Request   struct {
			Headers map[string]any `json:"headers"`
		} `json:"request"`
	}
	json.Unmarshal(ev.Params, &p)
	bs.mu.Lock()
	defer bs.mu.Unlock()
	rec := bs.rec
	pr := bs.wsPending(ev.SessionID, p.RequestID, "", false)
	if pr == nil || rec == nil {
		return
	}
	for k, v := range p.Request.Headers {
		if strings.HasPrefix(k, ":") {
			continue
		}
		pr.rec.ReqHeaders[k] = fmt.Sprint(v)
	}
	rk := key(ev.SessionID, p.RequestID)
	if pr.rec.URL != "" {
		bs.hooks.TrackHarvestHop(rk, pr.rec.URL)
		for k, v := range pr.rec.ReqHeaders {
			_ = bs.hooks.HarvestRequestHeader(rk, pr.rec.URL, k, v)
		}
	}
	if err := bs.persistWSLocked(rec, pr, true); err != nil {
		log.Printf("保存 WebSocket 握手失败: %v", err)
	}
}

func (bs *Capture) onWSHandshakeResponse(ev cdp.Event) {
	var p struct {
		RequestID string `json:"requestId"`
		Response  struct {
			Status  int            `json:"status"`
			Headers map[string]any `json:"headers"`
		} `json:"response"`
	}
	json.Unmarshal(ev.Params, &p)
	bs.mu.Lock()
	defer bs.mu.Unlock()
	rec := bs.rec
	pr := bs.wsPending(ev.SessionID, p.RequestID, "", false)
	if pr == nil || rec == nil {
		return
	}
	// Status is 101 only when the handshake succeeded. A missing or failed
	// handshake stays 0 so it is classified as 未完成. The HTTP code is kept
	// on the receive envelope.
	for k, v := range p.Response.Headers {
		pr.rec.RespHeaders[k] = fmt.Sprint(v)
	}
	if p.Response.Status == 101 {
		pr.rec.Status = 101
		pr.wsState = "open"
	} else if p.Response.Status != 0 {
		pr.wsState = "error"
		if pr.wsErr == "" {
			pr.wsErr = fmt.Sprintf("HTTP %d", p.Response.Status)
		}
	}
	if err := bs.persistWSLocked(rec, pr, true); err != nil {
		log.Printf("保存 WebSocket 握手失败: %v", err)
	}
}

func (bs *Capture) onWSFrame(ev cdp.Event, sent bool) {
	var p struct {
		RequestID string `json:"requestId"`
		Response  struct {
			Opcode      int    `json:"opcode"`
			PayloadData string `json:"payloadData"`
		} `json:"response"`
	}
	json.Unmarshal(ev.Params, &p)
	frame, ok := wsCaptureFrame(p.Response.Opcode, p.Response.PayloadData)
	if !ok {
		return
	}
	bs.mu.Lock()
	defer bs.mu.Unlock()
	rec := bs.rec
	pr := bs.wsPending(ev.SessionID, p.RequestID, "", false)
	if pr == nil || rec == nil {
		return
	}
	pr.addWSFrame(sent, frame)
	if err := bs.persistWSLocked(rec, pr, false); err != nil {
		log.Printf("保存 WebSocket 帧失败: %v", err)
	}
}

func (bs *Capture) onWSClosed(ev cdp.Event) {
	var p struct {
		RequestID string `json:"requestId"`
	}
	json.Unmarshal(ev.Params, &p)
	bs.mu.Lock()
	defer bs.mu.Unlock()
	rec := bs.rec
	if rec == nil {
		return
	}
	k := key(ev.SessionID, p.RequestID)
	pr := rec.pending[k]
	if pr == nil || !pr.ws {
		return
	}
	pr.wsState = "closed"
	if err := bs.persistWSLocked(rec, pr, true); err != nil {
		log.Printf("保存 WebSocket 关闭失败: %v", err)
		return
	}
	delete(rec.pending, k)
}

func (bs *Capture) onWSError(ev cdp.Event) {
	var p struct {
		RequestID    string `json:"requestId"`
		ErrorMessage string `json:"errorMessage"`
	}
	json.Unmarshal(ev.Params, &p)
	bs.mu.Lock()
	defer bs.mu.Unlock()
	rec := bs.rec
	pr := bs.wsPending(ev.SessionID, p.RequestID, "", false)
	if pr == nil || rec == nil {
		return
	}
	pr.wsState = "error"
	pr.wsErr = clipWSErr(p.ErrorMessage)
	if err := bs.persistWSLocked(rec, pr, true); err != nil {
		log.Printf("保存 WebSocket 错误失败: %v", err)
	}
}

// wsPending returns the in-progress WebSocket row. A row is created only for
// webSocketCreated with a real ws:// or wss:// URL. Caller holds bs.mu.
func (bs *Capture) wsPending(session, requestID, rawURL string, create bool) *pendingReq {
	rec := bs.rec
	if rec == nil || rec.stopped || requestID == "" {
		return nil
	}
	if bs.hooks.Ignored(session) {
		return nil
	}
	k := key(session, requestID)
	if pr, ok := rec.pending[k]; ok {
		return pr
	}
	if !create || !validWSURL(rawURL) {
		return nil
	}
	rec.seq++
	pr := &pendingReq{ws: true, session: session, reqID: requestID, rec: &Request{
		RecordingID: rec.id, Seq: rec.seq, Method: "WS", URL: rawURL, ResourceType: "WebSocket",
		ReqHeaders: map[string]string{}, RespHeaders: map[string]string{},
		TS: time.Now().Format("15:04:05.000"),
	}}
	rec.pending[k] = pr
	return pr
}

func validWSURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return false
	}
	return u.Scheme == "ws" || u.Scheme == "wss"
}

// persistWSLocked writes the JSON envelopes. force is set for handshake, close,
// error, and stop. Other frames flush at most once per 500ms. Caller holds bs.mu.
// On failure the pending row is left in place.
func (bs *Capture) persistWSLocked(rec *activeRecording, pr *pendingReq, force bool) error {
	if rec == nil || pr == nil || pr.rec == nil {
		return nil
	}
	if !force && !pr.wsFlush.IsZero() && time.Since(pr.wsFlush) < 500*time.Millisecond {
		return nil
	}
	sent, sentCut := fitWSFrames(pr.wsSent, pr.wsSentCut, "", "")
	recv, recvCut := fitWSFrames(pr.wsRecv, pr.wsRecvCut, pr.wsState, pr.wsErr)
	pr.wsSent, pr.wsSentCut = sent, sentCut
	pr.wsRecv, pr.wsRecvCut = recv, recvCut
	sb, err := json.Marshal(NewEnvelope(pr.wsSent, pr.wsSentCut, "", ""))
	if err != nil {
		return err
	}
	rb, err := json.Marshal(NewEnvelope(pr.wsRecv, pr.wsRecvCut, pr.wsState, pr.wsErr))
	if err != nil {
		return err
	}
	pr.rec.ReqBody = string(sb)
	pr.rec.RespBody = string(rb)
	noise, why := bs.hooks.Classify(pr.rec)
	pr.rec.Noise, pr.rec.NoiseReason = noise, why
	if pr.rec.ID == 0 {
		if err := bs.repository.InsertRequest(pr.rec); err != nil {
			return err
		}
		pr.wsInserted = true
		pr.wsNoise = noise
		rec.count++
		if !noise {
			rec.useful++
		}
	} else {
		if err := bs.repository.UpdateRequest(pr.rec); err != nil {
			return err
		}
		if pr.wsNoise != noise {
			if pr.wsNoise && !noise {
				rec.useful++
			} else if !pr.wsNoise && noise && rec.useful > 0 {
				rec.useful--
			}
			pr.wsNoise = noise
		}
	}
	pr.wsFlush = time.Now()
	return nil
}

func NewEnvelope(frames []Frame, cut bool, state, errMsg string) Envelope {
	if frames == nil {
		frames = []Frame{}
	}
	return Envelope{V: 1, State: state, Error: errMsg, Truncated: cut, Frames: frames}
}

// fitWSFrames drops whole frames from the end until the marshalled envelope fits.
func fitWSFrames(frames []Frame, cut bool, state, errMsg string) ([]Frame, bool) {
	if frames == nil {
		frames = []Frame{}
	} else {
		frames = append([]Frame{}, frames...)
	}
	for {
		b, err := json.Marshal(NewEnvelope(frames, cut, state, errMsg))
		if err == nil && len(b) <= MaxBody {
			return frames, cut
		}
		if len(frames) == 0 {
			return frames, true
		}
		frames = frames[:len(frames)-1]
		cut = true
	}
}

// wsMetaReserve is the largest close/error metadata a later flush can add.
// Frames are accepted only when they still fit with this reserve and with
// truncated:true, so a later flush does not have to drop an earlier frame.
func wsMetaReserve(sent bool) (state, errMsg string) {
	if sent {
		return "", ""
	}
	return "closed", strings.Repeat("\x01", 512)
}

func wsFramesFit(frames []Frame, sent bool) bool {
	state, errMsg := wsMetaReserve(sent)
	b, err := json.Marshal(NewEnvelope(frames, true, state, errMsg))
	return err == nil && len(b) <= MaxBody
}

func (pr *pendingReq) addWSFrame(sent bool, f Frame) {
	if (sent && pr.wsSentCut) || (!sent && pr.wsRecvCut) {
		return
	}
	cur := pr.wsRecv
	if sent {
		cur = pr.wsSent
	}
	next := append(append([]Frame{}, cur...), f)
	if !wsFramesFit(next, sent) {
		if sent {
			pr.wsSentCut = true
		} else {
			pr.wsRecvCut = true
		}
		return
	}
	if sent {
		pr.wsSent = next
	} else {
		pr.wsRecv = next
	}
}

func wsCaptureFrame(opcode int, data string) (Frame, bool) {
	f := Frame{TS: time.Now().Format("15:04:05.000"), Op: opcode}
	switch opcode {
	case 1:
		f.Text = data
		return f, true
	case 2:
		f.Bytes = wsBinaryLen(data)
		return f, true
	default:
		return Frame{}, false
	}
}

func wsBinaryLen(data string) int {
	if data == "" {
		return 0
	}
	if b, err := base64.StdEncoding.DecodeString(data); err == nil {
		return len(b)
	}
	if b, err := base64.RawStdEncoding.DecodeString(data); err == nil {
		return len(b)
	}
	return 0
}

func clipWSErr(s string) string {
	if len(s) <= 512 {
		return s
	}
	return s[:512]
}

// FinishRecording stops capturing and returns the recording stats.
func (bs *Capture) FinishRecording() *Stats {
	bs.mu.Lock()
	rec := bs.rec
	if rec == nil {
		bs.mu.Unlock()
		return nil
	}
	rec.stopped = true
	bs.mu.Unlock()
	// wait for in-flight body fetches (bounded)
	done := make(chan struct{})
	go func() { rec.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	bs.mu.Lock()
	for k, pr := range rec.pending {
		if pr.ws {
			if err := bs.persistWSLocked(rec, pr, true); err != nil {
				if err2 := bs.persistWSLocked(rec, pr, true); err2 != nil {
					log.Printf("结束录制时保存 WebSocket 失败: %v", err2)
				}
			}
		} else if pr.rec.Status != 0 {
			bs.storeLocked(rec, pr)
		}
		delete(rec.pending, k)
	}
	bs.rec = nil
	stats := &Stats{Count: rec.count, Useful: rec.useful}
	bs.mu.Unlock()
	return stats
}

func (bs *Capture) RecordingStats() (int, int) {
	bs.mu.Lock()
	defer bs.mu.Unlock()
	if bs.rec == nil {
		return 0, 0
	}
	return bs.rec.count, bs.rec.useful
}
