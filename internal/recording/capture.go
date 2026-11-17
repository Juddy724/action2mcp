package recording

import (
	"action2mcp/internal/cdp"
	"errors"
	"sync"
)

// CaptureRepository is the recorder's persistence port. It never receives browser handles.
type Repository interface {
	InsertRequest(*Request) error
	UpdateRequest(*Request) error
}

// CaptureHooks supplies application policy and the two CDP body-fetch commands.
// Nil hooks use deterministic no-op defaults for isolated/offline event capture.
type Hooks struct {
	Classify             func(*Request) (bool, string)
	TrackHarvestHop      func(string, string)
	HarvestRequestHeader func(string, string, string, string) error
	Ignored              func(string) bool
	Command              func(string, string, any, any) error
}

type Capture struct {
	mu         sync.Mutex
	rec        *activeRecording
	repository Repository
	hooks      Hooks
}

type Stats struct {
	Count  int
	Useful int
}

func New(repository Repository, hooks Hooks) *Capture {
	if hooks.Classify == nil {
		hooks.Classify = func(*Request) (bool, string) { return false, "" }
	}
	if hooks.TrackHarvestHop == nil {
		hooks.TrackHarvestHop = func(string, string) {}
	}
	if hooks.HarvestRequestHeader == nil {
		hooks.HarvestRequestHeader = func(string, string, string, string) error { return nil }
	}
	if hooks.Ignored == nil {
		hooks.Ignored = func(string) bool { return false }
	}
	if hooks.Command == nil {
		hooks.Command = func(string, string, any, any) error { return errors.New("capture body transport unavailable") }
	}
	return &Capture{repository: repository, hooks: hooks}
}

func (c *Capture) Start(id int64, name string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rec = &activeRecording{id: id, name: name, pending: map[string]*pendingReq{}}
}

func (c *Capture) ActiveName() (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.rec == nil {
		return "", false
	}
	return c.rec.name, true
}

// HandleEvent accepts a CDP network event. It does not launch a browser.
func (c *Capture) HandleEvent(ev cdp.Event) {
	switch ev.Method {
	case "Network.requestWillBeSent":
		c.onRequest(ev)
	case "Network.requestWillBeSentExtraInfo":
		c.onExtraInfo(ev)
	case "Network.responseReceived":
		c.onResponse(ev)
	case "Network.loadingFinished":
		c.onFinished(ev, false)
	case "Network.loadingFailed":
		c.onFinished(ev, true)
	case "Network.webSocketCreated":
		c.onWSCreated(ev)
	case "Network.webSocketWillSendHandshakeRequest":
		c.onWSHandshake(ev)
	case "Network.webSocketHandshakeResponseReceived":
		c.onWSHandshakeResponse(ev)
	case "Network.webSocketFrameSent":
		c.onWSFrame(ev, true)
	case "Network.webSocketFrameReceived":
		c.onWSFrame(ev, false)
	case "Network.webSocketClosed":
		c.onWSClosed(ev)
	case "Network.webSocketFrameError":
		c.onWSError(ev)
	}
}

func captureTruncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "\n…[已截断]"
	}
	return s
}
