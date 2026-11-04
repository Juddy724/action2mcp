// harness: drives the Action2MCP dedicated browser over CDP like a user would
// (real mouse clicks / keyboard input), as a second DevTools client.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"action2mcp/internal/cdp"
)

var profile = flag.String("profile", "", "browser profile dir (contains DevToolsActivePort)")

func die(f string, a ...any) { fmt.Fprintf(os.Stderr, "harness: "+f+"\n", a...); os.Exit(1) }

func connect(ctx context.Context) *cdp.Conn {
	var b []byte
	var err error
	for i := 0; i < 50; i++ {
		b, err = os.ReadFile(filepath.Join(*profile, "DevToolsActivePort"))
		if err == nil {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil {
		die("no DevToolsActivePort: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	c, err := cdp.Dial(ctx, "ws://127.0.0.1:"+lines[0]+lines[1])
	if err != nil {
		die("dial: %v", err)
	}
	go func() {
		for range c.Events() {
		}
	}()
	return c
}

type target struct {
	TargetID string `json:"targetId"`
	Type     string `json:"type"`
	URL      string `json:"url"`
	Title    string `json:"title"`
}

func pages(ctx context.Context, c *cdp.Conn) []target {
	var r struct {
		TargetInfos []target `json:"targetInfos"`
	}
	if err := c.Call(ctx, "", "Target.getTargets", nil, &r); err != nil {
		die("getTargets: %v", err)
	}
	var out []target
	for _, t := range r.TargetInfos {
		if t.Type == "page" && !strings.HasPrefix(t.URL, "devtools://") {
			out = append(out, t)
		}
	}
	return out
}

func attach(ctx context.Context, c *cdp.Conn) (string, target) {
	ps := pages(ctx, c)
	if m := os.Getenv("HARNESS_MATCH"); m != "" {
		var f []target
		for _, p := range ps {
			if strings.Contains(p.URL, m) {
				f = append(f, p)
			}
		}
		ps = f
	}
	if len(ps) == 0 {
		die("no page")
	}
	var r struct {
		SessionID string `json:"sessionId"`
	}
	if err := c.Call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": ps[0].TargetID, "flatten": true}, &r); err != nil {
		die("attach: %v", err)
	}
	return r.SessionID, ps[0]
}

func eval(ctx context.Context, c *cdp.Conn, s, js string) (any, error) {
	var r struct {
		Result struct {
			Value any `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text      string `json:"text"`
			Exception struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	err := c.Call(ctx, s, "Runtime.evaluate", map[string]any{"expression": js, "returnByValue": true, "awaitPromise": true, "userGesture": true}, &r)
	if err != nil {
		return nil, err
	}
	if r.ExceptionDetails != nil {
		return nil, fmt.Errorf("js: %s %s", r.ExceptionDetails.Text, r.ExceptionDetails.Exception.Description)
	}
	return r.Result.Value, nil
}

func clickAt(ctx context.Context, c *cdp.Conn, s string, rectJS string) {
	v, err := eval(ctx, c, s, `(function(){var e=`+rectJS+`; if(!e) return null; e.scrollIntoView&&e.scrollIntoView({block:'center'}); var r=e.getBoundingClientRect(); return [r.left+r.width/2, r.top+r.height/2];})()`)
	if err != nil || v == nil {
		die("element not found for click: %s (%v)", rectJS, err)
	}
	xy := v.([]any)
	x, y := xy[0].(float64), xy[1].(float64)
	for _, typ := range []string{"mouseMoved", "mousePressed", "mouseReleased"} {
		p := map[string]any{"type": typ, "x": x, "y": y, "button": "left", "clickCount": 1}
		if typ == "mouseMoved" {
			p["button"] = "none"
		}
		if err := c.Call(ctx, s, "Input.dispatchMouseEvent", p, nil); err != nil {
			// browser may close in response to the click (e.g. overlay stop) — that's fine
			fmt.Println("click: (connection ended after", typ+")")
			return
		}
	}
	fmt.Printf("clicked at (%.0f,%.0f)\n", x, y)
}

func main() {
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		die("usage: harness -profile DIR pages|eval JS|wait JS SECS|nav URL|type SEL TEXT|click SEL|click-overlay|overlay-visible|close-page")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	c := connect(ctx)
	defer c.Close()
	switch args[0] {
	case "pages":
		b, _ := json.MarshalIndent(pages(ctx, c), "", "  ")
		fmt.Println(string(b))
	case "eval":
		s, _ := attach(ctx, c)
		v, err := eval(ctx, c, s, args[1])
		if err != nil {
			die("%v", err)
		}
		b, _ := json.Marshal(v)
		fmt.Println(string(b))
	case "wait":
		s, _ := attach(ctx, c)
		var secs float64 = 15
		if len(args) > 2 {
			fmt.Sscan(args[2], &secs)
		}
		deadline := time.Now().Add(time.Duration(secs * float64(time.Second)))
		for {
			v, err := eval(ctx, c, s, args[1])
			if err == nil && v != nil && v != false && v != "" && v != float64(0) {
				b, _ := json.Marshal(v)
				fmt.Println("ok:", string(b))
				return
			}
			if time.Now().After(deadline) {
				die("timeout waiting for %s (last=%v err=%v)", args[1], v, err)
			}
			time.Sleep(250 * time.Millisecond)
		}
	case "nav":
		s, _ := attach(ctx, c)
		if err := c.Call(ctx, s, "Page.navigate", map[string]any{"url": args[1]}, nil); err != nil {
			die("nav: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
		for i := 0; i < 60; i++ {
			v, _ := eval(ctx, c, s, `document.readyState==='complete' ? location.href : ''`)
			if v != nil && v != "" {
				fmt.Println("loaded:", v)
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
		die("page did not load")
	case "type":
		s, _ := attach(ctx, c)
		clickAt(ctx, c, s, `document.querySelector(`+jsq(args[1])+`)`)
		if err := c.Call(ctx, s, "Input.insertText", map[string]any{"text": args[2]}, nil); err != nil {
			die("insertText: %v", err)
		}
		fmt.Println("typed", args[2])
	case "click":
		s, _ := attach(ctx, c)
		clickAt(ctx, c, s, `document.querySelector(`+jsq(args[1])+`)`)
	case "overlay-visible":
		s, _ := attach(ctx, c)
		v, err := eval(ctx, c, s, `(function(){var h=document.getElementById('__a2m_overlay'); if(!h||!h.shadowRoot) return null; var b=h.shadowRoot.querySelector('#stop'); var r=b.getBoundingClientRect(); return {text:h.shadowRoot.textContent.replace(/\s+/g,' ').slice(-40), w:r.width, h:r.height, x:r.left, y:r.top, vw:innerWidth, vh:innerHeight};})()`)
		if err != nil {
			die("%v", err)
		}
		b, _ := json.Marshal(v)
		fmt.Println(string(b))
	case "click-overlay":
		s, _ := attach(ctx, c)
		clickAt(ctx, c, s, `(document.getElementById('__a2m_overlay')||{}).shadowRoot && document.getElementById('__a2m_overlay').shadowRoot.querySelector('#stop')`)
	case "close-page":
		for _, p := range pages(ctx, c) {
			c.Call(ctx, "", "Target.closeTarget", map[string]any{"targetId": p.TargetID}, nil)
			fmt.Println("closed", p.URL)
		}
	case "screenshot":
		s, _ := attach(ctx, c)
		var r struct {
			Data []byte `json:"data"`
		}
		if err := c.Call(ctx, s, "Page.captureScreenshot", map[string]any{"format": "png"}, &r); err != nil {
			die("%v", err)
		}
		os.WriteFile(args[1], r.Data, 0644)
		fmt.Println("saved", args[1])
	default:
		die("unknown command %s", args[0])
	}
}

func jsq(s string) string { b, _ := json.Marshal(s); return string(b) }
