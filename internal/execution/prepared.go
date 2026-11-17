package execution

import (
	"action2mcp/internal/credential"
	"action2mcp/internal/domain"
	"action2mcp/internal/vault"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Encodings describe template locations, never text supplied by the caller.
type credentialEncoding struct {
	query      bool
	jsonLayers int
	escapeHTML bool
}

type credentialSubstitution struct {
	token, ref string
	encoding   credentialEncoding
}

type deferredCredentials struct {
	prefix       string
	subs         []credentialSubstitution
	preview      bool
	maskedParams map[string]bool
	deferName    func(string) bool
}

func renderValue(vals map[string]any, name string, d *deferredCredentials, enc credentialEncoding) any {
	deferrable := credential.IsRefName(name)
	if d != nil && d.deferName != nil {
		deferrable = d.deferName(name)
	}
	if d == nil || !deferrable {
		return vals[name]
	}
	token := fmt.Sprintf("%s%dEND", d.prefix, len(d.subs))
	d.subs = append(d.subs, credentialSubstitution{token, name, enc})
	return token
}

func (e credentialEncoding) encode(value string) string {
	if e.query {
		return url.QueryEscape(value)
	}
	for i := 0; i < e.jsonLayers; i++ {
		var b []byte
		if e.escapeHTML {
			b, _ = json.Marshal(value)
		} else {
			b = CompactJSON(value)
		}
		value = string(b[1 : len(b)-1])
	}
	return value
}

type PreparedCall struct {
	Preview      domain.RequestPreview `json:"preview"`
	PreviewHash  string                `json:"preview_hash"`
	request      domain.RequestPreview
	subs         []credentialSubstitution
	credHeaders  []string
	secretValues []string
	configValues []string // datasource ids / env values: token-boundary hide, not result substring scrub
	ws           bool
	wsMessages   []string
	wsSQL        string
	wsConfig     ToolConfig
	presentCfg   ToolConfig // result_format / selector / detect_failure snapshot (HTTP and WS)
	configErr    error
	wsStats      *wsSessionStats
}

func replaceRequest(r domain.RequestPreview, replace func(string) string) domain.RequestPreview {
	h := make(map[string]string, len(r.Headers))
	for k, v := range r.Headers {
		h[k] = replace(v)
	}
	return domain.RequestPreview{Method: r.Method, URL: replace(r.URL), Headers: h, Body: replace(r.Body)}
}

func (p *PreparedCall) fingerprint() string {
	// Stable tokens bind both the reference's origin and its encoding context.
	pairs := []string{}
	locations := []string{}
	for i, sub := range p.subs {
		pairs = append(pairs, sub.token, fmt.Sprintf("A2MCREDENTIAL%dEND", i))
		locations = append(locations, fmt.Sprintf("%s:%t:%d:%t", sub.ref, sub.encoding.query, sub.encoding.jsonLayers, sub.encoding.escapeHTML))
	}
	replacer := strings.NewReplacer(pairs...)
	r := replaceRequest(p.request, replacer.Replace)
	msgs := make([]string, len(p.wsMessages))
	for i, m := range p.wsMessages {
		msgs[i] = replacer.Replace(m)
	}
	b, _ := json.Marshal(struct {
		Request     domain.RequestPreview
		References  []string
		CredHeaders []string
		Messages    []string
		SQL         string
		Guard       bool
		MaxRows     int
	}{r, locations, p.credHeaders, msgs, p.wsSQL, p.wsConfig.SqlGuardEnabled(), p.wsConfig.MaxRows()})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (p *PreparedCall) resolve(resolve func(string) (string, error)) (domain.RequestPreview, error) {
	pairs := []string{}
	values := map[string]string{}
	for _, sub := range p.subs {
		value, ok := values[sub.ref]
		if !ok {
			var err error
			value, err = resolve(sub.ref)
			if err != nil {
				return domain.RequestPreview{}, err
			}
			values[sub.ref] = value
		}
		pairs = append(pairs, sub.token, sub.encoding.encode(value))
	}
	return replaceRequest(p.request, strings.NewReplacer(pairs...).Replace), nil
}

func (a *Engine) Prepare(t *Tool, args map[string]any) (*PreparedCall, error) {
	if t != nil && t.mwID != 0 {
		tool, err := a.console.Refresh(t, args)
		if err != nil {
			return nil, err
		}
		t = tool
	}
	analysis := analyzeApprovalTemplate(t)
	secrets := a.ApprovalSecretValues(t, args)
	at := time.Now()
	if a.prepareNow != nil {
		at = a.prepareNow()
	}
	vals, err := t.bindValues(args, nil, nil, true, at)
	if err != nil {
		return nil, fmt.Errorf("%s", a.ScrubApprovalText(err.Error(), secrets))
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	d := &deferredCredentials{prefix: "A2M" + hex.EncodeToString(random[:]) + "REF", deferName: func(n string) bool { return credential.IsServerRef(n, IsWSMethod(t.Method)) }}
	method, u, headers, body, err := t.renderValues(vals, d)
	if err != nil {
		return nil, err
	}
	p := &PreparedCall{request: domain.RequestPreview{Method: method, URL: u, Headers: headers, Body: body}, subs: d.subs, credHeaders: append([]string(nil), t.CredHeaders...), presentCfg: presentationFields(t.Config)}
	if err := a.freezeWSCall(t, vals, d, p); err != nil {
		return nil, fmt.Errorf("%s", a.ScrubApprovalText(err.Error(), secrets))
	}
	p.subs = d.subs
	p.PreviewHash = p.fingerprint()
	p.secretValues = append(secrets, a.ApprovalSecretValues(t, vals)...)
	displayVals := make(map[string]any, len(vals))
	maskedParams := map[string]bool{}
	for name, value := range vals {
		displayVals[name] = value
	}
	for _, param := range t.Params {
		if a.ParamIsSecret(t, param, vals[param.Name]) {
			if v := domain.ArgumentText(vals[param.Name]); v != "" {
				p.secretValues = append(p.secretValues, v)
			}
			displayVals[param.Name] = vault.Mask
			maskedParams[param.Name] = true
		}
	}
	display := &deferredCredentials{prefix: d.prefix, preview: true, maskedParams: maskedParams, deferName: d.deferName}
	method, u, headers, body, err = t.renderValues(displayVals, display)
	if err != nil {
		return nil, err
	}
	pairs := []string{}
	for _, sub := range display.subs {
		pairs = append(pairs, sub.token, "{{"+sub.ref+"}}")
	}
	replacer := strings.NewReplacer(pairs...)
	p.Preview = replaceRequest(domain.RequestPreview{Method: method, URL: u, Headers: headers, Body: body}, replacer.Replace)
	if p.ws && p.wsSQL != "" {
		p.Preview.Body = p.wsSQL
		if len(p.wsMessages) > 0 {
			// Preview keeps credential placeholders; SQL is the user-facing payload.
		}
	}
	p.Preview = a.ScrubApprovalPreview(p.Preview, p.secretValues)
	// An over-limit template cannot establish safe literal boundaries.
	if analysis.limitedURL {
		p.Preview.URL = vault.Mask
	}
	if analysis.limitedBody {
		p.Preview.Body = vault.Mask
	}
	for key, limited := range analysis.limitedHeaders {
		if limited {
			p.Preview.Headers[key] = vault.Mask
		}
	}
	if t.mwID != 0 {
		if name, alias, hide, ok := a.console.Preview(t, args); ok {
			p.RedactConsole(name, alias, hide)
			p.Preview = a.ScrubApprovalPreview(p.Preview, p.secretValues)
		}
	}
	return p, nil
}

// Keep masks valid as JSON values without adding quotes inside JSON strings.
// Only the display render calls this; execution retains its legacy rendering.
func quotePreviewJSONMasks(body string, maskedParams map[string]bool) string {
	var out strings.Builder
	for i := 0; i < len(body); {
		if body[i] == '"' {
			_, end := approvalTemplateToken(body, i)
			out.WriteString(body[i:end])
			i = end
			continue
		}
		if strings.HasPrefix(body[i:], "{{") {
			if m := placeholderRe.FindStringSubmatch(body[i:]); m != nil && strings.HasPrefix(body[i:], m[0]) && maskedParams[m[1]] {
				out.Write(CompactJSON(m[0]))
				i += len(m[0])
				continue
			}
		}
		out.WriteByte(body[i])
		i++
	}
	return out.String()
}

// Fingerprint binds the frozen request and credential locations, never the mutable display.
func (p *PreparedCall) Fingerprint() string { return p.fingerprint() }

// ScrubPrepared applies a call's private redaction snapshot without exposing secret lists.
func (e *Engine) ScrubPrepared(text string, p *PreparedCall, isError bool) string {
	text = e.ScrubApprovalText(text, p.secretValues)
	if isError {
		text = vault.ScrubConfigTokens(text, p.configValues)
	}
	return text
}

// ReviewPreview preserves the prior redaction policy when previewing or confirming edits.
// Confirmation carries history into the new immutable execution snapshot.
func (e *Engine) ReviewPreview(p, prior *PreparedCall, confirm bool) {
	if confirm {
		p.secretValues = append(p.secretValues, prior.secretValues...)
		p.configValues = append(p.configValues, prior.configValues...)
		prior = p
	}
	p.Preview = e.ScrubApprovalPreview(p.Preview, prior.secretValues)
	p.Preview = ScrubPreviewConfigTokens(p.Preview, prior.configValues)
}
func (e *Engine) PreparedParams(t *Tool, args map[string]any, p *PreparedCall) []domain.Param {
	return e.ApprovalParams(t, args, p.secretValues)
}

func (p *PreparedCall) RedactConsole(name, alias string, configValues []string) {
	if p == nil {
		return
	}
	p.configValues = append(p.configValues, configValues...)
	p.Preview.URL = fmt.Sprintf("WebSocket SQL 控制台「%s」 / %s", name, alias)
	p.Preview.Method = "WS"
	if p.wsSQL != "" {
		p.Preview.Body = p.wsSQL
	}
	for k, v := range p.Preview.Headers {
		if strings.Contains(v, "{{") {
			continue
		}
		p.Preview.Headers[k] = vault.Mask
	}
	p.Preview = scrubPreviewSecrets(p.Preview, p.secretValues)
	p.Preview = ScrubPreviewConfigTokens(p.Preview, p.configValues)
}

func scrubPreviewSecrets(prev domain.RequestPreview, secrets []string) domain.RequestPreview {
	return mapPreviewText(prev, func(s string) string { return vault.ScrubSecretText(s, nil, secrets) })
}

func ScrubPreviewConfigTokens(prev domain.RequestPreview, values []string) domain.RequestPreview {
	return mapPreviewText(prev, func(s string) string { return vault.ScrubConfigTokens(s, values) })
}

func mapPreviewText(prev domain.RequestPreview, mask func(string) string) domain.RequestPreview {
	h := map[string]string{}
	for k, v := range prev.Headers {
		h[k] = mask(v)
	}
	return domain.RequestPreview{Method: prev.Method, URL: mask(prev.URL), Headers: h, Body: mask(prev.Body)}
}
