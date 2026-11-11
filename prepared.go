package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type RequestPreview struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

type ApprovalPreview struct {
	Preview     RequestPreview `json:"preview"`
	PreviewHash string         `json:"preview_hash"`
}

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
	deferrable := isRefName(name)
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
			b = compactJSON(value)
		}
		value = string(b[1 : len(b)-1])
	}
	return value
}

type PreparedCall struct {
	Preview      RequestPreview `json:"preview"`
	PreviewHash  string         `json:"preview_hash"`
	request      RequestPreview
	subs         []credentialSubstitution
	credHeaders  []string
	secretValues []string
	ws           bool
	wsMessages   []string
	wsSQL        string
	wsConfig     ToolConfig
	configErr    error
	wsStats      *wsSessionStats
}

func replaceRequest(r RequestPreview, replace func(string) string) RequestPreview {
	h := make(map[string]string, len(r.Headers))
	for k, v := range r.Headers {
		h[k] = replace(v)
	}
	return RequestPreview{r.Method, replace(r.URL), h, replace(r.Body)}
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
		Request     RequestPreview
		References  []string
		CredHeaders []string
		Messages    []string
		SQL         string
		Guard       bool
		MaxRows     int
	}{r, locations, p.credHeaders, msgs, p.wsSQL, p.wsConfig.sqlGuardEnabled(), p.wsConfig.maxRows()})
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func (p *PreparedCall) resolve(resolve func(string) (string, error)) (RequestPreview, error) {
	pairs := []string{}
	values := map[string]string{}
	for _, sub := range p.subs {
		value, ok := values[sub.ref]
		if !ok {
			var err error
			value, err = resolve(sub.ref)
			if err != nil {
				return RequestPreview{}, err
			}
			values[sub.ref] = value
		}
		pairs = append(pairs, sub.token, sub.encoding.encode(value))
	}
	return replaceRequest(p.request, strings.NewReplacer(pairs...).Replace), nil
}

func (a *App) Prepare(t *Tool, args map[string]any) (*PreparedCall, error) {
	if t != nil && t.mwID != 0 {
		tool, mw, ds, err := a.refreshSQLConsoleTool(t, args)
		if err != nil {
			return nil, err
		}
		t = tool
		_ = mw
		_ = ds
	}
	analysis := analyzeApprovalTemplate(t)
	secrets := a.approvalSecretValues(t, args)
	at := time.Now()
	if a.prepareNow != nil {
		at = a.prepareNow()
	}
	vals, err := t.bindValues(args, nil, nil, true, at)
	if err != nil {
		return nil, fmt.Errorf("%s", a.scrubApprovalText(err.Error(), secrets))
	}
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return nil, err
	}
	d := &deferredCredentials{prefix: "A2M" + hex.EncodeToString(random[:]) + "REF", deferName: func(n string) bool { return isServerRef(n, isWSMethod(t.Method)) }}
	method, u, headers, body, err := t.renderValues(vals, d)
	if err != nil {
		return nil, err
	}
	p := &PreparedCall{request: RequestPreview{method, u, headers, body}, subs: d.subs, credHeaders: append([]string(nil), t.CredHeaders...)}
	if err := a.freezeWSCall(t, vals, d, p); err != nil {
		return nil, fmt.Errorf("%s", a.scrubApprovalText(err.Error(), secrets))
	}
	p.subs = d.subs
	p.PreviewHash = p.fingerprint()
	p.secretValues = append(secrets, a.approvalSecretValues(t, vals)...)
	displayVals := make(map[string]any, len(vals))
	maskedParams := map[string]bool{}
	for name, value := range vals {
		displayVals[name] = value
	}
	for _, param := range t.Params {
		if a.paramIsSecret(t, param, vals[param.Name]) {
			if v := argString(vals[param.Name]); v != "" {
				p.secretValues = append(p.secretValues, v)
			}
			displayVals[param.Name] = secretMask
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
	p.Preview = replaceRequest(RequestPreview{method, u, headers, body}, replacer.Replace)
	if p.ws && p.wsSQL != "" {
		p.Preview.Body = p.wsSQL
		if len(p.wsMessages) > 0 {
			// Preview keeps credential placeholders; SQL is the user-facing payload.
		}
	}
	p.Preview = a.scrubApprovalPreview(p.Preview, p.secretValues)
	// An over-limit template cannot establish safe literal boundaries.
	if analysis.limitedURL {
		p.Preview.URL = secretMask
	}
	if analysis.limitedBody {
		p.Preview.Body = secretMask
	}
	for key, limited := range analysis.limitedHeaders {
		if limited {
			p.Preview.Headers[key] = secretMask
		}
	}
	if t.mwID != 0 {
		if mw, err := a.store.GetMiddleware(t.mwID); err == nil {
			alias := t.mwAlias
			if a := argStr(args, "database"); strings.TrimSpace(a) != "" {
				alias = a
			}
			ds, _ := mw.lookupDatasource(alias)
			redactSQLConsolePreview(p, mw, alias, ds.secretValues(&mw.Config))
			p.Preview = a.scrubApprovalPreview(p.Preview, p.secretValues)
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
				out.Write(compactJSON(m[0]))
				i += len(m[0])
				continue
			}
		}
		out.WriteByte(body[i])
		i++
	}
	return out.String()
}
