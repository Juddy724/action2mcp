package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResp struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcErr         `json:"error,omitempty"`
}

var supportedProtocols = []string{"2025-06-18", "2025-03-26", "2024-11-05"}

// mcpCtx carries per-request state through dispatch.
type mcpCtx struct {
	sess  *mcpSession
	notes [][]byte // server->client notifications produced while handling the request
}

func (c *mcpCtx) notifyToolsChanged() {
	c.notes = append(c.notes, notificationJSON("notifications/tools/list_changed"))
}

func (a *App) handleMCP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	trim := strings.TrimSpace(string(body))
	var reqs []rpcReq
	batch := strings.HasPrefix(trim, "[")
	if batch {
		err = json.Unmarshal(body, &reqs)
	} else {
		var one rpcReq
		err = json.Unmarshal(body, &one)
		reqs = []rpcReq{one}
	}
	if err != nil {
		writeJSON(w, 400, rpcResp{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcErr{-32700, "Parse error"}})
		return
	}
	var out []rpcResp
	sid := r.Header.Get("Mcp-Session-Id")
	mc := &mcpCtx{}
	for _, q := range reqs {
		if q.Method == "initialize" {
			sid = randID()
			w.Header().Set("Mcp-Session-Id", sid)
			var p struct {
				ClientInfo struct {
					Name    string `json:"name"`
					Version string `json:"version"`
				} `json:"clientInfo"`
			}
			json.Unmarshal(q.Params, &p)
			s := a.session(sid)
			s.mu.Lock()
			s.client = strings.TrimSpace(p.ClientInfo.Name + " " + p.ClientInfo.Version)
			s.mu.Unlock()
		}
		mc.sess = a.session(sid)
		if h := r.Header.Get("X-A2M-Client"); h != "" {
			mc.sess.mu.Lock()
			if mc.sess.client == "" {
				mc.sess.client = h
			}
			mc.sess.mu.Unlock()
		}
		res, e := a.dispatchMCP(r.Context(), q, mc)
		if len(q.ID) == 0 || string(q.ID) == "null" {
			continue // notification or response from client
		}
		resp := rpcResp{JSONRPC: "2.0", ID: q.ID}
		if e != nil {
			resp.Error = e
		} else {
			resp.Result = res
		}
		out = append(out, resp)
	}
	// Deliver notifications: on the session's GET SSE stream if one is open, otherwise inline in this
	// POST response as SSE (when the client accepts it). Clients that support neither still get the
	// tool definitions inside the load_pack result.
	var inline [][]byte
	for _, n := range mc.notes {
		if mc.sess == nil || !mc.sess.push(n) {
			inline = append(inline, n)
		}
	}
	if len(out) == 0 {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var payload any = out[0]
	if batch {
		payload = out
	}
	if len(inline) > 0 && strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.WriteHeader(200)
		for _, n := range inline {
			fmt.Fprintf(w, "event: message\ndata: %s\n\n", n)
		}
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", compactJSON(payload))
		return
	}
	writeJSON(w, 200, payload)
}

func compactJSON(v any) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	return bytes.TrimSpace(buf.Bytes())
}

func textResult(text string, isErr bool) map[string]any {
	return map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isErr}
}

const instrCommon = "这些工具来自用户在浏览器中录制的真实业务操作（Action2MCP）。调用时会自动带上用户在专用浏览器里的登录态；登录过期时会按「登录中心」的配置自动重新登录（企业微信单点登录或配置管理里保存的账号）。流程包里如果加入了中间件（数据库 / Redis / 消息队列），会提供 db_query、redis_command、mq_send 等通用工具，参数 middleware 指定要操作哪一个；每个中间件的权限（增删改查等）由用户在控制台配置，未开启的权限会返回「无权限」错误，请不要尝试绕过。连接信息和密码不会提供给你。"

const instrTiered = "工具按「流程包」分组、按需加载（阶梯式）：1) 先调用 list_packs 查看有哪些流程包及适用场景；2) 按当前任务选一个包，调用 load_pack 加载。返回里的 guide 是这个包的使用说明，有内容时先按它确定工具顺序和参数来源，再调用工具；工具的名称、说明和参数也在这次返回里，并会出现在工具列表里；3) 如果你的工具列表没有刷新出来，用 call_pack_tool(tool, arguments) 调用；4) 用完可调用 unload_pack 卸载。Tools are grouped into packs and loaded on demand: call list_packs first, pick a pack, load_pack it, read its guide when present, then call its tools (or use call_pack_tool if your tool list does not refresh). "

func (a *App) dispatchMCP(ctx context.Context, q rpcReq, mc *mcpCtx) (any, *rpcErr) {
	switch q.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(q.Params, &p)
		ver := supportedProtocols[0]
		for _, v := range supportedProtocols {
			if v == p.ProtocolVersion {
				ver = v
			}
		}
		instr := "只暴露当前在控制台中开启的流程包里的工具。" + instrCommon
		if a.mcpMode() == ModeTiered {
			instr = instrTiered + instrCommon
		} else {
			instr += a.flatPackGuides()
		}
		return map[string]any{
			"protocolVersion": ver,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": true}},
			"serverInfo":      map[string]any{"name": "action2mcp", "title": "Action2MCP", "version": Version},
			"instructions":    instr,
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": a.toolList(mc.sess)}, nil
	case "tools/call":
		var p struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if err := json.Unmarshal(q.Params, &p); err != nil {
			return nil, &rpcErr{-32602, "invalid params"}
		}
		if p.Arguments == nil {
			p.Arguments = map[string]any{}
		}
		if a.mcpMode() == ModeTiered {
			switch p.Name {
			case "list_packs":
				return a.mcpListPacks(mc), nil
			case "load_pack":
				return a.mcpLoadPack(mc, p.Arguments), nil
			case "unload_pack":
				return a.mcpUnloadPack(mc, p.Arguments), nil
			case "call_pack_tool":
				name := strings.TrimSpace(argStr(p.Arguments, "tool"))
				args, err := argObject(p.Arguments["arguments"])
				if err != nil {
					return textResult("arguments 必须是 JSON 对象（按 load_pack 返回的 inputSchema 填写）："+err.Error(), true), nil
				}
				if name == "" {
					return textResult("请提供 tool（工具名，来自 load_pack 的返回结果）", true), nil
				}
				if isEntryTool(name) {
					return textResult(name+" 是入口工具，请直接调用它，不要通过 call_pack_tool。", true), nil
				}
				res, rerr := a.invokeTool(ctx, mc, name, args)
				if rerr != nil {
					return textResult(rerr.Message, true), nil
				}
				return res, nil
			}
		}
		return a.invokeTool(ctx, mc, p.Name, p.Arguments)
	case "resources/list":
		return map[string]any{"resources": []any{}}, nil
	case "resources/templates/list":
		return map[string]any{"resourceTemplates": []any{}}, nil
	case "prompts/list":
		return map[string]any{"prompts": []any{}}, nil
	case "logging/setLevel":
		return map[string]any{}, nil
	}
	if strings.HasPrefix(q.Method, "notifications/") {
		return nil, nil
	}
	return nil, &rpcErr{-32601, "Method not found: " + q.Method}
}

// argObject accepts an object, a JSON string holding an object (some agents stringify), or nothing.
func argObject(v any) (map[string]any, error) {
	switch x := v.(type) {
	case nil:
		return map[string]any{}, nil
	case map[string]any:
		return x, nil
	case string:
		if strings.TrimSpace(x) == "" {
			return map[string]any{}, nil
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(x), &m); err != nil {
			return nil, err
		}
		if m == nil {
			m = map[string]any{}
		}
		return m, nil
	}
	return nil, fmt.Errorf("类型 %T", v)
}

// invokeTool runs a recorded tool or a middleware tool. It is lenient: the tool only has to belong to
// a pack that is enabled in the console (being loaded in this session is NOT required). The console
// toggle is the security boundary; load_pack only controls what is advertised in tools/list.
func (a *App) invokeTool(ctx context.Context, mc *mcpCtx, name string, args map[string]any) (any, *rpcErr) {
	client := "未知客户端"
	if mc.sess != nil {
		client = mc.sess.clientName()
	}
	if _, ok := isMWTool(name); ok {
		text, isErr := a.callMWTool(ctx, client, name, args)
		return textResult(text, isErr), nil
	}
	tools, _ := a.store.ExposedTools()
	var t *Tool
	for _, x := range tools {
		if x.Name == name {
			t = x
		}
	}
	if t == nil {
		msg := fmt.Sprintf("工具 %s 不存在或所在流程包未开启", name)
		if a.mcpMode() == ModeTiered {
			msg += "。请先调用 list_packs 查看可用流程包，再用 load_pack 加载，按返回的工具名调用。"
		}
		return nil, &rpcErr{-32602, msg}
	}
	res, err := a.Execute(t, args)
	if err != nil {
		return textResult("调用失败："+err.Error(), true), nil
	}
	if res.Error != "" {
		return textResult("请求失败："+res.Error, true), nil
	}
	text := fmt.Sprintf("HTTP %d\n%s", res.Status, res.Body)
	if res.Relogged {
		text = "（登录已过期，已自动重新登录并重试）\n" + text
	}
	if res.Status == 401 {
		text += "\n\n[提示] 目标网站返回未登录，自动登录也没有成功。请让用户在 Action2MCP 控制台「登录中心」检查登录配置或点击「打开浏览器登录」后再试。"
	} else if res.Status == 403 {
		text += "\n\n[提示] 目标网站返回无权限（403）。已经尝试过重新登录，可能是当前账号没有这个操作的权限。"
	}
	return textResult(text, res.Status >= 400), nil
}

// ---------- tool lists ----------

var entryToolNames = []string{"list_packs", "load_pack", "unload_pack", "call_pack_tool"}

func isEntryTool(n string) bool {
	for _, x := range entryToolNames {
		if x == n {
			return true
		}
	}
	return false
}

func entryToolDefs() []map[string]any {
	obj := func(props map[string]any, req ...string) map[string]any {
		m := map[string]any{"type": "object", "properties": props}
		if len(req) > 0 {
			m["required"] = req
		}
		return m
	}
	return []map[string]any{
		{"name": "list_packs", "title": "列出流程包",
			"description": "【第一步 Step 1】列出当前可用的流程包（每个包是一组围绕某项业务的工具，例如「禅道记工时」「客服查单」）。拿到任务后先调用它，根据 description / scenarios（适用场景）/ tool_names 选出和任务相关的包，再调用 load_pack 加载。不要一次加载所有包。\nList the available tool packs first; pick the pack(s) that match your current task, then call load_pack.",
			"inputSchema": obj(map[string]any{}),
			"annotations": map[string]any{"readOnlyHint": true}},
		{"name": "load_pack", "title": "加载流程包",
			"description": "【第二步 Step 2】加载一个流程包：返回 guide（使用说明）、该包所有工具的名称、说明和参数 schema（inputSchema），同时把这些工具加入你的工具列表（服务器会发送 notifications/tools/list_changed）。guide 不是空的时候，先按它确定调用顺序和参数从哪来，再调用工具。如果工具列表没有出现它们，用 call_pack_tool 调用。\nLoad a pack by name or id. The result contains guide plus tools (name, description, inputSchema). When guide is not empty, follow it before calling tools. Tools are added to tools/list; if your client does not refresh, use call_pack_tool.",
			"inputSchema": obj(map[string]any{"pack": map[string]any{"type": "string", "description": "流程包名称或 id（来自 list_packs）/ pack name or id"}}, "pack")},
		{"name": "unload_pack", "title": "卸载流程包",
			"description": "任务完成或换任务时卸载流程包，把它的工具从工具列表中移除，保持上下文干净。不填 pack 表示卸载全部。\nUnload a pack (or all packs when pack is empty) to keep your context small.",
			"inputSchema": obj(map[string]any{"pack": map[string]any{"type": "string", "description": "流程包名称或 id；留空 = 全部 / empty = all"}})},
		{"name": "call_pack_tool", "title": "调用包内工具（兜底）",
			"description": "【兜底 Fallback】按工具名调用已开启流程包里的工具（包括 db_query、redis_command 等中间件工具）。当 load_pack 之后你的工具列表里没有出现新工具时使用；arguments 按 load_pack 返回的 inputSchema 填写。权限、自动登录等规则与直接调用完全相同。\nCall a pack tool by name when your client did not refresh its tool list after load_pack. arguments must follow the tool's inputSchema.",
			"inputSchema": obj(map[string]any{
				"tool":      map[string]any{"type": "string", "description": "工具名（来自 load_pack 的返回）/ tool name"},
				"arguments": map[string]any{"type": "object", "description": "工具参数 / tool arguments", "additionalProperties": true},
			}, "tool")},
	}
}

// recordedToolDefs turns recorded tools into MCP tool entries.
func (a *App) recordedToolDefs(tools []*Tool, packNames map[int64][]string, skipReserved bool) []map[string]any {
	list := []map[string]any{}
	for _, t := range tools {
		if _, ok := isMWTool(t.Name); ok {
			continue // built-in middleware tool names take precedence
		}
		if skipReserved && isEntryTool(t.Name) {
			continue
		}
		desc := strings.TrimSpace(t.Description)
		if desc == "" {
			desc = t.Title
		} else if t.Title != "" && !strings.Contains(desc, t.Title) {
			desc = t.Title + "：" + desc
		}
		if ps := packNames[t.ID]; len(ps) > 0 {
			desc += "（流程包：" + strings.Join(ps, "、") + "）"
		}
		item := map[string]any{"name": t.Name, "description": desc, "inputSchema": t.InputSchema()}
		if t.Title != "" {
			item["title"] = t.Title
		}
		list = append(list, item)
	}
	return list
}

// toolList is what tools/list returns for a session.
func (a *App) toolList(sess *mcpSession) []map[string]any {
	if a.mcpMode() == ModeFlat {
		tools, _ := a.store.ExposedTools()
		list := a.recordedToolDefs(tools, a.packNamesByTool(), false)
		return append(list, a.mwToolList()...)
	}
	list := entryToolDefs()
	if sess == nil {
		return list
	}
	loaded := sess.loadedIDs()
	if len(loaded) == 0 {
		return list
	}
	packs, _ := a.store.ListPacks()
	sel := []*Pack{}
	for _, p := range packs {
		if p.Enabled && loaded[p.ID] {
			sel = append(sel, p)
		}
	}
	return append(list, a.packToolDefs(sel)...)
}

// packToolDefs returns the MCP tool entries (recorded + middleware) for the given packs.
func (a *App) packToolDefs(packs []*Pack) []map[string]any {
	toolIDs := map[int64]bool{}
	mwIDs := map[int64]bool{}
	for _, p := range packs {
		for _, id := range p.ToolIDs {
			toolIDs[id] = true
		}
		for _, id := range p.MiddlewareIDs {
			mwIDs[id] = true
		}
	}
	all, _ := a.store.ExposedTools()
	tools := []*Tool{}
	for _, t := range all {
		if toolIDs[t.ID] {
			tools = append(tools, t)
		}
	}
	list := a.recordedToolDefs(tools, a.packNamesByTool(), true)
	ms, names := a.store.ExposedMiddleware()
	sel := []*Middleware{}
	for _, m := range ms {
		if mwIDs[m.ID] {
			sel = append(sel, m)
		}
	}
	return append(list, a.mwToolListFor(sel, names)...)
}

func (a *App) packNamesByTool() map[int64][]string {
	out := map[int64][]string{}
	packs, _ := a.store.ListPacks()
	for _, p := range packs {
		if !p.Enabled {
			continue
		}
		for _, id := range p.ToolIDs {
			out[id] = append(out[id], p.Name)
		}
	}
	return out
}

// ---------- entry tools ----------

// findEnabledPack resolves a pack by id or name among enabled packs.
func (a *App) findEnabledPack(ref string) (*Pack, []*Pack) {
	ref = strings.TrimSpace(ref)
	packs, _ := a.store.ListPacks()
	en := []*Pack{}
	for _, p := range packs {
		if p.Enabled {
			en = append(en, p)
		}
	}
	if id, err := strconv.ParseInt(ref, 10, 64); err == nil {
		for _, p := range en {
			if p.ID == id {
				return p, en
			}
		}
	}
	for _, p := range en {
		if p.Name == ref {
			return p, en
		}
	}
	for _, p := range en {
		if strings.EqualFold(p.Name, ref) {
			return p, en
		}
	}
	return nil, en
}

func packNameList(ps []*Pack) string {
	n := []string{}
	for _, p := range ps {
		n = append(n, fmt.Sprintf("%s(id=%d)", p.Name, p.ID))
	}
	if len(n) == 0 {
		return "（当前没有开启的流程包，请让用户在 Action2MCP 控制台开启）"
	}
	return strings.Join(n, "、")
}

func (a *App) mcpListPacks(mc *mcpCtx) any {
	packs, _ := a.store.ListPacks()
	tools, _ := a.store.ExposedTools()
	tname := map[int64]string{}
	for _, t := range tools {
		tname[t.ID] = t.Name
	}
	mws, _ := a.store.ListMiddleware()
	mwByID := map[int64]*Middleware{}
	for _, m := range mws {
		mwByID[m.ID] = m
	}
	loaded := mc.sess.loadedIDs()
	type packOut struct {
		ID          int64    `json:"id"`
		Name        string   `json:"name"`
		Description string   `json:"description,omitempty"`
		Scenarios   string   `json:"scenarios,omitempty"`
		ToolCount   int      `json:"tool_count"`
		ToolNames   []string `json:"tool_names,omitempty"`
		Middleware  []string `json:"middleware,omitempty"`
		Loaded      bool     `json:"loaded"`
	}
	out := []packOut{}
	for _, p := range packs {
		if !p.Enabled {
			continue
		}
		po := packOut{ID: p.ID, Name: p.Name, Description: strings.TrimSpace(p.Description), Scenarios: strings.TrimSpace(p.Scenarios), Loaded: loaded[p.ID]}
		for _, id := range p.ToolIDs {
			if n, ok := tname[id]; ok {
				po.ToolNames = append(po.ToolNames, n)
			}
		}
		mwTools := map[string]bool{}
		for _, id := range p.MiddlewareIDs {
			if m := mwByID[id]; m != nil {
				po.Middleware = append(po.Middleware, m.Name+"("+m.kindLabel()+")")
				for _, d := range mwToolDefs() {
					if d.Type == m.Type {
						mwTools[d.Name] = true
					}
				}
			}
		}
		po.ToolCount = len(po.ToolNames) + len(mwTools)
		if len(po.ToolNames) > 12 {
			po.ToolNames = append(po.ToolNames[:12], fmt.Sprintf("…等 %d 个", len(po.ToolNames)))
		}
		out = append(out, po)
	}
	next := "根据当前任务选择相关的流程包，调用 load_pack(pack=名称或id) 加载后再使用其中的工具。Pick the pack(s) relevant to your task and call load_pack."
	if len(out) == 0 {
		next = "当前没有开启的流程包。请让用户在 Action2MCP 控制台「流程包」页开启需要的流程包。No pack is enabled; ask the user to enable one in the Action2MCP console."
	}
	return textResult(string(compactJSON(map[string]any{"packs": out, "next": next})), false)
}

type toolBrief struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

func (a *App) mcpLoadPack(mc *mcpCtx, args map[string]any) any {
	ref := argStr(args, "pack")
	if strings.TrimSpace(ref) == "" {
		ref = argStr(args, "name")
	}
	if strings.TrimSpace(ref) == "" {
		ref = argStr(args, "id")
	}
	p, en := a.findEnabledPack(ref)
	if p == nil {
		return textResult(fmt.Sprintf("流程包「%s」不存在或未开启。可用的流程包：%s。请先调用 list_packs。", ref, packNameList(en)), true)
	}
	mc.sess.mu.Lock()
	changed := !mc.sess.loaded[p.ID]
	mc.sess.loaded[p.ID] = true
	mc.sess.mu.Unlock()
	if changed {
		mc.notifyToolsChanged()
	}
	defs := a.packToolDefs([]*Pack{p})
	briefs := []toolBrief{}
	for _, d := range defs {
		briefs = append(briefs, toolBrief{Name: d["name"].(string), Description: d["description"].(string), InputSchema: d["inputSchema"]})
	}
	loadedNames := a.loadedPackNames(mc.sess)
	guide := a.packGuideText(p)
	next := "这些工具已加入你的工具列表，可直接按名称调用；如果你的工具列表里没有它们，用 call_pack_tool(tool=工具名, arguments={...}) 调用。用完可 unload_pack。These tools are now in tools/list; if your client does not show them, use call_pack_tool."
	if guide != "" {
		next = "先按 guide 里的顺序和参数来源调用工具，不要只凭工具名猜测。这些工具已加入你的工具列表；如果列表里没有它们，用 call_pack_tool(tool=工具名, arguments={...}) 调用。用完可 unload_pack。Read guide before calling tools. If your client does not show them, use call_pack_tool."
	}
	if len(briefs) == 0 {
		next = "这个流程包里还没有工具。请让用户在控制台把工具加入该流程包。"
	}
	res := map[string]any{
		"loaded":       p.Name,
		"pack_id":      p.ID,
		"guide":        guide,
		"tools":        briefs,
		"loaded_packs": loadedNames,
		"next":         next,
	}
	return textResult(string(compactJSON(res)), false)
}

// packGuideText is the pack guide as the model should see it. Secret values are masked.
// {{secret.name}} references are left as written and are not resolved.
func (a *App) packGuideText(p *Pack) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(a.vault.Scrub(p.Guide))
}

// flatPackGuides appends each enabled pack's guide to the flat-mode connection instructions.
func (a *App) flatPackGuides() string {
	packs, _ := a.store.ListPacks()
	var b strings.Builder
	for _, p := range packs {
		if p == nil || !p.Enabled {
			continue
		}
		g := a.packGuideText(p)
		if g == "" {
			continue
		}
		fmt.Fprintf(&b, "\n\n## 流程包「%s」(id=%d) 使用说明\n%s", p.Name, p.ID, g)
	}
	if b.Len() == 0 {
		return ""
	}
	return "\n\n以下是已开启流程包的使用说明。调用其中的工具前，先按对应说明确定顺序和参数来源。" + b.String()
}

func (a *App) loadedPackNames(s *mcpSession) []string {
	loaded := s.loadedIDs()
	packs, _ := a.store.ListPacks()
	out := []string{}
	for _, p := range packs {
		if p.Enabled && loaded[p.ID] {
			out = append(out, p.Name)
		}
	}
	sort.Strings(out)
	return out
}

func (a *App) mcpUnloadPack(mc *mcpCtx, args map[string]any) any {
	ref := strings.TrimSpace(argStr(args, "pack"))
	if ref == "" {
		ref = strings.TrimSpace(argStr(args, "name"))
	}
	s := mc.sess
	if ref == "" || ref == "*" || ref == "all" {
		s.mu.Lock()
		n := len(s.loaded)
		s.loaded = map[int64]bool{}
		s.mu.Unlock()
		if n > 0 {
			mc.notifyToolsChanged()
		}
		return textResult(`{"unloaded":"全部 / all","loaded_packs":[]}`, false)
	}
	// resolve among all packs (a pack disabled after loading can still be unloaded)
	packs, _ := a.store.ListPacks()
	var p *Pack
	id, idErr := strconv.ParseInt(ref, 10, 64)
	for _, x := range packs {
		if (idErr == nil && x.ID == id) || x.Name == ref || strings.EqualFold(x.Name, ref) {
			p = x
			break
		}
	}
	if p == nil {
		return textResult(fmt.Sprintf("流程包「%s」不存在。当前已加载：%s", ref, strings.Join(a.loadedPackNames(s), "、")), true)
	}
	s.mu.Lock()
	was := s.loaded[p.ID]
	delete(s.loaded, p.ID)
	s.mu.Unlock()
	if was {
		mc.notifyToolsChanged()
	}
	return textResult(string(compactJSON(map[string]any{"unloaded": p.Name, "was_loaded": was, "loaded_packs": a.loadedPackNames(s)})), false)
}
