// Package mcpserver is the Streamable-HTTP MCP adapter: JSON-RPC framing, flat/tiered discovery and tools/call routing.
package mcpserver

import (
	"action2mcp/internal/analysis"
	"action2mcp/internal/approval"
	"action2mcp/internal/execution"
	"action2mcp/internal/flow"
	"action2mcp/internal/invoke"
	"action2mcp/internal/mcp"
	"action2mcp/internal/mwconfig"
	"action2mcp/internal/mwtools"
	"action2mcp/internal/store"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// mcpRepository is the catalog surface the MCP server reads.
type Repository interface {
	ExposedMiddleware() ([]*mwconfig.Middleware, map[int64][]string)
	ExposedTools() ([]*execution.Tool, error)
	GetSetting(key, def string) string
	GetTool(id int64) (*execution.Tool, error)
	ListMiddleware() ([]*mwconfig.Middleware, error)
	ListPacks() ([]*store.Pack, error)
}

type Options struct {
	Version     string
	Repository  Repository
	Sessions    *mcp.Manager
	Engine      func() *execution.Engine
	Analysis    func() *analysis.Service
	Middlewares func() *mwtools.Service
	Approvals   func() *invoke.Gateway
	Flow        func() *flow.Executor
}

// mcpServer is the Streamable-HTTP MCP adapter: JSON-RPC framing, discovery
// (flat and tiered packs) and tools/call routing through the approval gate.
type Server struct {
	version     string
	repo        Repository
	sessions    *mcp.Manager
	engine      func() *execution.Engine
	analysis    func() *analysis.Service
	middlewares func() *mwtools.Service
	approvals   func() *invoke.Gateway
	flow        func() *flow.Executor
}

func New(o Options) *Server {
	return &Server{version: o.Version, repo: o.Repository, sessions: o.Sessions, engine: o.Engine, analysis: o.Analysis, middlewares: o.Middlewares, approvals: o.Approvals, flow: o.Flow}
}

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

const instrCommon = "这些工具来自用户在浏览器中录制的真实业务操作（Action2MCP）。调用时会自动带上用户在专用浏览器里的登录态；登录过期时会按「登录中心」的配置自动重新登录（企业微信单点登录或配置管理里保存的账号）。流程包里如果加入了中间件（数据库 / Redis / 消息队列），会提供 db_query、redis_command、mq_send 等通用工具，参数 middleware 指定要操作哪一个；每个中间件的权限（增删改查等）由用户在控制台配置，未开启的权限会返回「无权限」错误，请不要尝试绕过。需要审批的工具在调用时必须在参数 operation_note 中备注操作解释说明与影响分析（说明本次操作要做什么、为什么执行，以及会对业务数据或系统产生什么影响），供用户在控制台待审批列表中核对。连接信息和密码不会提供给你。"

const instrTiered = "工具按「流程包」分组、按需加载（阶梯式）：1) 先调用 list_packs 查看有哪些流程包及适用场景；2) 按当前任务选一个包，调用 load_pack 加载。返回里的 guide 是这个包的使用说明，有内容时先按它确定工具顺序和参数来源，再调用工具；工具的名称、说明和参数也在这次返回里，并会出现在工具列表里；3) 如果你的工具列表没有刷新出来，用 call_pack_tool(tool, arguments) 调用；4) 用完可调用 unload_pack 卸载。Tools are grouped into packs and loaded on demand: call list_packs first, pick a pack, load_pack it, read its guide when present, then call its tools (or use call_pack_tool if your tool list does not refresh). "

func formatMCPCallResult(prefix string, res *execution.CallResult, err error) (string, bool) {
	if err != nil {
		return prefix + "调用失败：" + err.Error(), true
	}
	if res != nil && res.Outcome != "" {
		text := res.Body
		if res.Error != "" && res.Outcome != execution.OutcomeSuccess {
			text = execution.FirstNonEmpty(res.Error, res.Body)
		}
		if res.Relogged {
			text = "（登录已过期，已自动重新登录并重试）\n" + text
		}
		return prefix + text, res.Outcome != execution.OutcomeSuccess
	}
	if res != nil && res.Error != "" {
		return prefix + "请求失败：" + res.Error, true
	}
	status := 0
	body := ""
	relogged := false
	if res != nil {
		status = res.Status
		body = res.Body
		relogged = res.Relogged
	}
	text := fmt.Sprintf("HTTP %d\n%s", status, body)
	if relogged {
		text = "（登录已过期，已自动重新登录并重试）\n" + text
	}
	if status == 401 {
		text += "\n\n[提示] 目标网站返回未登录，自动登录也没有成功。请让用户在 Action2MCP 控制台「登录中心」检查登录配置或点击「打开浏览器登录」后再试。"
	} else if status == 403 {
		text += "\n\n[提示] 目标网站返回无权限（403）。已经尝试过重新登录，可能是当前账号没有这个操作的权限。"
	}
	return prefix + text, status >= 400
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
			"annotations": mcp.Annotations(true, false, true)},
		{"name": "load_pack", "title": "加载流程包",
			"description": "【第二步 Step 2】加载一个流程包：返回 guide（使用说明）、该包所有工具的名称、说明和参数 schema（inputSchema），同时把这些工具加入你的工具列表（服务器会发送 notifications/tools/list_changed）。guide 不是空的时候，先按它确定调用顺序和参数从哪来，再调用工具。如果工具列表没有出现它们，用 call_pack_tool 调用。\nLoad a pack by name or id. The result contains guide plus tools (name, description, inputSchema). When guide is not empty, follow it before calling tools. Tools are added to tools/list; if your client does not refresh, use call_pack_tool.",
			"inputSchema": obj(map[string]any{"pack": map[string]any{"type": "string", "description": "流程包名称或 id（来自 list_packs）/ pack name or id"}}, "pack"),
			"annotations": mcp.Annotations(false, false, false)},
		{"name": "unload_pack", "title": "卸载流程包",
			"description": "任务完成或换任务时卸载流程包，把它的工具从工具列表中移除，保持上下文干净。不填 pack 表示卸载全部。\nUnload a pack (or all packs when pack is empty) to keep your context small.",
			"inputSchema": obj(map[string]any{"pack": map[string]any{"type": "string", "description": "流程包名称或 id；留空 = 全部 / empty = all"}}),
			"annotations": mcp.Annotations(false, false, false)},
		{"name": "call_pack_tool", "title": "调用包内工具（兜底）",
			"description": "【兜底 Fallback】按工具名调用已开启流程包里的工具（包括 db_query、redis_command、ws_sql_query 等中间件工具）。当 load_pack 之后你的工具列表里没有出现新工具时使用；arguments 按 load_pack 返回的 inputSchema 填写（需要审批的工具请务必在 arguments 中传入 operation_note，写明本次操作目的、内容与影响范围）。权限、自动登录等规则与直接调用完全相同。被调工具若是写操作，仍须用户明确要求才调用。\nCall a pack tool by name when your client did not refresh its tool list after load_pack. arguments must follow the tool's inputSchema (include operation_note when required for approval).",
			"inputSchema": obj(map[string]any{
				"tool":      map[string]any{"type": "string", "description": "工具名（来自 load_pack 的返回）/ tool name"},
				"arguments": map[string]any{"type": "object", "description": "工具参数 / tool arguments", "additionalProperties": true},
			}, "tool")},
	}
}

func (a *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
	mc := &mcp.Call{}
	canParallel := batch && len(reqs) > 1
	for _, q := range reqs {
		if q.Method == "initialize" {
			canParallel = false
			break
		}
	}
	if canParallel {
		mc.Session = a.sessions.Session(sid)
		if h := r.Header.Get("X-A2M-Client"); h != "" {
			mc.Session.HintClientName(h)
		}
		results := make([]*rpcResp, len(reqs))
		var wg sync.WaitGroup
		for i, q := range reqs {
			i, q := i, q
			wg.Add(1)
			go func() {
				defer wg.Done()
				res, e := a.dispatchMCP(r.Context(), q, mc)
				if len(q.ID) == 0 || string(q.ID) == "null" {
					return
				}
				resp := &rpcResp{JSONRPC: "2.0", ID: q.ID}
				if e != nil {
					resp.Error = e
				} else {
					resp.Result = res
				}
				results[i] = resp
			}()
		}
		wg.Wait()
		for _, resp := range results {
			if resp != nil {
				out = append(out, *resp)
			}
		}
	} else {
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
				s := a.sessions.Session(sid)
				s.SetClientName(strings.TrimSpace(p.ClientInfo.Name + " " + p.ClientInfo.Version))
			}
			mc.Session = a.sessions.Session(sid)
			if h := r.Header.Get("X-A2M-Client"); h != "" {
				mc.Session.HintClientName(h)
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
	}
	// Deliver notifications: on the session's GET SSE stream if one is open, otherwise inline in this
	// POST response as SSE (when the client accepts it). Clients that support neither still get the
	// tool definitions inside the load_pack result.
	var inline [][]byte
	for _, n := range mc.Notifications() {
		if mc.Session == nil || !mc.Session.Push(n) {
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
		fmt.Fprintf(w, "event: message\ndata: %s\n\n", execution.CompactJSON(payload))
		return
	}
	writeJSON(w, 200, payload)
}

func (a *Server) dispatchMCP(ctx context.Context, q rpcReq, mc *mcp.Call) (any, *rpcErr) {
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
		if a.Mode() == mcp.ModeTiered {
			instr = instrTiered + instrCommon
			if a.analysis().Enabled() {
				instr += "\n\n" + analysis.TieredHint
			}
		} else {
			instr += a.flatPackGuides()
		}
		return map[string]any{
			"protocolVersion": ver,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": true}},
			"serverInfo":      map[string]any{"name": "action2mcp", "title": "Action2MCP", "version": a.version},
			"instructions":    instr,
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": a.toolList(mc.Session)}, nil
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
		if a.Mode() == mcp.ModeTiered {
			switch p.Name {
			case "list_packs":
				return a.mcpListPacks(mc), nil
			case "load_pack":
				return a.mcpLoadPack(mc, p.Arguments), nil
			case "unload_pack":
				return a.mcpUnloadPack(mc, p.Arguments), nil
			case "call_pack_tool":
				name := strings.TrimSpace(mcp.ArgString(p.Arguments, "tool"))
				args, err := mcp.ArgObject(p.Arguments["arguments"])
				if err != nil {
					return mcp.TextResult("arguments 必须是 JSON 对象（按 load_pack 返回的 inputSchema 填写）："+err.Error(), true), nil
				}
				if name == "" {
					return mcp.TextResult("请提供 tool（工具名，来自 load_pack 的返回结果）", true), nil
				}
				if mcp.IsEntryTool(name) {
					return mcp.TextResult(name+" 是入口工具，请直接调用它，不要通过 call_pack_tool。", true), nil
				}
				res, rerr := a.invokeTool(ctx, mc, name, args)
				if rerr != nil {
					return mcp.TextResult(rerr.Message, true), nil
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

// invokeTool runs a recorded tool or a middleware tool. It is lenient: the tool only has to belong to
// a pack that is enabled in the console (being loaded in this session is NOT required). The console
// toggle is the security boundary; load_pack only controls what is advertised in tools/list.
func (a *Server) invokeTool(ctx context.Context, mc *mcp.Call, name string, args map[string]any) (any, *rpcErr) {
	client := "未知客户端"
	if mc != nil && mc.Session != nil {
		client = mc.Session.ClientName()
	}
	if analysis.IsTool(name) {
		return a.analysis().Call(mc, name, args), nil
	}
	if _, ok := mwtools.IsTool(name); ok {
		text, isErr := a.middlewares().Call(ctx, client, name, args)
		return mcp.TextResult(text, isErr), nil
	}
	tools, _ := a.repo.ExposedTools()
	var t *execution.Tool
	for _, x := range tools {
		if x.Name == name {
			t = x
		}
	}
	if t == nil {
		msg := fmt.Sprintf("工具 %s 不存在或所在流程包未开启", name)
		if a.Mode() == mcp.ModeTiered {
			msg += "。请先调用 list_packs 查看可用流程包，再用 load_pack 加载，按返回的工具名调用。"
		}
		return nil, &rpcErr{-32602, msg}
	}
	var pending *invoke.Approved
	var explanation string
	if t.Approval == "always" {
		var err error
		args, err = approval.CopyArgs(args)
		if err != nil {
			return mcp.TextResult(err.Error(), true), nil
		}
	}
	args, explanation = execution.ExtractApprovalNote(t, args)
	prepared, err := a.engine().Prepare(t, args)
	if err != nil {
		return mcp.TextResult("调用失败："+err.Error(), true), nil
	}
	prefix := ""
	if t.Approval == "always" {
		pending, err = a.approvals().Wait(ctx, t, args, prepared, client, explanation)
		if err != nil {
			return mcp.TextResult(err.Error(), true), nil
		}
		if !a.approvals().CommitValid(pending) {
			a.approvals().Service().RecordResult(pending.Record.ID, "未执行：工具在审批期间被修改/关闭/请求内容已变化")
			return mcp.TextResult("工具或请求内容在审批期间变化，未执行，请重新调用", true), nil
		}
		prepared = pending.Prepared
		prefix = a.approvals().EditPrefix(pending)
	}
	if execution.IsFlowMethod(t.Method) {
		if a.flow == nil || a.flow() == nil {
			return mcp.TextResult("自定义工具编排执行器未就绪", true), nil
		}
		fres, ferr := a.flow().Run(ctx, t, args, explanation)
		out := ""
		isErr := false
		if ferr != nil {
			out = prefix + "调用失败：" + ferr.Error()
			isErr = true
		} else if fres != nil {
			out = prefix + fres.Body
			isErr = !fres.OK
		}
		if pending != nil {
			a.approvals().Service().RecordResult(pending.Record.ID, out)
		}
		return mcp.TextResult(out, isErr), nil
	}
	res, err := a.engine().Send(prepared)
	out, isErr := formatMCPCallResult(prefix, res, err)
	if pending != nil {
		a.approvals().Service().RecordResult(pending.Record.ID, out)
	}
	return mcp.TextResult(out, isErr), nil
}

// recordedToolDefs turns recorded tools into MCP tool entries.
func (a *Server) recordedToolDefs(tools []*execution.Tool, packNames map[int64][]string, skipReserved bool) []map[string]any {
	list := []map[string]any{}
	for _, t := range tools {
		if _, ok := mwtools.IsTool(t.Name); ok {
			continue // built-in middleware tool names take precedence
		}
		if analysis.IsTool(t.Name) {
			continue // native 录制分析 handlers own these names
		}
		if skipReserved && mcp.IsEntryTool(t.Name) {
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
		if t.Approval == "always" {
			desc += "（需审批：调用时必须在 operation_note 参数中说明本次操作的目的与影响）"
		}
		write, ann := toolOpKind(t)
		if write {
			desc = mcp.ApplyWritePrefix(desc)
		}
		secrets := a.engine().McpToolSecrets(t)
		desc = a.engine().ScrubApprovalText(desc, secrets)
		title := a.engine().ScrubApprovalText(t.Title, secrets)
		item := map[string]any{"name": t.Name, "description": desc, "inputSchema": a.engine().McpInputSchema(t), "annotations": ann}
		if title != "" {
			item["title"] = title
		}
		list = append(list, item)
	}
	return list
}

// toolList is what tools/list returns for a session.
func (a *Server) toolList(sess *mcp.Session) []map[string]any {
	if a.Mode() == mcp.ModeFlat {
		tools, _ := a.repo.ExposedTools()
		list := a.recordedToolDefs(tools, a.packNamesByTool(), false)
		list = append(list, a.middlewares().ToolList()...)
		if a.analysis().Enabled() {
			list = append(list, analysis.ToolDefs()...)
		}
		return list
	}
	list := entryToolDefs()
	if sess == nil {
		return list
	}
	loaded := sess.LoadedIDs()
	if a.analysis().Enabled() && loaded[store.RecordingPackID] {
		list = append(list, analysis.ToolDefs()...)
	}
	if len(loaded) == 0 || (len(loaded) == 1 && loaded[store.RecordingPackID]) {
		return list
	}
	packs, _ := a.repo.ListPacks()
	sel := []*store.Pack{}
	for _, p := range packs {
		if p.Enabled && loaded[p.ID] {
			sel = append(sel, p)
		}
	}
	if len(sel) == 0 {
		return list
	}
	return append(list, a.packToolDefs(sel)...)
}

// packToolDefs returns the MCP tool entries (recorded + middleware) for the given packs.
func (a *Server) packToolDefs(packs []*store.Pack) []map[string]any {
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
	all, _ := a.repo.ExposedTools()
	tools := []*execution.Tool{}
	for _, t := range all {
		if toolIDs[t.ID] {
			tools = append(tools, t)
		}
	}
	list := a.recordedToolDefs(tools, a.packNamesByTool(), true)
	ms, names := a.repo.ExposedMiddleware()
	sel := []*mwconfig.Middleware{}
	for _, m := range ms {
		if mwIDs[m.ID] {
			sel = append(sel, m)
		}
	}
	return append(list, a.middlewares().ToolListFor(sel, names)...)
}

func (a *Server) packNamesByTool() map[int64][]string {
	out := map[int64][]string{}
	packs, _ := a.repo.ListPacks()
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

// findEnabledPack resolves a pack by id or name among enabled packs.
func (a *Server) findEnabledPack(ref string) (*store.Pack, []*store.Pack) {
	ref = strings.TrimSpace(ref)
	packs, _ := a.repo.ListPacks()
	en := []*store.Pack{}
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
		return nil, en
	}
	for _, p := range packs {
		if p.Name == ref {
			if !p.Enabled {
				return nil, en
			}
			return p, en
		}
	}
	var matches []*store.Pack
	for _, p := range en {
		if strings.EqualFold(p.Name, ref) {
			matches = append(matches, p)
		}
	}
	if len(matches) == 1 {
		return matches[0], en
	}
	return nil, en
}

func (a *Server) mcpListPacks(mc *mcp.Call) any {
	packs, _ := a.repo.ListPacks()
	tools, _ := a.repo.ExposedTools()
	tname := map[int64]string{}
	for _, t := range tools {
		tname[t.ID] = t.Name
	}
	mws, _ := a.repo.ListMiddleware()
	mwByID := map[int64]*mwconfig.Middleware{}
	for _, m := range mws {
		mwByID[m.ID] = m
	}
	loaded := mc.Session.LoadedIDs()
	type packOut struct {
		ID              int64    `json:"id"`
		Name            string   `json:"name"`
		Description     string   `json:"description,omitempty"`
		Scenarios       string   `json:"scenarios,omitempty"`
		ToolCount       int      `json:"tool_count"`
		ToolNames       []string `json:"tool_names,omitempty"`
		Middleware      []string `json:"middleware,omitempty"`
		MiddlewareCount int      `json:"middleware_count"`
		Loaded          bool     `json:"loaded"`
		Builtin         bool     `json:"builtin,omitempty"`
	}
	out := []packOut{}
	for _, p := range packs {
		if !p.Enabled {
			continue
		}
		secrets := a.mcpPackSecrets(p)
		po := packOut{ID: p.ID, Name: p.Name, Description: strings.TrimSpace(a.engine().ScrubApprovalText(p.Description, secrets)), Scenarios: strings.TrimSpace(a.engine().ScrubApprovalText(p.Scenarios, secrets)), Loaded: loaded[p.ID]}
		for _, id := range p.ToolIDs {
			if n, ok := tname[id]; ok {
				po.ToolNames = append(po.ToolNames, n)
			}
		}
		for _, id := range p.MiddlewareIDs {
			if m := mwByID[id]; m != nil {
				po.Middleware = append(po.Middleware, m.Name+"("+m.KindLabel()+")")
			}
		}
		po.ToolCount = len(po.ToolNames)
		po.MiddlewareCount = len(po.Middleware)
		if len(po.ToolNames) > 12 {
			po.ToolNames = append(po.ToolNames[:12], fmt.Sprintf("…等 %d 个", len(po.ToolNames)))
		}
		out = append(out, po)
	}
	if a.analysis().Enabled() {
		names := analysis.ToolNames()
		out = append(out, packOut{
			ID: store.RecordingPackID, Name: store.RecordingPackName, Description: analysis.PackBlurb, Scenarios: analysis.PackScenarios,
			ToolCount: len(names), MiddlewareCount: 0, ToolNames: names, Loaded: loaded[store.RecordingPackID], Builtin: true,
		})
	}
	next := "根据当前任务选择相关的流程包，调用 load_pack(pack=名称或id) 加载后再使用其中的工具。Pick the pack(s) relevant to your task and call load_pack."
	if len(out) == 0 {
		next = "当前没有开启的流程包。请让用户在 Action2MCP 控制台「流程包」页开启需要的流程包。No pack is enabled; ask the user to enable one in the Action2MCP console."
	}
	return mcp.TextResult(string(execution.CompactJSON(map[string]any{"packs": out, "next": next})), false)
}

func (a *Server) mcpLoadPack(mc *mcp.Call, args map[string]any) any {
	ref := mcp.ArgString(args, "pack")
	if strings.TrimSpace(ref) == "" {
		ref = mcp.ArgString(args, "name")
	}
	if strings.TrimSpace(ref) == "" {
		ref = mcp.ArgString(args, "id")
	}
	if a.analysis().IsPackRef(ref) {
		return a.analysis().LoadPack(mc)
	}
	p, en := a.findEnabledPack(ref)
	if p == nil {
		return mcp.TextResult(fmt.Sprintf("流程包「%s」不存在或未开启。可用的流程包：%s。请先调用 list_packs。", ref, analysis.PackNameList(en)), true)
	}
	changed := mc.Session.LoadPack(p.ID)
	if changed {
		mc.NotifyToolsChanged()
	}
	defs := a.packToolDefs([]*store.Pack{p})
	briefs := []mcp.ToolBrief{}
	for _, d := range defs {
		briefs = append(briefs, mcp.ToolBrief{Name: d["name"].(string), Description: d["description"].(string), InputSchema: d["inputSchema"], Annotations: d["annotations"]})
	}
	loadedNames := a.LoadedPackNames(mc.Session)
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
	return mcp.TextResult(string(execution.CompactJSON(res)), false)
}

// packGuideText is the pack guide as the model should see it. Secret values are masked.
// {{secret.name}} references are left as written and are not resolved.
func (a *Server) mcpPackSecrets(p *store.Pack) []string {
	if p == nil {
		return nil
	}
	var secrets []string
	for _, id := range p.ToolIDs {
		t, err := a.repo.GetTool(id)
		if err != nil || t == nil {
			continue
		}
		secrets = append(secrets, a.engine().McpToolSecrets(t)...)
	}
	return secrets
}

func (a *Server) packGuideText(p *store.Pack) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(a.engine().ScrubApprovalText(p.Guide, a.mcpPackSecrets(p)))
}

// flatPackGuides appends each enabled pack's guide to the flat-mode connection instructions.
func (a *Server) flatPackGuides() string {
	packs, _ := a.repo.ListPacks()
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
	if a.analysis().Enabled() {
		fmt.Fprintf(&b, "\n\n## 内置流程包「%s」\n%s", store.RecordingPackName, analysis.PackGuide)
	}
	if b.Len() == 0 {
		return ""
	}
	return "\n\n以下是已开启流程包的使用说明。调用其中的工具前，先按对应说明确定顺序和参数来源。" + b.String()
}

func (a *Server) LoadedPackNames(s *mcp.Session) []string {
	loaded := s.LoadedIDs()
	packs, _ := a.repo.ListPacks()
	out := []string{}
	for _, p := range packs {
		if p.Enabled && loaded[p.ID] {
			out = append(out, p.Name)
		}
	}
	if a.analysis().Enabled() && loaded[store.RecordingPackID] {
		out = append(out, store.RecordingPackName)
	}
	sort.Strings(out)
	return out
}

func (a *Server) mcpUnloadPack(mc *mcp.Call, args map[string]any) any {
	ref := strings.TrimSpace(mcp.ArgString(args, "pack"))
	if ref == "" {
		ref = strings.TrimSpace(mcp.ArgString(args, "name"))
	}
	s := mc.Session
	if ref == "" || ref == "*" || ref == "all" {
		n := s.UnloadAll()
		if n > 0 {
			mc.NotifyToolsChanged()
		}
		return mcp.TextResult(`{"unloaded":"全部 / all","loaded_packs":[]}`, false)
	}
	if a.analysis().IsPackRef(ref) {
		return a.analysis().UnloadPack(mc)
	}
	// resolve among all packs (a pack disabled after loading can still be unloaded)
	packs, _ := a.repo.ListPacks()
	var p *store.Pack
	id, idErr := strconv.ParseInt(ref, 10, 64)
	for _, x := range packs {
		if (idErr == nil && x.ID == id) || (idErr != nil && x.Name == ref) {
			p = x
			break
		}
	}
	if p == nil && idErr != nil {
		var matches []*store.Pack
		for _, x := range packs {
			if strings.EqualFold(x.Name, ref) {
				matches = append(matches, x)
			}
		}
		if len(matches) == 1 {
			p = matches[0]
		}
		if len(matches) > 1 {
			return mcp.TextResult("流程包名称匹配不唯一，请使用精确名称或 id。选项："+analysis.PackNameList(matches), true)
		}
	}
	if p == nil {
		return mcp.TextResult(fmt.Sprintf("流程包「%s」不存在。当前已加载：%s", ref, strings.Join(a.LoadedPackNames(s), "、")), true)
	}
	was := s.UnloadPack(p.ID)
	if was {
		mc.NotifyToolsChanged()
	}
	return mcp.TextResult(string(execution.CompactJSON(map[string]any{"unloaded": p.Name, "was_loaded": was, "loaded_packs": a.LoadedPackNames(s)})), false)
}

func (a *Server) Mode() string {
	if a.repo.GetSetting("mcp_mode", mcp.ModeTiered) == mcp.ModeFlat {
		return mcp.ModeFlat
	}
	return mcp.ModeTiered
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func randID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
