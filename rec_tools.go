package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Built-in pack 「录制分析」 is not a packs-table row. Its tools are native
// handlers (no HTTP replay). The console setting rec_analysis defaults to on.
const (
	recPackID          int64 = -1
	recPackName              = "录制分析"
	settingRecAnalysis       = "rec_analysis"
	recPackBlurb             = "内置包。识别录制记录，给请求写作用，并把完成流程所需的最少请求保存成工具。请 load_pack 后按说明调用。用户没指定流程包时必须先问。写操作要告诉用户。"
	recPackScenarios         = "分析某次录制、识别接口作用、把录制保存成工具、整理一条业务流程"
	recWorkflow              = "工作顺序：先 rec_get_recording 看全貌 → 必要时 rec_get_request 看细节 → rec_annotate 给所有业务相关请求写作用 → 选出完成流程所需的最少请求 → 若用户没明确说保存到哪个流程包，必须先问用户（可调用 rec_list_target_packs 拿到真实选项）→ 再 rec_save_tool。会修改数据的请求必须标 category=write，并在回复用户时说明这些写操作。"
	recTieredHint            = "内置流程包「录制分析」用于识别录制并保存成工具（控制台「接入 AI / 设置」可关闭）。用户提出分析录制时，先 list_packs，再 load_pack(pack=-1) 加载内置「录制分析」，按返回说明里的顺序调用 rec_* 工具。用户没明确说保存到哪个流程包时，必须先问用户。"
	recPackGuide             = `按这个顺序做，不要跳步：
1. rec_list_recordings 列出录制，确认是哪一条。起始网址只给源（scheme://host）。
2. rec_get_recording 看全貌（默认隐藏噪音）。相同 method+host+path 已合并，query 只给参数名。
3. 看不清作用时再 rec_get_request 看单条脱敏详情和可参数化字段 candidates。Cookie、Authorization、Token、密码和配置管理里的密钥都已遮盖。
4. rec_annotate 给所有业务相关请求写作用（purpose）、分类（category）和是否属于本流程（useful）。noise_override 可纠正误判：true 强制当噪音，false 强制当业务请求。会修改数据的请求 category 必须是 write，并在回复用户时说明。
5. 只保留完成用户目标所需的最少请求。
6. 如果用户没有明确说保存到哪个流程包：先 rec_list_target_packs，把现有流程包告诉用户并询问。得到答复之前不要调用 rec_save_tool，也不要自己起一个包名。
7. rec_save_tool 保存。pack 必填，没有默认值。新建包只有在用户明确给出名字时才把 create_pack 设为 true。同名工具要用户同意后才 overwrite=true。
这些工具只读录制、写本机的标注和工具定义，不会重放请求。`
)

// sensitiveKeyRe matches header / query / body key names whose values must never
// be shown to the model or stored as a tool literal.
var sensitiveKeyRe = regexp.MustCompile(`(?i)(passw|passwd|pwd|password|secret|token|cookie|authorization|api[_-]?key|apikey|session|csrf|xsrf|bearer|credential|jwt|private[_-]?key|access[_-]?key|(?:^|[._-])pin(?:$|[._-]))`)

func (a *App) recAnalysisEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(a.store.GetSetting(settingRecAnalysis, "on"))) {
	case "0", "off", "false", "no":
		return false
	default:
		return true
	}
}

func (a *App) isRecPackRef(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	if strings.EqualFold(ref, recPackName) {
		packs, err := a.store.ListPacks()
		if err != nil {
			return false
		}
		for _, p := range packs {
			if p.Enabled && p.Name == ref {
				return false
			}
		}
		return true
	}
	id, err := strconv.ParseInt(ref, 10, 64)
	return err == nil && id == recPackID
}

func isRecTool(name string) bool {
	switch name {
	case "rec_list_recordings", "rec_get_recording", "rec_get_request", "rec_annotate", "rec_save_tool", "rec_list_target_packs":
		return true
	default:
		return false
	}
}

func isSensitiveKey(k string) bool {
	k = strings.TrimSpace(k)
	if k == "" {
		return false
	}
	return isPassKey(k) || sensitiveKeyRe.MatchString(k) || sensitiveKeyRe.MatchString(lastKey(k))
}

func isSensitiveHeader(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "cookie" || n == "set-cookie" || n == "authorization" || n == "proxy-authorization" {
		return true
	}
	return IsCredHeader(name) || isSensitiveKey(n)
}

func isWriteMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH", "DELETE":
		return true
	default:
		return false
	}
}

func validNoteCategory(c string) bool {
	switch c {
	case "query", "write", "auth", "config", "page", "noise":
		return true
	default:
		return false
	}
}

func recSchema(props map[string]any, req ...string) map[string]any {
	m := map[string]any{"type": "object", "properties": props}
	if len(req) > 0 {
		m["required"] = req
	}
	return m
}

func recAnn(readOnly bool) map[string]any {
	return map[string]any{"readOnlyHint": readOnly}
}

func recToolNames() []string {
	names := make([]string, 0, 6)
	for _, d := range recToolDefs() {
		names = append(names, d["name"].(string))
	}
	return names
}

func recToolDefs() []map[string]any {
	return []map[string]any{
		{"name": "rec_list_recordings", "title": "列出录制",
			"description": "【录制分析】列出本机全部录制：id、名称、创建时间、请求总数、业务请求数、起始网址的源（只有 scheme://host，不含路径和查询）。确定要分析哪一条之后调用 rec_get_recording。\n" + recWorkflow,
			"inputSchema": recSchema(map[string]any{}),
			"annotations": recAnn(true)},
		{"name": "rec_get_recording", "title": "查看录制全貌",
			"description": "【录制分析】查看一条录制的 summary 和压缩后的请求行。相同 method+host+path 合并成一行，给出 count 和最早的 id。query 只返回参数名，不返回值。include_noise 默认 false，不返回判定为噪音的请求（标注里的 noise_override 优先于自动判断）。看不清时再对某一行的 id 调用 rec_get_request。\n" + recWorkflow,
			"inputSchema": recSchema(map[string]any{
				"recording_id":  map[string]any{"type": "integer", "description": "录制 id，来自 rec_list_recordings"},
				"include_noise": map[string]any{"type": "boolean", "description": "true 时连噪音请求一起返回。默认 false"},
				"offset":        map[string]any{"type": "integer", "description": "合并后的行偏移，默认 0"},
				"limit":         map[string]any{"type": "integer", "description": "最多返回多少行，默认 50，最大 200"},
			}, "recording_id"),
			"annotations": recAnn(true)},
		{"name": "rec_get_request", "title": "查看单条请求",
			"description": "【录制分析】查看单条请求的脱敏详情：请求头、响应头、截断后的请求体和响应体（附总长度）、可参数化的 candidates，以及已有标注。Cookie、Authorization、Token、密码、Set-Cookie 和配置管理里的密钥都会遮盖，不要在回复里复述任何疑似密钥的内容。POST/PUT/PATCH/DELETE 可能修改数据，须结合接口语义判断；实际修改数据的请求要标 category=write 并告诉用户。\n" + recWorkflow,
			"inputSchema": recSchema(map[string]any{
				"request_id": map[string]any{"type": "integer", "description": "请求 id，来自 rec_get_recording"},
				"max_body":   map[string]any{"type": "integer", "description": "请求体和响应体各自最多返回的字节数，默认 4000"},
			}, "request_id"),
			"annotations": recAnn(true)},
		{"name": "rec_annotate", "title": "标注录制",
			"description": "【录制分析·写入标注】给一条录制写整体 summary，并批量给请求写作用。每条 note：request_id、purpose（中文一句话）、category（query 查询 / write 写操作 / auth 登录认证 / config 配置枚举 / page 页面 / noise 无关）、useful（是否属于要完成的流程）、noise_override（true 强制噪音，false 强制业务，省略则沿用自动判断）。source 固定为 agent。请求必须属于这条录制。会改数据的请求必须是 write，并在回复用户时说明。标完后选出最少请求；用户没说流程包就先问，不要调用 rec_save_tool。\n" + recWorkflow,
			"inputSchema": recSchema(map[string]any{
				"recording_id": map[string]any{"type": "integer", "description": "录制 id"},
				"summary":      map[string]any{"type": "string", "description": "这次录制对应的业务流程，一两句话"},
				"notes": map[string]any{"type": "array", "description": "要写入的标注。同一 request_id 不要重复", "items": recSchema(map[string]any{
					"request_id":     map[string]any{"type": "integer"},
					"purpose":        map[string]any{"type": "string", "description": "中文一句话说明这个接口的作用"},
					"category":       map[string]any{"type": "string", "enum": []string{"query", "write", "auth", "config", "page", "noise"}, "description": "query / write / auth / config / page / noise。会改数据的用 write"},
					"useful":         map[string]any{"type": "boolean", "description": "是否属于要保存的业务流程"},
					"noise_override": map[string]any{"type": "boolean", "description": "true 强制当噪音，false 强制当业务请求，省略则沿用自动判断"},
				}, "request_id", "category")},
			}, "recording_id"),
			"annotations": recAnn(false)},
		{"name": "rec_list_target_packs", "title": "列出可保存的流程包",
			"description": "【录制分析】列出可以保存工具的业务流程包：id、名称、是否开启、已有工具名。不含内置包「录制分析」。用户没明确说保存到哪个流程包时，先调用本工具，把这些真实选项告诉用户并询问，得到明确答复后再 rec_save_tool。不要自己挑一个，也不要默认新建。\n" + recWorkflow,
			"inputSchema": recSchema(map[string]any{}),
			"annotations": recAnn(true)},
		{"name": "rec_save_tool", "title": "保存为工具",
			"description": "【录制分析·写入工具】把一条录制请求保存成参数化工具并放进指定流程包。这是写操作：调用前告诉用户将要保存什么；若原请求会改数据，说明它是写操作。pack（流程包名称或 id）必填，没有默认值。用户没明确指定时禁止调用，先问用户。流程包不存在且 create_pack=false 时会失败并列出现有流程包，此时继续问，不要擅自创建。只有用户明确给出新名字时才 create_pack=true。同名工具已存在时失败，除非用户同意覆盖并且 overwrite=true。params.from 是 candidates 的路径，例如 query:keyword 或 body:user.id。敏感值不会写入工具。\n" + recWorkflow,
			"inputSchema": recSchema(map[string]any{
				"request_id":  map[string]any{"type": "integer", "description": "要保存的请求 id"},
				"pack":        map[string]any{"type": "string", "description": "流程包名称或 id。必填，没有默认值。用户没明确指定时不要调用"},
				"name":        map[string]any{"type": "string", "description": "工具英文标识，例如 search_order"},
				"title":       map[string]any{"type": "string", "description": "给人看的短标题"},
				"description": map[string]any{"type": "string", "description": "工具做什么、什么时候调用"},
				"params": map[string]any{"type": "array", "description": "要变成参数的字段", "items": recSchema(map[string]any{
					"name":        map[string]any{"type": "string", "description": "参数名"},
					"from":        map[string]any{"type": "string", "description": "候选路径：query:键、body:字段路径 或 form:字段"},
					"type":        map[string]any{"type": "string", "description": "string、number、integer 或 boolean"},
					"description": map[string]any{"type": "string"},
					"required":    map[string]any{"type": "boolean"},
					"default":     map[string]any{"type": "string", "description": "不要填录制里的 Token、密码或 Cookie"},
				}, "from")},
				"create_pack": map[string]any{"type": "boolean", "description": "仅当用户明确说出一个还不存在的流程包名称时设为 true。默认 false"},
				"overwrite":   map[string]any{"type": "boolean", "description": "同名工具已存在时，只有用户同意覆盖才设为 true。默认 false"},
			}, "request_id", "pack", "name"),
			"annotations": recAnn(false)},
	}
}

func (a *App) callRecTool(mc *mcpCtx, name string, args map[string]any) any {
	if args == nil {
		args = map[string]any{}
	}
	var text string
	var isErr bool
	if !a.recAnalysisEnabled() {
		text, isErr = "录制分析已关闭。请让用户在 Action2MCP 控制台「接入 AI / 设置」打开「让 AI 分析录制」。", true
	} else {
		switch name {
		case "rec_list_recordings":
			text, isErr = a.recListRecordings()
		case "rec_get_recording":
			text, isErr = a.recGetRecording(args)
		case "rec_get_request":
			text, isErr = a.recGetRequest(args)
		case "rec_annotate":
			text, isErr = a.recAnnotate(args)
		case "rec_list_target_packs":
			text, isErr = a.recListTargetPacks()
		case "rec_save_tool":
			text, isErr = a.recSaveTool(mc, args)
		default:
			text, isErr = "未知的录制分析工具 "+name, true
		}
	}
	if isErr {
		lits, err := a.recErrorLiterals(args)
		if err != nil {
			text = "录制分析失败，无法安全读取脱敏上下文。"
		}
		text = a.finishRec(map[string]any{"error": text}, lits)
	}
	return textResult(text, isErr)
}

func (a *App) mcpLoadRecPack(mc *mcpCtx) any {
	if !a.recAnalysisEnabled() {
		return textResult("内置流程包「录制分析」已关闭。请让用户在 Action2MCP 控制台「接入 AI / 设置」打开「让 AI 分析录制」。", true)
	}
	mc.sess.mu.Lock()
	changed := !mc.sess.loaded[recPackID]
	mc.sess.loaded[recPackID] = true
	mc.sess.mu.Unlock()
	if changed {
		mc.notifyToolsChanged()
	}
	briefs := make([]toolBrief, 0, 6)
	for _, d := range recToolDefs() {
		briefs = append(briefs, toolBrief{Name: d["name"].(string), Description: d["description"].(string), InputSchema: d["inputSchema"]})
	}
	return textResult(string(compactJSON(map[string]any{
		"loaded":       recPackName,
		"pack_id":      recPackID,
		"builtin":      true,
		"guide":        recPackGuide,
		"tools":        briefs,
		"loaded_packs": a.loadedPackNames(mc.sess),
		"next":         "先按 guide 的顺序调用 rec_* 工具。这些工具已加入工具列表；如果列表里没有，用 call_pack_tool。用户没明确说保存到哪个流程包时，必须先问用户，不要调用 rec_save_tool。",
	})), false)
}

func (a *App) mcpUnloadRecPack(mc *mcpCtx) any {
	s := mc.sess
	s.mu.Lock()
	was := s.loaded[recPackID]
	delete(s.loaded, recPackID)
	s.mu.Unlock()
	if was {
		mc.notifyToolsChanged()
	}
	return textResult(string(compactJSON(map[string]any{
		"unloaded": recPackName, "was_loaded": was, "loaded_packs": a.loadedPackNames(s),
	})), false)
}

func (a *App) finishRec(v any, lits []string) string {
	return string(compactJSON(a.sanitizeRecValue(reflect.ValueOf(v), lits)))
}

// Walk typed values before encoding. In particular, a secret equal to "200"
// must never turn status:200 into invalid JSON or rewrite schema property names.
func (a *App) sanitizeRecValue(v reflect.Value, lits []string) any {
	if !v.IsValid() {
		return nil
	}
	if v.CanInterface() {
		if s, ok := v.Interface().(recSafeText); ok {
			return s
		}
	}
	switch v.Kind() {
	case reflect.Interface, reflect.Pointer:
		if v.IsNil() {
			return nil
		}
		return a.sanitizeRecValue(v.Elem(), lits)
	case reflect.String:
		return a.scrubRecText(v.String(), lits)
	case reflect.Map:
		if v.IsNil() {
			return nil
		}
		out := map[string]any{}
		it := v.MapRange()
		for it.Next() {
			out[it.Key().String()] = a.sanitizeRecValue(it.Value(), lits)
		}
		return out
	case reflect.Slice, reflect.Array:
		out := make([]any, v.Len())
		for i := range out {
			out[i] = a.sanitizeRecValue(v.Index(i), lits)
		}
		return out
	default:
		return v.Interface()
	}
}

func (a *App) scrubRecText(s string, lits []string) string {
	lits = append([]string(nil), lits...)
	if a.vault != nil {
		lits = append(lits, a.vault.secretVariants()...)
		a.vault.mu.RLock()
		for _, entry := range a.vault.cache {
			if entry.typ == "secret" {
				lits = append(lits, entry.value)
			}
		}
		a.vault.mu.RUnlock()
	}
	return replaceLiterals(s, lits)
}

func (a *App) recordingSecretLiterals(id int64) ([]string, error) {
	rec, err := a.store.GetRecording(id)
	if err != nil {
		return nil, err
	}
	lits := sensitiveQueryValues(rec.StartURL)
	rows, err := a.store.ListRequests(id)
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		q, err := a.store.GetRequest(row.ID)
		if err != nil {
			return nil, err
		}
		lits = append(lits, sensitiveLiterals(q)...)
	}
	return lits, nil
}

// Errors can mention stored pack names, candidate paths, and annotation values.
// Use the same recording context as successful results, even on validation errors.
func (a *App) recErrorLiterals(args map[string]any) ([]string, error) {
	if rid, ok := argInt64(args, "recording_id"); ok && rid > 0 {
		lits, err := a.recordingSecretLiterals(rid)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return lits, err
	}
	if id, ok := argInt64(args, "request_id"); ok && id > 0 {
		q, err := a.store.GetRequest(id)
		if err == sql.ErrNoRows {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return a.recordingSecretLiterals(q.RecordingID)
	}
	return nil, nil
}

func (a *App) recCandidates(q *ReqRecord) []Candidate {
	copy := *q
	kind, _, err := bodyKind(q.ReqBody, headerValue(q.ReqHeaders, "Content-Type"))
	if err != nil || kind == "multipart" || kind == "text" {
		copy.ReqBody = ""
	}
	if kind == "json" {
		if _, err := parseRecJSON(copy.ReqBody); err != nil {
			copy.ReqBody = ""
		}
	}
	if kind == "form" {
		copy.ReqBody = tolerantForm(copy.ReqBody).Encode()
	}
	cs := SuggestParams(&copy)
	lits := sensitiveLiterals(q)
	for i := range cs {
		c := &cs[i]
		c.raw = c.Example
		if a.vault != nil {
			if ref := a.vault.FindByValue(c.raw); ref != "" && a.vault.TypeOf(ref) == "secret" {
				c.Secret, c.Ref, c.RefExists = true, ref, true
			}
		}
		c.Secret = c.Secret || isSensitiveKey(c.Path) || containsLiteral(c.raw, lits) || a.scrubRecText(c.raw, nil) != c.raw
		if c.Secret {
			c.Example, c.Suggest = "", true
		}
	}
	return cs
}

// Use the same BuildDraft builder as the console, with the stricter recording
// classification applied to all fields, including descendants and unselected fields.
func (a *App) buildRecDraft(q *ReqRecord, chosen []Candidate) (*Tool, error) {
	copy := *q
	kind, _, err := bodyKind(copy.ReqBody, headerValue(copy.ReqHeaders, "Content-Type"))
	if err != nil {
		return nil, fmt.Errorf("请求体无法安全解析")
	}
	if kind == "json" && strings.TrimSpace(copy.ReqBody) != "" {
		if _, err := parseRecJSON(copy.ReqBody); err != nil {
			return nil, fmt.Errorf("请求体 JSON 不完整，无法安全保存")
		}
	}
	if kind == "multipart" {
		return nil, fmt.Errorf("multipart 请求体暂不支持保存，请选择可安全参数化的 JSON 或表单请求")
	}
	if kind == "form" {
		copy.ReqBody = tolerantForm(copy.ReqBody).Encode()
	}
	seen := map[string]bool{}
	prepared := make([]Candidate, 0, len(chosen))
	for _, c := range chosen {
		seen[c.Loc+":"+c.Path] = true
		if !placeholderRe.MatchString(c.raw) {
			prepared = append(prepared, c)
		}
	}
	for _, c := range a.recCandidates(q) {
		if c.Secret && !seen[c.Loc+":"+c.Path] && !placeholderRe.MatchString(c.raw) {
			prepared = append(prepared, c)
		}
	}
	chosen = prepared
	used := map[string]bool{}
	for i := range chosen {
		c := &chosen[i]
		base := c.Name
		for suffix := 2; used[c.Name]; suffix++ {
			c.Name = fmt.Sprintf("%s_%d", base, suffix)
		}
		used[c.Name] = true
		if !c.Secret {
			continue
		}
		c.Example = ""
		// Vault references resolve to strings. Numeric/boolean fields instead
		// become required typed parameters so replay preserves their value types.
		if c.Type != "string" {
			c.Ref = ""
			continue
		}
		if c.raw == "" || c.raw == secretMask || placeholderRe.MatchString(c.raw) {
			continue
		}
		if c.Ref == "" && a.vault != nil {
			hash := sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%s", q.ID, c.Loc, c.Path)))
			c.Ref = fmt.Sprintf("rec_%x", hash[:16])
			if err := a.vault.Upsert(c.Ref, "secret", c.raw, originOf(q.URL), "录制分析自动保存"); err != nil {
				return nil, fmt.Errorf("保存敏感字段到配置管理失败：%w", err)
			}
		}
	}
	t, err := BuildDraft(&copy, chosen)
	if err != nil {
		return nil, err
	}
	t.Name, t.SourceReqID = suggestToolName(q), q.ID
	rec, err := a.store.GetRecording(q.RecordingID)
	if err != nil {
		return nil, err
	}
	t.Title = rec.Name
	return t, nil
}

func (a *App) recListRecordings() (string, bool) {
	recs, err := a.store.ListRecordings()
	if err != nil {
		return "读取录制失败：" + err.Error(), true
	}
	items := make([]map[string]any, 0, len(recs))
	var lits []string
	for _, rec := range recs {
		lits = append(lits, sensitiveQueryValues(rec.StartURL)...)
		context, err := a.recordingSecretLiterals(rec.ID)
		if err != nil {
			return "读取脱敏上下文失败：" + err.Error(), true
		}
		lits = append(lits, context...)
		items = append(items, map[string]any{
			"id":             rec.ID,
			"name":           rec.Name,
			"created_at":     rec.CreatedAt,
			"request_count":  rec.RequestCount,
			"business_count": rec.UsefulCount,
			"origin":         originOf(rec.StartURL),
		})
	}
	return a.finishRec(map[string]any{"recordings": items}, lits), false
}

func (a *App) recGetRecording(args map[string]any) (string, bool) {
	rid, ok := argInt64(args, "recording_id")
	if !ok || rid <= 0 {
		return "请提供 recording_id。", true
	}
	rec, err := a.store.GetRecording(rid)
	if err != nil || rec == nil {
		return fmt.Sprintf("录制 %d 不存在。", rid), true
	}
	reqs, err := a.store.ListRequests(rid)
	if err != nil {
		return "读取请求失败：" + err.Error(), true
	}
	notes, err := a.store.RequestNotes(rid)
	if err != nil {
		return "读取标注失败：" + err.Error(), true
	}
	includeNoise := argBool(args, "include_noise", false)
	offset := argNonNeg(args, "offset", 0)
	limit := argNonNeg(args, "limit", 50)
	if _, ok := args["limit"]; !ok || args["limit"] == nil || limit == 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	type group struct {
		id, seq                    int64
		count                      int
		method, host, path, reason string
		status                     int
		res                        string
		noise, heuristic           bool
		note                       *RequestNote
		keys                       map[string]struct{}
	}
	var order []string
	groups := map[string]*group{}
	var lits []string
	lits = append(lits, sensitiveQueryValues(rec.StartURL)...)
	context, err := a.recordingSecretLiterals(rid)
	if err != nil {
		return "读取脱敏上下文失败：" + err.Error(), true
	}
	lits = append(lits, context...)
	for i := range reqs {
		applyRequestNote(&reqs[i], notes)
		lits = append(lits, sensitiveQueryValues(reqs[i].URL)...)
		if !includeNoise && reqs[i].Noise {
			continue
		}
		u, _ := url.Parse(reqs[i].URL)
		host, path := "", "/"
		if u != nil {
			host = strings.ToLower(u.Host)
			if u.Path != "" {
				path = u.Path
			}
		}
		method := strings.ToUpper(reqs[i].Method)
		key := method + " " + host + " " + path
		g := groups[key]
		if g == nil {
			g = &group{
				id: int64(reqs[i].ID), seq: int64(reqs[i].Seq), method: method, host: host, path: path,
				status: reqs[i].Status, res: reqs[i].ResourceType, noise: reqs[i].Noise,
				heuristic: reqs[i].NoiseHeuristic, reason: reqs[i].NoiseReason, note: reqs[i].Note,
				keys: map[string]struct{}{},
			}
			groups[key] = g
			order = append(order, key)
		}
		g.count++
		if u != nil {
			for k := range u.Query() {
				if k != "" {
					g.keys[k] = struct{}{}
				}
			}
		}
	}
	rows := make([]map[string]any, 0, len(order))
	for _, key := range order {
		g := groups[key]
		keys := make([]string, 0, len(g.keys))
		for k := range g.keys {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		rows = append(rows, map[string]any{
			"id": g.id, "seq": g.seq, "count": g.count, "method": g.method, "host": g.host, "path": g.path,
			"query_keys": keys, "status": g.status, "resource_type": g.res,
			"noise": g.noise, "noise_reason": g.reason, "noise_heuristic": g.heuristic,
			"note": noteView(g.note),
		})
	}
	total := len(rows)
	if offset > total {
		offset = total
	}
	page := rows[offset:]
	if len(page) > limit {
		page = page[:limit]
	}
	if page == nil {
		page = []map[string]any{}
	}
	return a.finishRec(map[string]any{
		"recording_id": rec.ID, "name": rec.Name, "summary": rec.Summary,
		"request_count": rec.RequestCount, "business_count": rec.UsefulCount,
		"include_noise": includeNoise, "offset": offset, "limit": limit,
		"group_count": total, "requests": page,
	}, lits), false
}

func (a *App) recGetRequest(args map[string]any) (string, bool) {
	id, ok := argInt64(args, "request_id")
	if !ok || id <= 0 {
		return "请提供 request_id。", true
	}
	q, err := a.store.GetRequest(id)
	if err != nil || q == nil {
		return fmt.Sprintf("请求 %d 不存在。", id), true
	}
	notes, err := a.store.RequestNotes(q.RecordingID)
	if err != nil {
		return "读取标注失败：" + err.Error(), true
	}
	applyRequestNote(q, notes)
	maxBody := 4000
	if _, ok := args["max_body"]; ok && args["max_body"] != nil {
		maxBody = argInt(args, "max_body", 4000)
		if maxBody < 0 {
			maxBody = 0
		}
		if maxBody > 100000 {
			maxBody = 100000
		}
	}
	lits := sensitiveLiterals(q)
	u, _ := url.Parse(q.URL)
	host, path := "", "/"
	if u != nil {
		host = strings.ToLower(u.Host)
		if u.Path != "" {
			path = u.Path
		}
	}
	reqShown, reqTotal, reqCut, reqHidden := a.recBodyView(q.ReqBody, headerValue(q.ReqHeaders, "Content-Type"), lits, maxBody)
	respShown, respTotal, respCut, respHidden := a.recBodyView(q.RespBody, responseContentType(q), lits, maxBody)
	cands := a.recCandidates(q)
	candOut := make([]map[string]any, 0, len(cands))
	candBytes := 0
	for _, c := range cands {
		example := c.Example
		secret := c.Secret || isSensitiveKey(c.Path)
		if secret {
			example = ""
		} else {
			example = a.scrubRecText(example, lits)
		}
		example, exTotal, exCut := clipText(example, 200)
		row := map[string]any{
			"loc": c.Loc, "path": c.Path, "name": c.Name, "type": c.Type,
			"example": example, "suggest": c.Suggest, "secret": secret,
			"example_total": exTotal, "example_truncated": exCut,
		}
		rowBytes := len(compactJSON(row))
		if candBytes+rowBytes > 16000 || len(candOut) >= 100 {
			break
		}
		candBytes += rowBytes
		candOut = append(candOut, row)
	}
	shownURL := a.scrubRecText(maskURLSensitive(q.URL), lits)
	out := map[string]any{
		"id": q.ID, "recording_id": q.RecordingID, "seq": q.Seq,
		"method": q.Method, "url": shownURL, "host": host, "path": path,
		"query": maskedQuery(q.URL, lits, a), "status": q.Status,
		"resource_type": q.ResourceType, "resp_mime": q.RespMime,
		"noise": q.Noise, "noise_heuristic": q.NoiseHeuristic, "noise_reason": q.NoiseReason,
		"req_headers": a.maskHeaderMap(q.ReqHeaders, lits), "resp_headers": a.maskHeaderMap(q.RespHeaders, lits),
		"req_body": reqShown, "req_body_total": reqTotal, "req_body_truncated": reqCut,
		"resp_body": respShown, "resp_body_total": respTotal, "resp_body_truncated": respCut,
		"req_body_hidden": reqHidden, "resp_body_hidden": respHidden,
		"note": noteView(q.Note), "candidates": candOut, "candidates_truncated": len(candOut) < len(cands),
	}
	if isWriteMethod(q.Method) {
		out["write_hint"] = "POST/PUT/PATCH/DELETE 可能修改数据，请结合接口语义和标注判断；实际修改数据的请求必须标 category=write，并向用户说明。"
	}
	return a.finishRec(out, lits), false
}

func (a *App) recAnnotate(args map[string]any) (string, bool) {
	rid, ok := argInt64(args, "recording_id")
	if !ok || rid <= 0 {
		return "请提供 recording_id。", true
	}
	rec, err := a.store.GetRecording(rid)
	if err != nil || rec == nil {
		return fmt.Sprintf("录制 %d 不存在。", rid), true
	}
	var summary *string
	if v, exists := args["summary"]; exists && v != nil {
		s, ok := v.(string)
		if !ok {
			return "summary 必须是字符串。", true
		}
		summary = &s
	}
	var items []any
	if raw, exists := args["notes"]; exists && raw != nil {
		items, err = argArray(raw)
		if err != nil {
			return "notes 必须是数组：" + err.Error(), true
		}
	}
	if summary == nil && len(items) == 0 {
		return "请提供 summary（这次录制在做什么）或 notes（给业务请求写作用）。", true
	}
	batch := make([]RequestNote, 0, len(items))
	seen := map[int64]bool{}
	for i, item := range items {
		m, err := argObject(item)
		if err != nil {
			return fmt.Sprintf("notes[%d] 必须是对象。", i), true
		}
		reqID, ok := argInt64(m, "request_id")
		if !ok || reqID <= 0 {
			return fmt.Sprintf("notes[%d] 缺少 request_id。", i), true
		}
		if seen[reqID] {
			return fmt.Sprintf("notes 里 request_id %d 重复。", reqID), true
		}
		seen[reqID] = true
		q, err := a.store.GetRequest(reqID)
		if err != nil || q == nil {
			return fmt.Sprintf("request_id %d 不存在。", reqID), true
		}
		if q.RecordingID != rid {
			return fmt.Sprintf("request_id %d 不属于录制 %d。请只标注这次录制里的请求。", reqID, rid), true
		}
		cat := strings.TrimSpace(argStr(m, "category"))
		if !validNoteCategory(cat) {
			return fmt.Sprintf("request_id %d 的 category %q 不合法，只能是 query、write、auth、config、page、noise。", reqID, cat), true
		}
		purpose := ""
		if v, exists := m["purpose"]; exists && v != nil {
			s, ok := v.(string)
			if !ok {
				return fmt.Sprintf("request_id %d 的 purpose 必须是字符串。", reqID), true
			}
			purpose = strings.TrimSpace(s)
		}
		useful, err := argBoolPtr(m, "useful")
		if err != nil {
			return fmt.Sprintf("request_id %d 的 useful 必须是布尔值。", reqID), true
		}
		override, err := argBoolPtr(m, "noise_override")
		if err != nil {
			return fmt.Sprintf("request_id %d 的 noise_override 必须是布尔值。", reqID), true
		}
		batch = append(batch, RequestNote{
			RequestID: reqID, RecordingID: rid, Purpose: purpose, Category: cat,
			Useful: useful, NoiseOverride: override, Source: "agent",
		})
	}
	if summary != nil {
		if err := a.store.SetRecordingSummary(rid, *summary); err != nil {
			return "保存 summary 失败：" + err.Error(), true
		}
	}
	for _, n := range batch {
		if err := a.store.SetRequestNote(n); err != nil {
			return fmt.Sprintf("保存 request_id %d 的标注失败：%s", n.RequestID, err.Error()), true
		}
	}
	rec, err = a.store.GetRecording(rid)
	if err != nil {
		return "读取录制失败：" + err.Error(), true
	}
	stored, err := a.store.RequestNotes(rid)
	if err != nil {
		return "读取标注失败：" + err.Error(), true
	}
	lits, err := a.recordingSecretLiterals(rid)
	if err != nil {
		return "读取脱敏上下文失败：" + err.Error(), true
	}
	saved := make([]any, 0, len(batch))
	for _, n := range batch {
		if cur, ok := stored[n.RequestID]; ok {
			cp := cur
			saved = append(saved, noteView(&cp))
		}
	}
	sum := ""
	if rec != nil {
		sum = rec.Summary
	}
	return a.finishRec(map[string]any{
		"recording_id": rid, "summary": sum, "updated": len(batch), "notes": saved,
	}, lits), false
}

func (a *App) recListTargetPacks() (string, bool) {
	packs, err := a.store.ListPacks()
	if err != nil {
		return "读取流程包失败：" + err.Error(), true
	}
	tools, err := a.store.ListTools()
	if err != nil {
		return "读取工具失败：" + err.Error(), true
	}
	names := map[int64]string{}
	for _, t := range tools {
		names[t.ID] = t.Name
	}
	out := make([]map[string]any, 0, len(packs))
	for _, p := range packs {
		tn := make([]string, 0, len(p.ToolIDs))
		for _, id := range p.ToolIDs {
			if n, ok := names[id]; ok {
				tn = append(tn, n)
			}
		}
		out = append(out, map[string]any{"id": p.ID, "name": p.Name, "enabled": p.Enabled, "tool_names": tn})
	}
	return a.finishRec(map[string]any{
		"packs": out,
		"hint":  "这些是可以保存工具的业务流程包，不含内置包「录制分析」。用户没明确说用哪个时，把这份列表告诉用户并询问，得到答复后再调用 rec_save_tool。",
	}, nil), false
}

type recParamSpec struct {
	Name, From, Type, Description, Default string
	Required                               *bool
	HasDefault                             bool
}

func (a *App) recSaveTool(mc *mcpCtx, args map[string]any) (string, bool) {
	reqID, ok := argInt64(args, "request_id")
	if !ok || reqID <= 0 {
		return "请提供 request_id（来自 rec_get_recording 的 id）。", true
	}
	name := strings.TrimSpace(argStr(args, "name"))
	if name == "" {
		return "请提供 name（工具英文标识，例如 search_order）。", true
	}
	packRef := strings.TrimSpace(argStr(args, "pack"))
	if packRef == "" {
		return a.askPackText("必须指定 pack（流程包名称或 id），没有默认值。"), true
	}
	q, err := a.store.GetRequest(reqID)
	if err != nil || q == nil {
		return fmt.Sprintf("请求 %d 不存在。", reqID), true
	}
	specs, err := parseRecParams(args)
	if err != nil {
		return err.Error(), true
	}
	p, createName, msg := a.lookupTargetPack(packRef, argBool(args, "create_pack", false))
	if msg != "" {
		return msg, true
	}
	overwrite := argBool(args, "overwrite", false)
	var existingID int64
	if exist, err := a.store.GetToolByName(name); err == nil && exist != nil {
		if !overwrite {
			return fmt.Sprintf("工具标识 %q 已存在（id=%d）。不要覆盖，除非用户明确同意。用户同意后才再次调用并设置 overwrite=true。", name, exist.ID), true
		}
		existingID = exist.ID
	} else if err != nil && err != sql.ErrNoRows {
		return "读取工具失败：" + err.Error(), true
	}
	cands := a.recCandidates(q)
	chosen := make([]Candidate, 0, len(specs))
	overrides := map[string]recParamSpec{}
	names, sources := map[string]bool{}, map[string]bool{}
	for _, sp := range specs {
		c, ok := matchCandidate(cands, sp.From)
		if !ok {
			return fmt.Sprintf("参数 %q 的 from %q 对不上这条请求的候选字段。可用：%s。from 写成 query:关键字、body:字段路径 或 form:字段。", sp.Name, sp.From, formatCandList(cands)), true
		}
		if sp.Name != "" {
			c.Name = sp.Name
		}
		if sp.Type != "" {
			c.Type = sp.Type
		}
		source := c.Loc + ":" + c.Path
		hits := 0
		for _, candidate := range cands {
			if candidate.Loc == c.Loc && candidate.Path == c.Path {
				hits++
			}
		}
		if hits > 1 {
			return "参数来源在录制中重复，无法安全区分：" + source, true
		}
		if sources[source] {
			return "参数来源重复：" + source, true
		}
		if names[c.Name] {
			return "参数名称重复：" + c.Name + "。请为不同来源指定不同名称。", true
		}
		if !vaultNameRe.MatchString(c.Name) || isRefName(c.Name) {
			return "参数名称不合法：" + c.Name, true
		}
		names[c.Name], sources[source] = true, true
		chosen = append(chosen, c)
		overrides[source] = sp
	}
	lits := sensitiveLiterals(q)
	for _, sp := range specs {
		if sp.HasDefault && a.scrubRecText(sp.Default, lits) != sp.Default {
			return fmt.Sprintf("参数 %s 的 default 含有录制里的敏感值（Cookie、Token、密码等），已拒绝保存。请去掉 default。", sp.Name), true
		}
	}
	t, err := a.buildRecDraft(q, chosen)
	if err != nil {
		return "生成工具失败：" + err.Error(), true
	}
	t.Name = name
	t.ID = existingID
	if title := strings.TrimSpace(argStr(args, "title")); title != "" {
		t.Title = title
	}
	if desc := strings.TrimSpace(argStr(args, "description")); desc != "" {
		t.Description = desc
	}
	if strings.TrimSpace(t.Description) == "" {
		t.Description = t.Title
	}
	if strings.TrimSpace(t.Description) == "" {
		t.Description = "由录制保存的工具"
	}
	for _, c := range chosen {
		sp := overrides[c.Loc+":"+c.Path]
		for i := range t.Params {
			if t.Params[i].Name != c.Name {
				continue
			}
			if sp.Type != "" {
				t.Params[i].Type = sp.Type
			}
			if sp.Description != "" {
				t.Params[i].Description = sp.Description
			}
			if sp.Required != nil {
				t.Params[i].Required = *sp.Required
			}
			if sp.HasDefault {
				t.Params[i].Default = sp.Default
			}
			if c.Secret {
				t.Params[i].Default, t.Params[i].Required = "", true
			}
		}
	}
	if err := a.redactToolSecrets(t, q); err != nil {
		return "脱敏工具失败：" + err.Error(), true
	}
	if err := a.validateTool(t); err != nil {
		return "验证工具失败：" + err.Error(), true
	}
	created := false
	if p == nil {
		p = &Pack{Name: createName, Description: "由录制分析创建", Enabled: true, Scenarios: "保存自录制分析"}
		if err := a.store.SavePack(p); err != nil {
			return "创建流程包失败：" + err.Error(), true
		}
		created = true
	}
	if a.store.EnsureSite(t.URL) == nil {
		return "创建工具所属站点失败。", true
	}
	if err := a.store.SaveToolInPack(t, p.ID); err != nil {
		return "保存工具并加入流程包失败（已回滚）：" + err.Error(), true
	}
	a.broadcastToolsChanged()
	if mc != nil {
		mc.notifyToolsChanged()
	}
	return a.finishRec(map[string]any{
		"tool_id": t.ID, "name": t.Name, "title": t.Title,
		"pack_id": p.ID, "pack_name": p.Name, "pack_enabled": p.Enabled,
		"created_pack": created, "overwritten": existingID != 0,
		"input_schema": t.InputSchema(),
	}, lits), false
}

func (a *App) lookupTargetPack(ref string, create bool) (p *Pack, createName, msg string) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, "", a.askPackText("必须指定 pack（流程包名称或 id），没有默认值。")
	}
	packs, err := a.store.ListPacks()
	if err != nil {
		return nil, "", "读取流程包失败：" + err.Error()
	}
	if id, err := strconv.ParseInt(ref, 10, 64); err == nil {
		if id == recPackID {
			return nil, "", "不能把工具保存到内置包「录制分析」。请询问用户选择业务流程包。" + a.targetPackChoices()
		}
		for _, x := range packs {
			if x.ID == id {
				return x, "", ""
			}
		}
		return nil, "", fmt.Sprintf("流程包 id=%d 不存在。请询问用户要保存到哪个流程包，不要猜测。%s纯数字会被当成 id，不会用来新建流程包。", id, a.targetPackChoices())
	}
	for _, x := range packs {
		if x.Name == ref && (ref != recPackName || x.Enabled) {
			return x, "", ""
		}
	}
	if ref == recPackName {
		return nil, "", "不能把工具保存到内置包「录制分析」。请询问用户选择业务流程包。" + a.targetPackChoices()
	}
	var matches []*Pack
	for _, x := range packs {
		if strings.EqualFold(x.Name, ref) {
			matches = append(matches, x)
		}
	}
	if len(matches) == 1 {
		return matches[0], "", ""
	}
	if len(matches) > 1 {
		return nil, "", "流程包名称匹配不唯一，请使用精确名称或 id。选项：" + packNameList(matches)
	}
	if !create {
		return nil, "", fmt.Sprintf("流程包「%s」不存在。请询问用户要把工具保存到哪个流程包，不要自行创建。%s只有用户明确给出一个新的流程包名称时，才再次调用并设置 create_pack=true。", ref, a.targetPackChoices())
	}
	return nil, ref, ""
}

func (a *App) askPackText(prefix string) string {
	return prefix + "请先询问用户要把工具保存到哪个流程包，不要猜测，也不要默认新建。" + a.targetPackChoices() + "用户明确给出新名字后，才设置 create_pack=true。"
}

func (a *App) targetPackChoices() string {
	packs, err := a.store.ListPacks()
	if err != nil {
		return "读取现有流程包失败：" + err.Error()
	}
	if len(packs) == 0 {
		return "当前没有任何业务流程包。"
	}
	parts := make([]string, 0, len(packs))
	for _, p := range packs {
		state := "已开启"
		if !p.Enabled {
			state = "已关闭"
		}
		parts = append(parts, fmt.Sprintf("%s(id=%d,%s)", p.Name, p.ID, state))
	}
	return "现有流程包：" + strings.Join(parts, "、") + "。"
}

func parseRecParams(args map[string]any) ([]recParamSpec, error) {
	raw, ok := args["params"]
	if !ok || raw == nil {
		return nil, nil
	}
	arr, err := argArray(raw)
	if err != nil {
		return nil, fmt.Errorf("params 必须是数组：%s", err.Error())
	}
	out := make([]recParamSpec, 0, len(arr))
	for i, item := range arr {
		m, err := argObject(item)
		if err != nil {
			return nil, fmt.Errorf("params[%d] 必须是对象", i)
		}
		sp := recParamSpec{
			Name: strings.TrimSpace(argStr(m, "name")), From: strings.TrimSpace(argStr(m, "from")),
			Type: strings.TrimSpace(argStr(m, "type")), Description: strings.TrimSpace(argStr(m, "description")),
		}
		if sp.Type != "" && sp.Type != "string" && sp.Type != "number" && sp.Type != "integer" && sp.Type != "boolean" {
			return nil, fmt.Errorf("params[%d] 的 type 只能是 string、number、integer 或 boolean", i)
		}
		if sp.From == "" {
			return nil, fmt.Errorf("params[%d] 缺少 from（候选字段，例如 query:keyword 或 body:user.id）", i)
		}
		if v, exists := m["required"]; exists && v != nil {
			b, ok := v.(bool)
			if !ok {
				return nil, fmt.Errorf("params[%d] 的 required 必须是布尔值", i)
			}
			sp.Required = &b
		}
		if v, exists := m["default"]; exists && v != nil {
			s, ok := scalarString(v)
			if !ok {
				return nil, fmt.Errorf("params[%d] 的 default 必须是字符串或数字", i)
			}
			sp.Default = s
			sp.HasDefault = true
		}
		out = append(out, sp)
	}
	return out, nil
}

func matchCandidate(cands []Candidate, from string) (Candidate, bool) {
	from = strings.TrimSpace(from)
	loc, path, qualified := splitFrom(from)
	if !qualified {
		path = from
	}
	var exact, aliases []Candidate
	for _, c := range cands {
		if qualified && !strings.EqualFold(c.Loc, loc) {
			continue
		}
		if c.Path == path {
			exact = append(exact, c)
		} else if c.Name == path {
			aliases = append(aliases, c)
		}
	}
	hits := exact
	if len(hits) == 0 {
		hits = aliases
	}
	if len(hits) == 0 {
		return Candidate{}, false
	}
	for _, c := range hits[1:] {
		if c.Loc != hits[0].Loc || c.Path != hits[0].Path {
			return Candidate{}, false
		}
	}
	return hits[0], true
}

func splitFrom(from string) (loc, path string, ok bool) {
	low := strings.ToLower(from)
	for _, p := range []string{"query:", "body:", "form:", "query.", "body.", "form."} {
		if strings.HasPrefix(low, p) {
			loc = strings.TrimRight(strings.TrimSuffix(p, ":"), ".")
			path = from[len(p):]
			if path == "" {
				return "", "", false
			}
			return loc, path, true
		}
	}
	return "", "", false
}

func formatCandList(cs []Candidate) string {
	if len(cs) == 0 {
		return "（这条请求没有可参数化的 query/body/form 字段）"
	}
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		tag := ""
		if c.Secret || isSensitiveKey(c.Path) {
			tag = "(敏感，会自动处理)"
		}
		parts = append(parts, c.Loc+":"+c.Path+tag)
		if len(parts) >= 40 {
			parts = append(parts, "…")
			break
		}
	}
	return strings.Join(parts, "、")
}

func noteView(n *RequestNote) any {
	if n == nil {
		return nil
	}
	return map[string]any{
		"request_id": n.RequestID, "purpose": n.Purpose, "category": n.Category,
		"useful": n.Useful, "noise_override": n.NoiseOverride, "source": n.Source,
	}
}

func argInt64(args map[string]any, key string) (int64, bool) {
	v, ok := args[key]
	if !ok || v == nil {
		return 0, false
	}
	switch x := v.(type) {
	case float64:
		return int64(x), true
	case int:
		return int64(x), true
	case int64:
		return x, true
	case json.Number:
		n, err := x.Int64()
		return n, err == nil
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}

func argBool(args map[string]any, key string, def bool) bool {
	v, ok := args[key]
	if !ok || v == nil {
		return def
	}
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		switch strings.ToLower(strings.TrimSpace(x)) {
		case "1", "true", "yes", "on":
			return true
		case "0", "false", "no", "off":
			return false
		}
	}
	return def
}

func argBoolPtr(m map[string]any, key string) (*bool, error) {
	v, ok := m[key]
	if !ok || v == nil {
		return nil, nil
	}
	b, ok := v.(bool)
	if !ok {
		return nil, fmt.Errorf("type %T", v)
	}
	return &b, nil
}

func argNonNeg(args map[string]any, key string, def int) int {
	if _, ok := args[key]; !ok || args[key] == nil {
		return def
	}
	n := argInt(args, key, def)
	if n < 0 {
		return 0
	}
	return n
}

func argArray(v any) ([]any, error) {
	switch x := v.(type) {
	case []any:
		return x, nil
	case string:
		var a []any
		if strings.TrimSpace(x) == "" {
			return nil, nil
		}
		if err := json.Unmarshal([]byte(x), &a); err != nil {
			return nil, err
		}
		return a, nil
	default:
		return nil, fmt.Errorf("类型 %T", v)
	}
}

func scalarString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	default:
		return "", false
	}
}

func addSecret(out *[]string, s string) {
	if s == "" || s == secretMask || placeholderRe.MatchString(s) {
		return
	}
	*out = append(*out, s)
}

func addHeaderSecret(out *[]string, name, v string) {
	addSecret(out, v)
	switch strings.ToLower(name) {
	case "cookie":
		for _, line := range strings.Split(v, "\n") {
			r := http.Request{Header: http.Header{"Cookie": []string{line}}}
			for _, c := range r.Cookies() {
				addSecret(out, c.Value)
			}
			// Also retain values from malformed cookies the HTTP parser skips.
			for _, field := range strings.Split(line, ";") {
				if _, val, ok := strings.Cut(field, "="); ok {
					addSecret(out, strings.Trim(strings.TrimSpace(val), `"`))
				}
			}
		}
	case "set-cookie":
		// Captures may fold Set-Cookie headers onto one line. A comma in
		// Expires is not a separator; a comma followed by name= is.
		for _, line := range setCookieLines(v) {
			resp := http.Response{Header: http.Header{"Set-Cookie": []string{strings.TrimSpace(line)}}}
			for _, c := range resp.Cookies() {
				addSecret(out, c.Value)
			}
			first, _, _ := strings.Cut(line, ";")
			if _, val, ok := strings.Cut(first, "="); ok {
				addSecret(out, strings.Trim(strings.TrimSpace(val), `"`))
			}
		}
	}
	fields := strings.Fields(v)
	if len(fields) == 2 && !strings.Contains(v, "=") {
		addSecret(out, fields[len(fields)-1])
	}
}

var splitSetCookies = regexp.MustCompile("[,\\r\\n]+\\s*([!#$%&'*+.^_`|~0-9A-Za-z-]+=)")

func setCookieLines(v string) []string {
	var lines []string
	start := 0
	for _, m := range splitSetCookies.FindAllStringSubmatchIndex(v, -1) {
		lines = append(lines, v[start:m[0]])
		start = m[2]
	}
	return append(lines, v[start:])
}

func headerValue(h map[string]string, key string) string {
	for k, v := range h {
		if strings.EqualFold(k, key) {
			return v
		}
	}
	return ""
}

func isURLHeader(k string) bool {
	switch strings.ToLower(k) {
	case "location", "referer", "referrer", "origin", "content-location", "refresh", "link", "destination", "x-original-url", "x-rewrite-url":
		return true
	}
	return false
}

// Also handles URL-bearing Refresh/Link headers without treating their syntax
// as part of the URL.
var headerURLRe = regexp.MustCompile(`(?i)(?:https?://|/)[^\s<>"';,]+`)

func headerURLs(name, v string, visit func(string) string) string {
	if !strings.EqualFold(name, "Link") && !strings.EqualFold(name, "Refresh") {
		return visit(strings.TrimSpace(v))
	}
	return headerURLRe.ReplaceAllStringFunc(v, visit)
}

// Parse each pair separately: url.ParseQuery discards an entire pair containing
// a semicolon or bad escape. Retain that pair so token=... always gets masked.
func tolerantForm(body string) url.Values {
	vals := url.Values{}
	for _, pair := range strings.Split(body, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		if decoded, err := url.QueryUnescape(k); err == nil {
			k = decoded
		}
		if decoded, err := url.QueryUnescape(v); err == nil {
			v = decoded
		}
		vals[k] = append(vals[k], v)
	}
	return vals
}

func bodyKind(body, contentType string) (string, map[string]string, error) {
	media, params, err := mime.ParseMediaType(contentType)
	if contentType != "" && err != nil {
		return "", nil, err
	}
	media = strings.ToLower(media)
	switch {
	case media == "application/json" || strings.HasSuffix(media, "+json"):
		return "json", params, nil
	case media == "application/x-www-form-urlencoded":
		return "form", params, nil
	case strings.HasPrefix(media, "multipart/"):
		if params["boundary"] == "" {
			return "", nil, fmt.Errorf("missing multipart boundary")
		}
		return "multipart", params, nil
	}
	// Sniff old captures that have no content type as well as mislabeled JSON.
	t := strings.TrimSpace(body)
	if strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
		return "json", params, nil
	}
	if media == "" && strings.Contains(t, "=") {
		return "form", params, nil
	}
	return "text", params, nil
}

func parseRecJSON(body string) (any, error) {
	d := json.NewDecoder(strings.NewReader(body))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return nil, fmt.Errorf("incomplete or trailing JSON")
	}
	return v, nil
}

type recPart struct {
	name, filename, contentType, value string
}

func parseRecMultipart(body, boundary string) ([]recPart, error) {
	r := multipart.NewReader(strings.NewReader(body), boundary)
	var parts []recPart
	for {
		p, err := r.NextPart()
		if err == io.EOF {
			return parts, nil
		}
		if err != nil {
			return nil, err
		}
		value, err := io.ReadAll(p)
		if err != nil {
			return nil, err
		}
		if p.FormName() == "" {
			return nil, fmt.Errorf("multipart part has no field name")
		}
		parts = append(parts, recPart{p.FormName(), p.FileName(), p.Header.Get("Content-Type"), string(value)})
	}
}

func sensitiveQueryValues(raw string) []string {
	var out []string
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return nil
	}
	if u.User != nil {
		if p, ok := u.User.Password(); ok {
			addSecret(&out, p)
		}
	}
	for k, vs := range tolerantForm(u.RawQuery) {
		if !isSensitiveKey(k) {
			continue
		}
		for _, v := range vs {
			addSecret(&out, v)
		}
	}
	return out
}

func collectJSONSecrets(v any, sensitive bool, out *[]string) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			collectJSONSecrets(val, sensitive || isSensitiveKey(k), out)
		}
	case []any:
		for _, val := range x {
			collectJSONSecrets(val, sensitive, out)
		}
	default:
		if sensitive && v != nil {
			addSecret(out, fmt.Sprint(v))
		}
	}
}

// Keep complete, decoded secret fields found before a capture truncation. The
// body is still hidden on any parse failure; this only protects echoes elsewhere.
func collectPartialJSONSecrets(body string, out *[]string) {
	d := json.NewDecoder(strings.NewReader(body))
	d.UseNumber()
	var walk func(bool) error
	walk = func(sensitive bool) error {
		token, err := d.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{':
				for d.More() {
					key, err := d.Token()
					if err != nil {
						return err
					}
					k, ok := key.(string)
					if !ok {
						return fmt.Errorf("invalid JSON key")
					}
					if err := walk(sensitive || isSensitiveKey(k)); err != nil {
						return err
					}
				}
			case '[':
				for d.More() {
					if err := walk(sensitive); err != nil {
						return err
					}
				}
			default:
				return fmt.Errorf("unexpected JSON delimiter")
			}
			_, err := d.Token()
			return err
		}
		if sensitive && token != nil {
			addSecret(out, fmt.Sprint(token))
		}
		return nil
	}
	_ = walk(false)
}

func collectBodySecrets(body, contentType string, out *[]string) {
	kind, params, err := bodyKind(body, contentType)
	if err != nil {
		return
	}
	switch kind {
	case "json":
		if j, err := parseRecJSON(body); err == nil {
			collectJSONSecrets(j, false, out)
		} else {
			collectPartialJSONSecrets(body, out)
		}
	case "form":
		for k, vals := range tolerantForm(body) {
			if isSensitiveKey(k) {
				for _, v := range vals {
					addSecret(out, v)
				}
			}
		}
	case "multipart":
		if parts, err := parseRecMultipart(body, params["boundary"]); err == nil {
			for _, p := range parts {
				if isSensitiveKey(p.name) {
					addSecret(out, p.value)
				} else {
					collectBodySecrets(p.value, p.contentType, out)
				}
			}
		}
	}
}

func responseContentType(q *ReqRecord) string {
	if ct := headerValue(q.RespHeaders, "Content-Type"); ct != "" {
		return ct
	}
	return q.RespMime
}

func sensitiveLiterals(q *ReqRecord) []string {
	if q == nil {
		return nil
	}
	var out []string
	for _, headers := range []map[string]string{q.ReqHeaders, q.RespHeaders} {
		for k, v := range headers {
			if isSensitiveHeader(k) {
				addHeaderSecret(&out, k, v)
			}
			if isURLHeader(k) {
				headerURLs(k, v, func(raw string) string {
					out = append(out, sensitiveQueryValues(raw)...)
					return raw
				})
			}
		}
	}
	out = append(out, sensitiveQueryValues(q.URL)...)
	collectBodySecrets(q.ReqBody, headerValue(q.ReqHeaders, "Content-Type"), &out)
	collectBodySecrets(q.RespBody, responseContentType(q), &out)
	return out
}

func literalForms(lit string) []string {
	b, _ := json.Marshal(lit)
	escaped := string(b[1 : len(b)-1])
	quoted := strconv.Quote(lit)
	return []string{lit, url.QueryEscape(lit), url.PathEscape(lit), escaped, quoted[1 : len(quoted)-1], html.EscapeString(lit)}
}

func tokenChar(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' }

func replaceLiteral(s, lit, replacement string, short bool) string {
	if lit == "" {
		return s
	}
	if !short {
		return strings.ReplaceAll(s, lit, replacement)
	}
	var out strings.Builder
	start := 0
	for pos := 0; pos <= len(s)-len(lit); {
		rel := strings.Index(s[pos:], lit)
		if rel < 0 {
			break
		}
		i := pos + rel
		end := i + len(lit)
		left, right := true, true
		if i > 0 {
			r, _ := utf8.DecodeLastRuneInString(s[:i])
			left = !tokenChar(r)
		}
		if end < len(s) {
			r, _ := utf8.DecodeRuneInString(s[end:])
			right = !tokenChar(r)
		}
		if left && right {
			out.WriteString(s[start:i])
			out.WriteString(replacement)
			start = end
		}
		pos = end
	}
	out.WriteString(s[start:])
	return out.String()
}

func replaceLiterals(s string, lits []string) string {
	cp := append([]string(nil), lits...)
	sort.Slice(cp, func(i, j int) bool { return len(cp[i]) > len(cp[j]) })
	seen := map[string]bool{}
	for _, lit := range cp {
		if lit == "" || lit == secretMask || seen[lit] || placeholderRe.MatchString(lit) {
			continue
		}
		seen[lit] = true
		for _, form := range literalForms(lit) {
			s = replaceLiteral(s, form, secretMask, len(lit) < 4)
		}
	}
	return s
}

func containsLiteral(s string, lits []string) bool { return replaceLiterals(s, lits) != s }

func maskURLSensitive(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return "[URL hidden: could not be safely sanitized]"
	}
	u.User = nil
	q := tolerantForm(u.RawQuery)
	parts := make([]string, 0)
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		for _, v := range q[k] {
			if v != "" && isSensitiveKey(k) {
				v = secretMask
			}
			ev := v
			if v != secretMask {
				ev = url.QueryEscape(v)
			}
			parts = append(parts, url.QueryEscape(k)+"="+ev)
		}
	}
	u.RawQuery = strings.Join(parts, "&")
	return u.String()
}

const hiddenRecBody = "[body hidden: could not be safely sanitized]"

// A body has already been scrubbed as parsed values before clipping/encoding.
// Do not treat its serialized JSON as another string to search and replace.
type recSafeText string

func (a *App) sanitizeBodyJSON(v any, sensitive bool, lits []string) any {
	if sensitive && v != nil {
		return secretMask
	}
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range x {
			out[k] = a.sanitizeBodyJSON(val, isSensitiveKey(k), lits)
		}
		return out
	case []any:
		for i := range x {
			x[i] = a.sanitizeBodyJSON(x[i], false, lits)
		}
		return x
	case string:
		return a.scrubRecText(x, lits)
	case json.Number:
		if a.scrubRecText(x.String(), lits) != x.String() {
			return secretMask
		}
	case bool:
		if a.scrubRecText(strconv.FormatBool(x), lits) != strconv.FormatBool(x) {
			return secretMask
		}
	}
	return v
}

func (a *App) sanitizeRecBody(body, contentType string, lits []string) (string, bool) {
	if strings.TrimSpace(body) == "" {
		return body, false
	}
	kind, params, err := bodyKind(body, contentType)
	if err != nil {
		return hiddenRecBody, true
	}
	switch kind {
	case "json":
		j, err := parseRecJSON(body)
		if err != nil {
			return hiddenRecBody, true
		}
		return string(compactJSON(a.sanitizeBodyJSON(j, false, lits))), false
	case "form":
		vals := tolerantForm(body)
		for k, vs := range vals {
			for i, v := range vs {
				if isSensitiveKey(k) {
					vs[i] = secretMask
				} else {
					vs[i] = a.scrubRecText(v, lits)
				}
			}
		}
		return vals.Encode(), false
	case "multipart":
		parts, err := parseRecMultipart(body, params["boundary"])
		if err != nil {
			return hiddenRecBody, true
		}
		out := make([]map[string]any, 0, len(parts))
		for _, p := range parts {
			value := secretMask
			if !isSensitiveKey(p.name) {
				value, _ = a.sanitizeRecBody(p.value, p.contentType, lits)
			}
			out = append(out, map[string]any{"name": a.scrubRecText(p.name, lits), "filename": a.scrubRecText(p.filename, lits), "value": value})
		}
		return string(compactJSON(out)), false
	default:
		return a.scrubRecText(body, lits), false
	}
}

func (a *App) recBodyView(body, ct string, lits []string, max int) (recSafeText, int, bool, bool) {
	safe, hidden := a.sanitizeRecBody(body, ct, lits)
	if hidden {
		return recSafeText(safe), len(body), false, true
	}
	shown, _, cut := clipText(safe, max)
	return recSafeText(shown), len(body), cut, false
}

func (a *App) maskHeaderMap(h map[string]string, lits []string) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		lk := strings.ToLower(k)
		if strings.HasPrefix(k, ":") || dropHeaders[lk] {
			continue
		}
		if isSensitiveHeader(k) {
			if strings.TrimSpace(v) != "" {
				out[k] = secretMask
			}
			continue
		}
		if isURLHeader(k) {
			v = headerURLs(k, v, maskURLSensitive)
		}
		out[k] = a.scrubRecText(v, lits)
	}
	return out
}

func maskedQuery(raw string, lits []string, a *App) []map[string]any {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return []map[string]any{}
	}
	out := make([]map[string]any, 0)
	for _, kv := range strings.Split(u.RawQuery, "&") {
		if kv == "" {
			continue
		}
		k, v, _ := strings.Cut(kv, "=")
		if decoded, err := url.QueryUnescape(k); err == nil {
			k = decoded
		}
		if decoded, err := url.QueryUnescape(v); err == nil {
			v = decoded
		}
		if isSensitiveKey(k) && v != "" {
			v = secretMask
		} else if a != nil {
			v = a.scrubRecText(v, lits)
		} else {
			v = replaceLiterals(v, lits)
		}
		out = append(out, map[string]any{"key": k, "value": v})
	}
	return out
}

func clipText(s string, max int) (string, int, bool) {
	total := len(s)
	if max < 0 {
		max = 0
	}
	if total <= max {
		return s, total, false
	}
	return truncateBytes(s, max), total, true
}

func truncateBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 0 {
		return ""
	}
	i := max
	for i > 0 && !utf8.RuneStart(s[i]) {
		i--
	}
	return s[:i]
}

// Replace template text outside {{...}} only. Newly introduced vault references
// are protected on subsequent passes as well.
func outsideRecRefs(s string, fn func(string) string) string {
	var out strings.Builder
	start := 0
	for _, m := range placeholderRe.FindAllStringIndex(s, -1) {
		out.WriteString(fn(s[start:m[0]]))
		out.WriteString(s[m[0]:m[1]])
		start = m[1]
	}
	out.WriteString(fn(s[start:]))
	return out.String()
}

func (a *App) recTemplateText(s string, lits []string) string {
	type pair struct{ name, value string }
	var pairs []pair
	if a.vault != nil {
		a.vault.mu.RLock()
		for name, e := range a.vault.cache {
			if e.typ == "secret" && e.value != "" {
				pairs = append(pairs, pair{name, e.value})
			}
		}
		a.vault.mu.RUnlock()
	}
	sort.Slice(pairs, func(i, j int) bool {
		if len(pairs[i].value) == len(pairs[j].value) {
			return pairs[i].name < pairs[j].name
		}
		return len(pairs[i].value) > len(pairs[j].value)
	})
	for _, p := range pairs {
		for _, form := range literalForms(p.value) {
			s = outsideRecRefs(s, func(part string) string { return replaceLiteral(part, form, "{{secret."+p.name+"}}", len(p.value) < 4) })
		}
	}
	return outsideRecRefs(s, func(part string) string { return a.scrubRecText(part, lits) })
}

func encodeRecForm(vals url.Values) string {
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var parts []string
	for _, k := range keys {
		for _, value := range vals[k] {
			value = outsideRecRefs(value, url.QueryEscape)
			parts = append(parts, url.QueryEscape(k)+"="+value)
		}
	}
	return strings.Join(parts, "&")
}

func transformRecURL(raw string, field func(string, string) string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	u.User = nil
	u.Path = field("", u.Path)
	u.RawPath = ""
	u.Fragment = field("", u.Fragment)
	vals := tolerantForm(u.RawQuery)
	for k, vs := range vals {
		for i, v := range vs {
			vs[i] = field(k, v)
		}
	}
	u.RawQuery = encodeRecForm(vals)
	base := u.String()
	// url.URL escapes braces in paths/fragments; references are template syntax.
	base = strings.ReplaceAll(strings.ReplaceAll(base, "%7B", "{"), "%7D", "}")
	return base, nil
}

func recScalarType(v any) string {
	if _, ok := v.(json.Number); ok {
		return "number"
	}
	return jsonType(v)
}

func newRecSecretParam(t *Tool, path string, v any) string {
	base := paramName(path)
	name := base
	used := map[string]bool{}
	for _, p := range t.Params {
		used[p.Name] = true
	}
	for _, p := range t.Placeholders() {
		used[p] = true
	}
	for i := 2; used[name]; i++ {
		name = fmt.Sprintf("%s_%d", base, i)
	}
	t.Params = append(t.Params, Param{Name: name, Type: recScalarType(v), Required: true, Description: "敏感字段，调用时另填。"})
	return "{{" + name + "}}"
}

// Work on decoded field values, never on a serialized JSON document. Keep
// existing references intact and leave non-sensitive numbers/booleans typed.
func parameterizeRawSecrets(t *Tool, q *ReqRecord) error {
	var err error
	t.URL, err = transformRecURL(t.URL, func(key, value string) string {
		if isSensitiveKey(key) && value != "" && !placeholderRe.MatchString(value) {
			return newRecSecretParam(t, key, value)
		}
		return value
	})
	if err != nil {
		return err
	}
	kind, _, err := bodyKind(t.Body, headerValue(q.ReqHeaders, "Content-Type"))
	if err != nil {
		return err
	}
	if strings.TrimSpace(t.Body) == "" {
		return nil
	}
	switch kind {
	case "json":
		j, err := parseRecJSON(t.Body)
		if err != nil {
			return fmt.Errorf("请求体无法安全解析")
		}
		var walk func(any, string, bool) any
		walk = func(v any, path string, sensitive bool) any {
			switch x := v.(type) {
			case map[string]any:
				keys := make([]string, 0, len(x))
				for k := range x {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					x[k] = walk(x[k], path+"."+k, sensitive || isSensitiveKey(k))
				}
			case []any:
				for i := range x {
					x[i] = walk(x[i], fmt.Sprintf("%s[%d]", path, i), sensitive)
				}
			default:
				if sensitive && v != nil && fmt.Sprint(v) != "" && !placeholderRe.MatchString(fmt.Sprint(v)) {
					return newRecSecretParam(t, path, v)
				}
			}
			return v
		}
		t.Body = string(compactJSON(walk(j, "", false)))
	case "form":
		vals := tolerantForm(t.Body)
		for k, vs := range vals {
			for i, v := range vs {
				if isSensitiveKey(k) && v != "" && !placeholderRe.MatchString(v) {
					vs[i] = newRecSecretParam(t, k, v)
				}
			}
		}
		t.Body = encodeRecForm(vals)
	case "multipart":
		return fmt.Errorf("multipart 请求体无法安全保存")
	}
	return nil
}

func (a *App) redactToolSecrets(t *Tool, q *ReqRecord) error {
	lits := sensitiveLiterals(q)
	if err := parameterizeRawSecrets(t, q); err != nil {
		return err
	}
	var err error
	t.URL, err = transformRecURL(t.URL, func(_, v string) string { return a.recTemplateText(v, lits) })
	if err != nil {
		return err
	}
	kind, _, err := bodyKind(t.Body, headerValue(q.ReqHeaders, "Content-Type"))
	if err != nil {
		return err
	}
	if strings.TrimSpace(t.Body) != "" {
		switch kind {
		case "json":
			j, err := parseRecJSON(t.Body)
			if err != nil {
				return err
			}
			var walk func(any) any
			walk = func(v any) any {
				switch x := v.(type) {
				case map[string]any:
					for k, val := range x {
						x[k] = walk(val)
					}
				case []any:
					for i := range x {
						x[i] = walk(x[i])
					}
				case string:
					return a.recTemplateText(x, lits)
				default:
					if v != nil {
						if safe := a.recTemplateText(fmt.Sprint(v), lits); safe != fmt.Sprint(v) {
							return newRecSecretParam(t, "value", v)
						}
					}
				}
				return v
			}
			t.Body = string(compactJSON(walk(j)))
		case "form":
			vals := tolerantForm(t.Body)
			for _, vs := range vals {
				for i, v := range vs {
					vs[i] = a.recTemplateText(v, lits)
				}
			}
			t.Body = encodeRecForm(vals)
		default:
			t.Body = a.recTemplateText(t.Body, lits)
		}
	}
	t.Title = a.scrubRecText(t.Title, lits)
	t.Description = a.scrubRecText(t.Description, lits)
	for k, v := range t.Headers {
		if isSensitiveHeader(k) && !placeholderRe.MatchString(v) {
			delete(t.Headers, k)
			continue
		}
		if isURLHeader(k) {
			v = headerURLs(k, v, func(raw string) string {
				safe, err := transformRecURL(raw, func(_, value string) string { return a.recTemplateText(value, lits) })
				if err != nil {
					return secretMask
				}
				return safe
			})
		}
		t.Headers[k] = a.recTemplateText(v, lits)
	}
	for i := range t.Params {
		p := &t.Params[i]
		if a.scrubRecText(p.Default, lits) != p.Default || p.Default == secretMask || isSensitiveKey(p.Name) {
			p.Default, p.Required = "", true
		}
		p.Description = a.scrubRecText(p.Description, lits)
	}
	return nil
}
