package main

import (
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
2. rec_get_recording 看全貌（默认隐藏噪音）。相同 method+host+模板路径已合并，query 只给参数名。
3. 看不清作用时再 rec_get_request 看单条脱敏详情和可参数化字段 candidates。Cookie、Authorization、Token、密码和配置管理里的密钥都已遮盖。
4. rec_annotate 给所有业务相关请求写作用（purpose）、分类（category）和是否属于本流程（useful）。noise_override 可纠正误判：true 强制当噪音，false 强制当业务请求。会修改数据的请求 category 必须是 write，并在回复用户时说明。
5. 只保留完成用户目标所需的最少请求。
6. 如果用户没有明确说保存到哪个流程包：先 rec_list_target_packs，把现有流程包告诉用户并询问。得到答复之前不要调用 rec_save_tool，也不要自己起一个包名。
7. rec_save_tool 保存。pack 必填，没有默认值。新建包只有在用户明确给出名字时才把 create_pack 设为 true。同名工具要用户同意后才 overwrite=true。
这些工具只读录制、写本机的标注和工具定义，不会重放请求。`
)

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

func isSensitiveHeader(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "cookie" || n == "set-cookie" || n == "authorization" || n == "proxy-authorization" {
		return true
	}
	return IsCredHeader(name) || isSensitiveKey(n)
}

func isWriteMethod(method string) bool {
	switch strings.ToUpper(strings.TrimSpace(method)) {
	case "POST", "PUT", "PATCH", "DELETE", "WS":
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
	return mcpAnnotations(readOnly, false, readOnly)
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
			"description": "【录制分析】列出本机录制：id、名称、时间、请求数、业务请求数、origin（起始网址的源；起始网址为空时用第一条业务请求的源）。按包说明 guide 的顺序使用。",
			"inputSchema": recSchema(map[string]any{}),
			"annotations": recAnn(true)},
		{"name": "rec_get_recording", "title": "查看录制全貌",
			"description": "【录制分析】查看压缩请求行：相同 method+host+模板路径合并，长数字/hex/UUID 写成 {id}，h 是 hosts 下标，note 短键 c/p/u 为分类、作用、是否属于本流程。默认不含噪音，suspect_noise 列出疑似误判接口；按包说明 guide 的顺序使用。",
			"inputSchema": recSchema(map[string]any{
				"recording_id":          map[string]any{"type": "integer", "description": "录制 id，来自 rec_list_recordings"},
				"include_noise":         map[string]any{"type": "boolean", "description": "true 时连噪音请求一起返回。默认 false"},
				"exclude_reasons":       map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "排除这些噪音原因。不会自动排除「静态资源」，要排除就写明"},
				"include_noise_reasons": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "只额外包含这些噪音原因，业务请求始终包含"},
				"offset":                map[string]any{"type": "integer", "description": "合并后的行偏移，默认 0"},
				"limit":                 map[string]any{"type": "integer", "description": "最多返回多少行，默认 50，最大 200"},
			}, "recording_id"),
			"annotations": recAnn(true)},
		{"name": "rec_get_request", "title": "查看单条请求",
			"description": "【录制分析】查看单条脱敏详情（请求头、响应头、正文、candidates、标注）；Cookie、Token、密码和配置管理密钥会遮盖，POST/PUT/PATCH/DELETE 可能改数据，须标 category=write 并告诉用户。按包说明 guide 的顺序使用。",
			"inputSchema": recSchema(map[string]any{
				"request_id": map[string]any{"type": "integer", "description": "请求 id，来自 rec_get_recording"},
				"max_body":   map[string]any{"type": "integer", "description": "请求体和响应体各自最多返回的字节数，默认 4000"},
			}, "request_id"),
			"annotations": recAnn(true)},
		{"name": "rec_annotate", "title": "标注录制",
			"description": "【写操作，仅在用户明确要求时调用】 【录制分析·写入标注】写 summary，并用 request_id 或 request_ids 批量标注；apply_to_group=true 套用到同一模板路径组，会改数据的请求 category 必须是 write 并告诉用户。按包说明 guide 的顺序使用。",
			"inputSchema": recSchema(map[string]any{
				"recording_id": map[string]any{"type": "integer", "description": "录制 id"},
				"summary":      map[string]any{"type": "string", "description": "这次录制对应的业务流程，一两句话"},
				"notes": map[string]any{"type": "array", "description": "要写入的标注。覆盖到的 request_id 不要重复", "items": recSchema(map[string]any{
					"request_id":     map[string]any{"type": "integer", "description": "单个请求 id。与 request_ids 至少给一个"},
					"request_ids":    map[string]any{"type": "array", "items": map[string]any{"type": "integer"}, "description": "多个请求 id，可代替 request_id"},
					"apply_to_group": map[string]any{"type": "boolean", "description": "true 时把本条标注套用到 request_id 所在的 method+host+模板路径组"},
					"purpose":        map[string]any{"type": "string", "description": "中文一句话说明这个接口的作用"},
					"category":       map[string]any{"type": "string", "enum": []string{"query", "write", "auth", "config", "page", "noise"}, "description": "query / write / auth / config / page / noise。会改数据的用 write"},
					"useful":         map[string]any{"type": "boolean", "description": "是否属于要保存的业务流程"},
					"noise_override": map[string]any{"type": "boolean", "description": "true 强制当噪音，false 强制当业务请求，省略则沿用自动判断"},
				}, "category")},
			}, "recording_id"),
			"annotations": recAnn(false)},
		{"name": "rec_list_target_packs", "title": "列出可保存的流程包",
			"description": "【录制分析】列出可保存工具的业务流程包（id、名称、是否开启、已有工具名），不含内置包「录制分析」；用户没明确指定流程包时先询问。按包说明 guide 的顺序使用。",
			"inputSchema": recSchema(map[string]any{}),
			"annotations": recAnn(true)},
		{"name": "rec_save_tool", "title": "保存为工具",
			"description": "【写操作，仅在用户明确要求时调用】 【录制分析·写入工具】把一条录制请求保存成参数化工具；pack 必填，没明确指定时不要调用，dry_run=true 只返回模板不写入，敏感值不会落盘。按包说明 guide 的顺序使用。",
			"inputSchema": recSchema(map[string]any{
				"request_id":  map[string]any{"type": "integer", "description": "要保存的请求 id"},
				"pack":        map[string]any{"type": "string", "description": "流程包名称或 id。必填，没有默认值。用户没明确指定时不要调用"},
				"name":        map[string]any{"type": "string", "description": "工具英文标识，例如 search_order"},
				"title":       map[string]any{"type": "string", "description": "给人看的短标题"},
				"description": map[string]any{"type": "string", "description": "工具做什么、什么时候调用"},
				"params": map[string]any{"type": "array", "description": "要变成参数的字段", "items": recSchema(map[string]any{
					"name":        map[string]any{"type": "string", "description": "参数名"},
					"from":        map[string]any{"type": "string", "description": "候选路径：query:键、body:字段路径、form:字段 或 multipart:字段"},
					"type":        map[string]any{"type": "string", "description": "string、number、integer 或 boolean"},
					"description": map[string]any{"type": "string"},
					"required":    map[string]any{"type": "boolean"},
					"default":     map[string]any{"type": "string", "description": "不要填录制里的 Token、密码或 Cookie"},
				}, "from")},
				"create_pack": map[string]any{"type": "boolean", "description": "仅当用户明确说出一个还不存在的流程包名称时设为 true。默认 false"},
				"overwrite":   map[string]any{"type": "boolean", "description": "同名工具已存在时，只有用户同意覆盖才设为 true。默认 false"},
				"dry_run":     map[string]any{"type": "boolean", "description": "true 时校验并返回将保存的模板，不创建流程包、不写入工具。默认 false"},
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
		// Interpolated data is sanitized before this text is composed. Do not
		// mask the finished sentence: a vault value such as "overwrite" must
		// not rewrite server text like overwrite=true.
		if strings.HasPrefix(text, recStructuredPrefix) {
			return textResult(text[len(recStructuredPrefix):], true)
		}
		return textResult(string(compactJSON(map[string]any{"error": text})), true)
	}
	return textResult(text, isErr)
}

// redactEcho sanitizes one interpolated fragment. The surrounding template is
// composed afterwards and must not be scrubbed again.
func (a *App) redactEcho(s string, lits []string) string {
	if strings.TrimSpace(s) == "" || a == nil {
		return s
	}
	return a.sanitizeString(s, false, 0, lits)
}

const recStructuredPrefix = "\x1e"

func recProblemResult(problems []string) (string, bool) {
	if len(problems) == 0 {
		return "", false
	}
	msg := problems[0]
	if len(problems) > 1 {
		msg = "发现 " + strconv.Itoa(len(problems)) + " 个问题：" + strings.Join(problems, "；")
	}
	return recStructuredPrefix + string(compactJSON(map[string]any{"error": msg, "problems": problems})), true
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
		briefs = append(briefs, toolBrief{Name: d["name"].(string), Description: d["description"].(string), InputSchema: d["inputSchema"], Annotations: d["annotations"]})
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
		return a.sanitizeString(v.String(), false, 0, lits)
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
	if a != nil && a.vault != nil {
		for _, x := range a.vault.secretVariants() {
			if crossFieldLiteral(x) {
				lits = append(lits, x)
			}
		}
	}
	var safe []string
	for _, x := range lits {
		if crossFieldLiteral(x) {
			safe = append(safe, x)
		}
	}
	return outsideRecRefs(s, func(part string) string {
		part = replaceLiterals(part, lits)
		// Encoding-aware vault/recording forms, but only for literals that are
		// already safe to search as substrings (see crossFieldLiteral).
		return scrubSecretText(part, nil, safe)
	})
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
	kind, params, err := bodyKind(q.ReqBody, headerValue(q.ReqHeaders, "Content-Type"))
	var parts []recPart
	if err == nil && kind == "multipart" {
		parts, _ = parseRecMultipart(q.ReqBody, params["boundary"])
	}
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
	for _, p := range parts {
		if p.filename != "" {
			continue
		}
		cs = append(cs, Candidate{Loc: "multipart", Path: p.name, Name: paramName(p.name), Type: "string", Example: p.value, Suggest: !noisyParam.MatchString(p.name)})
	}
	lits := sensitiveLiterals(q)
	for i := range cs {
		c := &cs[i]
		c.raw = c.Example
		// Short vault values ("1", "true") must not mark page numbers or
		// websocket opcodes as secrets. Exact vault matches still apply to
		// values that are eligible as cross-field literals.
		if a.vault != nil && crossFieldLiteral(c.raw) {
			if ref := a.vault.FindByValue(c.raw); ref != "" && a.vault.TypeOf(ref) == "secret" {
				c.Secret, c.Ref, c.RefExists = true, ref, true
			}
		}
		// Ancestry, not the leaf name: credentials.value stays secret after rename.
		if pathSensitive(c.Path) {
			c.Secret = true
		}
		if crossFieldLiteral(c.raw) && (containsLiteral(c.raw, lits) || a.scrubRecText(c.raw, nil) != c.raw) {
			c.Secret = true
		}
		if a.revealsSecret(c.raw, lits) {
			c.Secret = true
		}
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
	kind, params, err := bodyKind(copy.ReqBody, headerValue(copy.ReqHeaders, "Content-Type"))
	if err != nil {
		return nil, fmt.Errorf("请求体无法安全解析")
	}
	var mpBody, mpBoundary string
	if kind == "multipart" {
		mpBody = copy.ReqBody
		mpBoundary = params["boundary"]
		if _, err := parseRecMultipart(mpBody, mpBoundary); err != nil {
			return nil, fmt.Errorf("multipart 请求体无法安全解析")
		}
		copy.ReqBody = ""
	} else if kind == "json" && strings.TrimSpace(copy.ReqBody) != "" {
		if _, err := parseRecJSON(copy.ReqBody); err != nil {
			return nil, fmt.Errorf("请求体 JSON 不完整，无法安全保存")
		}
	} else if kind == "form" {
		copy.ReqBody = tolerantForm(copy.ReqBody).Encode()
	}
	seen := map[string]bool{}
	prepared := make([]Candidate, 0, len(chosen))
	for _, c := range chosen {
		seen[c.Loc+":"+c.Path] = true
		if !isWholePlaceholder(c.raw) {
			prepared = append(prepared, c)
		}
	}
	for _, c := range a.recCandidates(q) {
		if c.Secret && !seen[c.Loc+":"+c.Path] && !isWholePlaceholder(c.raw) {
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
		// Draft construction never writes the vault: reuse an existing entry,
		// otherwise leave Ref empty so the field becomes a required parameter.
		if c.Type != "string" || !crossFieldLiteral(c.raw) {
			c.Ref = ""
		}
	}
	t, err := BuildDraft(&copy, chosen)
	if err != nil {
		return nil, err
	}
	if kind == "multipart" {
		repl := map[string]string{}
		used := map[string]bool{}
		for _, p := range t.Params {
			used[p.Name] = true
		}
		for _, c := range chosen {
			if c.Loc != "multipart" {
				continue
			}
			if c.Ref != "" {
				repl[c.Path] = "{{secret." + c.Ref + "}}"
				continue
			}
			name := c.Name
			if name == "" {
				name = paramName(c.Path)
			}
			base := name
			for i := 2; used[name]; i++ {
				name = fmt.Sprintf("%s_%d", base, i)
			}
			used[name] = true
			desc := "multipart 字段 " + c.Path
			ex := c.Example
			reqd := !optionalParam.MatchString(name)
			if c.Secret {
				desc = removedSecretDesc
				ex = ""
				reqd = true
			}
			typ := c.Type
			if typ == "" {
				typ = "string"
			}
			t.Params = append(t.Params, Param{Name: name, Type: typ, Required: reqd, Default: ex, Description: desc, Secret: c.Secret})
			repl[c.Path] = "{{" + name + "}}"
		}
		body, err := rebuildMultipart(mpBody, mpBoundary, repl)
		if err != nil {
			return nil, fmt.Errorf("multipart 请求体无法安全保存")
		}
		t.Body = body
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
		origin := originOf(rec.StartURL)
		if origin == "" {
			var oerr error
			origin, oerr = a.recordingBusinessOrigin(rec.ID)
			if oerr != nil {
				return "读取录制失败：" + oerr.Error(), true
			}
		}
		items = append(items, map[string]any{
			"id":             rec.ID,
			"name":           rec.Name,
			"created_at":     rec.CreatedAt,
			"request_count":  rec.RequestCount,
			"business_count": rec.UsefulCount,
			"origin":         origin,
		})
	}
	return a.finishRec(map[string]any{"recordings": items}, lits), false
}

func (a *App) recordingBusinessOrigin(id int64) (string, error) {
	rows, err := a.store.ListRequests(id)
	if err != nil {
		return "", err
	}
	notes, err := a.store.RequestNotes(id)
	if err != nil {
		return "", err
	}
	for i := range rows {
		applyRequestNote(&rows[i], notes)
		if rows[i].Noise {
			continue
		}
		if o := originOf(rows[i].URL); o != "" {
			return o, nil
		}
	}
	return "", nil
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
	excludeReasons, err := argStringSlice(args, "exclude_reasons")
	if err != nil {
		return err.Error(), true
	}
	includeReasons, err := argStringSlice(args, "include_noise_reasons")
	if err != nil {
		return err.Error(), true
	}
	offset := argNonNeg(args, "offset", 0)
	limit := argNonNeg(args, "limit", 50)
	if _, ok := args["limit"]; !ok || args["limit"] == nil || limit == 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	type member struct {
		id                   int64
		seq                  int
		status               int
		noise, heuristic     bool
		method, host, path   string
		rawPath, res, reason string
		note                 *RequestNote
		keys                 map[string]struct{}
	}
	type group struct {
		key        string
		host, path string
		example    string
		templated  bool
		members    []member
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
		host, templated, rawPath, key := requestGroupKey(reqs[i].Method, reqs[i].URL)
		g := groups[key]
		if g == nil {
			g = &group{key: key, host: host, path: templated, example: rawPath, templated: templated != rawPath}
			groups[key] = g
			order = append(order, key)
		}
		keys := map[string]struct{}{}
		if u, err := url.Parse(reqs[i].URL); err == nil && u != nil {
			for k := range u.Query() {
				if k != "" {
					keys[k] = struct{}{}
				}
			}
		}
		g.members = append(g.members, member{
			id: int64(reqs[i].ID), seq: reqs[i].Seq, status: reqs[i].Status,
			noise: reqs[i].Noise, heuristic: reqs[i].NoiseHeuristic,
			method: strings.ToUpper(reqs[i].Method), host: host, path: templated, rawPath: rawPath,
			res: reqs[i].ResourceType, reason: reqs[i].NoiseReason, note: reqs[i].Note, keys: keys,
		})
	}
	includeMember := func(m member) bool {
		if !m.noise {
			return true
		}
		if reasonListed(excludeReasons, m.reason) {
			return false
		}
		if len(includeReasons) > 0 {
			return reasonListed(includeReasons, m.reason)
		}
		return includeNoise
	}
	hosts := []string{}
	hostIndex := map[string]int{}
	hostOf := func(h string) int {
		if i, ok := hostIndex[h]; ok {
			return i
		}
		hostIndex[h] = len(hosts)
		hosts = append(hosts, h)
		return hostIndex[h]
	}
	rows := make([]map[string]any, 0, len(order))
	var suspect []map[string]any
	for _, key := range order {
		g := groups[key]
		mixed := false
		if len(g.members) > 0 {
			first := g.members[0].noise
			for _, m := range g.members[1:] {
				if m.noise != first {
					mixed = true
					break
				}
			}
		}
		var included []member
		for _, m := range g.members {
			if includeMember(m) {
				included = append(included, m)
			}
		}
		suspectGroup := false
		for _, m := range g.members {
			if isSuspectNoise(m.method, m.res, m.path, m.reason, m.noise) {
				suspectGroup = true
				break
			}
		}
		if len(included) == 0 {
			if !includeNoise && suspectGroup && len(suspect) < 30 {
				m0 := g.members[0]
				item := map[string]any{
					"id": m0.id, "method": m0.method, "h": hostOf(g.host), "path": g.path,
					"reason": m0.reason, "count": len(g.members),
				}
				if len(g.members) > 1 {
					ids := make([]int64, 0, len(g.members))
					for _, m := range g.members {
						ids = append(ids, m.id)
						if len(ids) == 50 {
							break
						}
					}
					item["ids"] = ids
				}
				suspect = append(suspect, item)
			}
			continue
		}
		m0 := included[0]
		keys := map[string]struct{}{}
		// Identity and member ids come from every member. count is the filtered
		// size, so a business view still counts only business rows.
		ids := make([]int64, 0, len(g.members))
		for _, m := range g.members {
			ids = append(ids, m.id)
		}
		for _, m := range included {
			for k := range m.keys {
				keys[k] = struct{}{}
			}
		}
		qkeys := make([]string, 0, len(keys))
		for k := range keys {
			qkeys = append(qkeys, k)
		}
		sort.Strings(qkeys)
		row := map[string]any{
			"id": g.members[0].id, "seq": m0.seq, "count": len(included), "method": m0.method,
			"h": hostOf(g.host), "path": g.path,
		}
		if g.templated {
			row["example_path"] = g.example
		}
		if len(qkeys) > 0 {
			row["query_keys"] = qkeys
		}
		if m0.status != 0 {
			row["status"] = m0.status
		}
		if m0.res != "" {
			row["resource_type"] = m0.res
		}
		if m0.noise {
			row["noise"] = true
		}
		if m0.reason != "" {
			row["noise_reason"] = m0.reason
		}
		if m0.heuristic != m0.noise {
			row["noise_heuristic"] = m0.heuristic
		}
		if note := noteCompact(m0.note); note != nil {
			row["note"] = note
		}
		idList := ids
		truncIDs := false
		if len(idList) > 50 {
			idList = idList[:50]
			truncIDs = true
		}
		row["ids"] = idList
		if truncIDs {
			row["ids_truncated"] = true
		}
		if mixed {
			row["mixed_noise"] = true
		}
		if suspectGroup && m0.noise {
			row["suspect"] = true
		}
		rows = append(rows, row)
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
	hasMore := offset+len(page) < total
	var next any
	if hasMore {
		next = offset + len(page)
	}
	if hosts == nil {
		hosts = []string{}
	}
	out := map[string]any{
		"recording_id": rec.ID, "name": rec.Name,
		"request_count": rec.RequestCount, "business_count": rec.UsefulCount,
		"hosts": hosts, "offset": offset, "limit": limit,
		"total_groups": total, "group_count": total,
		"has_more": hasMore, "next_offset": next,
		"requests": page,
	}
	if strings.TrimSpace(rec.Summary) != "" {
		out["summary"] = rec.Summary
	}
	if includeNoise {
		out["include_noise"] = true
	}
	if !includeNoise && len(suspect) > 0 {
		out["suspect_noise"] = suspect
	}
	return a.finishRec(out, lits), false
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
	reqShown, reqTotal, reqCut, reqHidden, reqPartial, reqOutline := a.recBodyView(q.ReqBody, headerValue(q.ReqHeaders, "Content-Type"), lits, maxBody)
	respShown, respTotal, respCut, respHidden, respPartial, respOutline := a.recBodyView(q.RespBody, responseContentType(q), lits, maxBody)
	cands := a.recCandidates(q)
	candOut := make([]map[string]any, 0, len(cands))
	candBytes := 0
	for _, c := range cands {
		example := c.Example
		secret := c.Secret || pathSensitive(c.Path)
		if secret {
			example = ""
		} else {
			example = a.sanitizeString(example, false, 0, lits)
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
	shownURL := a.maskURLSensitive(q.URL, lits)
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
	if reqPartial {
		out["req_body_partial"] = true
	}
	if respPartial {
		out["resp_body_partial"] = true
	}
	if marked, note := bodyTruncationInfo("请求体", reqShown, reqTotal, reqPartial, reqCut, maxBody); note != "" {
		out["req_body"] = marked
		out["req_body_truncation"] = recSafeText(note)
	}
	if marked, note := bodyTruncationInfo("响应体", respShown, respTotal, respPartial, respCut, maxBody); note != "" {
		out["resp_body"] = marked
		out["resp_body_truncation"] = recSafeText(note)
	}
	if reqOutline != nil {
		out["req_body_outline"] = reqOutline
	}
	if respOutline != nil {
		out["resp_body_outline"] = respOutline
	}
	if q.RespBody == "" && (strings.EqualFold(q.ResourceType, "Document") || strings.EqualFold(q.ResourceType, "Other")) {
		out["resp_body_note"] = recSafeText("响应体未采集（页面文档/重定向等不记录响应体）")
	}
	switch strings.ToUpper(q.Method) {
	case "GET", "HEAD", "OPTIONS":
		if q.ReqBody == "" {
			out["req_body_note"] = recSafeText("请求体未采集（该方法通常没有请求体）")
		}
	}
	if isWriteMethod(q.Method) {
		out["write_hint"] = recSafeText("POST/PUT/PATCH/DELETE 可能修改数据，请结合接口语义和标注判断；实际修改数据的请求必须标 category=write，并向用户说明。")
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
	reqs, err := a.store.ListRequests(rid)
	if err != nil {
		return "读取请求失败：" + err.Error(), true
	}
	byID := map[int64]*ReqRecord{}
	groupIDs := map[string][]int64{}
	for i := range reqs {
		byID[reqs[i].ID] = &reqs[i]
		_, _, _, key := requestGroupKey(reqs[i].Method, reqs[i].URL)
		groupIDs[key] = append(groupIDs[key], reqs[i].ID)
	}
	batch := make([]RequestNote, 0, len(items))
	seen := map[int64]bool{}
	written := make([]int64, 0)
	for i, item := range items {
		m, err := argObject(item)
		if err != nil {
			return fmt.Sprintf("notes[%d] 必须是对象。", i), true
		}
		var ids []int64
		if reqID, ok := argInt64(m, "request_id"); ok && reqID > 0 {
			ids = append(ids, reqID)
		} else if _, exists := m["request_id"]; exists && m["request_id"] != nil {
			return fmt.Sprintf("notes[%d] 的 request_id 不合法。", i), true
		}
		if rawIDs, exists := m["request_ids"]; exists && rawIDs != nil {
			arr, err := argArray(rawIDs)
			if err != nil {
				return fmt.Sprintf("notes[%d] 的 request_ids 必须是数组。", i), true
			}
			for _, one := range arr {
				id, ok := scalarInt64(one)
				if !ok || id <= 0 {
					return fmt.Sprintf("notes[%d] 的 request_ids 含有不合法的 id。", i), true
				}
				ids = append(ids, id)
			}
		}
		if len(ids) == 0 {
			return fmt.Sprintf("notes[%d] 缺少 request_id 或 request_ids。", i), true
		}
		anchor := ids[0]
		if _, ok := argInt64(m, "request_id"); ok {
			anchor = ids[0]
		}
		if argBool(m, "apply_to_group", false) {
			reqID, ok := argInt64(m, "request_id")
			if !ok || reqID <= 0 {
				return fmt.Sprintf("notes[%d] 设置了 apply_to_group 但缺少 request_id。", i), true
			}
			q := byID[reqID]
			if q == nil {
				return fmt.Sprintf("request_id %d 不存在。", reqID), true
			}
			_, _, _, key := requestGroupKey(q.Method, q.URL)
			ids = append(append([]int64{}, groupIDs[key]...), ids...)
			anchor = reqID
		}
		uniq := make([]int64, 0, len(ids))
		local := map[int64]bool{}
		for _, id := range ids {
			if local[id] {
				continue
			}
			local[id] = true
			uniq = append(uniq, id)
		}
		cat := strings.TrimSpace(argStr(m, "category"))
		if !validNoteCategory(cat) {
			shown := secretMask
			if lits, lerr := a.recordingSecretLiterals(rid); lerr == nil {
				shown = a.redactEcho(cat, lits)
			}
			return fmt.Sprintf("request_id %d 的 category %q 不合法，只能是 query、write、auth、config、page、noise。", anchor, shown), true
		}
		purpose := ""
		if v, exists := m["purpose"]; exists && v != nil {
			s, ok := v.(string)
			if !ok {
				return fmt.Sprintf("request_id %d 的 purpose 必须是字符串。", anchor), true
			}
			purpose = strings.TrimSpace(s)
		}
		useful, err := argBoolPtr(m, "useful")
		if err != nil {
			return fmt.Sprintf("request_id %d 的 useful 必须是布尔值。", anchor), true
		}
		override, err := argBoolPtr(m, "noise_override")
		if err != nil {
			return fmt.Sprintf("request_id %d 的 noise_override 必须是布尔值。", anchor), true
		}
		for _, id := range uniq {
			if seen[id] {
				return fmt.Sprintf("notes 里 request_id %d 重复。", id), true
			}
			seen[id] = true
			q := byID[id]
			if q == nil {
				got, err := a.store.GetRequest(id)
				if err != nil || got == nil {
					return fmt.Sprintf("request_id %d 不存在。", id), true
				}
				return fmt.Sprintf("request_id %d 不属于录制 %d。请只标注这次录制里的请求。", id, rid), true
			}
			batch = append(batch, RequestNote{
				RequestID: id, RecordingID: rid, Purpose: purpose, Category: cat,
				Useful: useful, NoiseOverride: override, Source: "agent",
			})
			written = append(written, id)
		}
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
	lits, err := a.recordingSecretLiterals(rid)
	if err != nil {
		return "读取脱敏上下文失败：" + err.Error(), true
	}
	if written == nil {
		written = []int64{}
	}
	return a.finishRec(map[string]any{
		"recording_id": rid, "updated": len(batch), "request_ids": written, "summary_updated": summary != nil,
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
		"hint":  recSafeText("这些是可以保存工具的业务流程包，不含内置包「录制分析」。用户没明确说用哪个时，把这份列表告诉用户并询问，得到答复后再调用 rec_save_tool。"),
	}, nil), false
}

type recParamSpec struct {
	Name, From, Type, Description, Default string
	Required                               *bool
	HasDefault                             bool
}

func (a *App) recSaveTool(mc *mcpCtx, args map[string]any) (string, bool) {
	var problems []string
	reqID, reqOK := argInt64(args, "request_id")
	if !reqOK || reqID <= 0 {
		problems = append(problems, "请提供 request_id（来自 rec_get_recording 的 id）。")
	}
	name := strings.TrimSpace(argStr(args, "name"))
	if name == "" {
		problems = append(problems, "请提供 name（工具英文标识，例如 search_order）。")
	} else if !toolNameRe.MatchString(name) {
		problems = append(problems, "name 不合法，只能包含字母、数字、下划线和连字符，最长 64。")
	}
	packRef := strings.TrimSpace(argStr(args, "pack"))
	if packRef == "" {
		problems = append(problems, a.askPackText("必须指定 pack（流程包名称或 id），没有默认值。"))
	}
	specs, paramProblems := parseRecParams(args)
	problems = append(problems, paramProblems...)
	var q *ReqRecord
	if reqOK && reqID > 0 {
		got, err := a.store.GetRequest(reqID)
		if err != nil || got == nil {
			problems = append(problems, fmt.Sprintf("请求 %d 不存在。", reqID))
		} else {
			q = got
		}
	}
	chosen := make([]Candidate, 0, len(specs))
	overrides := map[string]recParamSpec{}
	var saveLits []string
	if q != nil {
		cands := a.recCandidates(q)
		names, sources := map[string]bool{}, map[string]bool{}
		saveLits = sensitiveLiterals(q)
		for _, sp := range specs {
			c, ok := matchCandidate(cands, sp.From)
			if !ok {
				problems = append(problems, fmt.Sprintf("参数 %q 的 from %q 对不上这条请求的候选字段。可用：%s。from 写成 query:关键字、body:字段路径、form:字段 或 multipart:字段。", a.redactEcho(sp.Name, saveLits), a.redactEcho(sp.From, saveLits), a.formatCandList(cands, saveLits)))
				continue
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
				problems = append(problems, "参数来源在录制中重复，无法安全区分："+a.redactEcho(source, saveLits))
				continue
			}
			if sources[source] {
				problems = append(problems, "参数来源重复："+a.redactEcho(source, saveLits))
				continue
			}
			if names[c.Name] {
				problems = append(problems, "参数名称重复："+a.redactEcho(c.Name, saveLits)+"。请为不同来源指定不同名称。")
				continue
			}
			if !vaultNameRe.MatchString(c.Name) || isRefName(c.Name) {
				problems = append(problems, "参数名称不合法："+a.redactEcho(c.Name, saveLits))
				continue
			}
			if a.revealsSecret(c.Name, saveLits) {
				problems = append(problems, "参数名称含有密钥或凭证，不能作为标识："+a.redactEcho(c.Name, saveLits))
				continue
			}
			if sp.HasDefault && a.revealsSecret(sp.Default, saveLits) {
				problems = append(problems, fmt.Sprintf("参数 %s 的 default 含有录制里的敏感值（Cookie、Token、密码等），已拒绝保存。请去掉 default。", a.redactEcho(sp.Name, saveLits)))
				continue
			}
			if sp.Description != "" && a.revealsSecret(sp.Description, saveLits) {
				sp.Description = a.sanitizeString(sp.Description, false, 0, saveLits)
			}
			names[c.Name], sources[source] = true, true
			chosen = append(chosen, c)
			overrides[source] = sp
		}
	}
	var p *Pack
	var createName string
	if packRef != "" {
		var msg string
		p, createName, msg = a.lookupTargetPack(packRef, argBool(args, "create_pack", false))
		if msg != "" {
			problems = append(problems, msg)
		}
	}
	overwrite := argBool(args, "overwrite", false)
	var existingID int64
	var existingTool *Tool
	if name != "" && toolNameRe.MatchString(name) {
		if isEntryTool(name) {
			problems = append(problems, "工具名 "+name+" 是阶梯模式的入口工具名，已被保留，请换一个名字")
		} else if isRecTool(name) {
			problems = append(problems, "工具名 "+name+" 是内置录制分析工具名，已被保留，请换一个名字")
		} else if a.revealsSecret(name, saveLits) {
			problems = append(problems, "name 含有密钥或凭证，不能作为工具标识。")
		}
		if exist, err := a.store.GetToolByName(name); err == nil && exist != nil {
			if !overwrite {
				problems = append(problems, fmt.Sprintf("工具标识 %q 已存在（id=%d）。不要覆盖，除非用户明确同意。用户同意后才再次调用并设置 overwrite=true。", a.redactEcho(name, saveLits), exist.ID))
			} else {
				existingID = exist.ID
				existingTool = exist
			}
		} else if err != nil && err != sql.ErrNoRows {
			return "读取工具失败：" + a.redactEcho(err.Error(), saveLits), true
		}
	}
	if createName != "" && a.revealsSecret(createName, saveLits) {
		problems = append(problems, "流程包名称含有密钥或凭证，不能作为标识。")
	}
	if len(problems) > 0 {
		return recProblemResult(problems)
	}
	dry := argBool(args, "dry_run", false)
	lits := sensitiveLiterals(q)
	t, err := a.buildRecDraft(q, chosen)
	if err != nil {
		return "生成工具失败：" + err.Error(), true
	}
	t.Name = name
	t.ID = existingID
	if existingTool != nil {
		t.Config.ResultFormat = existingTool.Config.ResultFormat
		t.Config.ResultSelector = existingTool.Config.ResultSelector
		t.Config.DetectFailure = existingTool.Config.DetectFailure
		t.Config.OpKind = existingTool.Config.OpKind
	}
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
				t.Params[i].Secret = true
				// §1: a sensitive field is a required parameter with an empty
				// default. Do not keep the captured value in the description.
				t.Params[i].Default = ""
				t.Params[i].Required = true
				t.Params[i].Description = removedSecretDesc
			}
		}
	}
	if err := a.redactToolSecrets(t, q); err != nil {
		return "脱敏工具失败：" + err.Error(), true
	}
	if err := a.validateTool(t); err != nil {
		return "验证工具失败：" + err.Error(), true
	}
	if dry {
		keys := make([]string, 0, len(t.Headers))
		for k := range t.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return a.finishRec(map[string]any{
			"dry_run": true, "name": t.Name, "title": t.Title, "method": t.Method,
			"url": recSafeText(t.URL), "header_keys": keys, "body": recSafeText(t.Body),
			"input_schema": a.mcpInputSchema(t),
		}, lits), false
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
		"input_schema": a.mcpInputSchema(t),
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
		return nil, "", fmt.Sprintf("流程包「%s」不存在。请询问用户要把工具保存到哪个流程包，不要自行创建。%s只有用户明确给出一个新的流程包名称时，才再次调用并设置 create_pack=true。", a.redactEcho(ref, nil), a.targetPackChoices())
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
		name := p.Name
		if a != nil {
			name = a.redactEcho(p.Name, nil)
		}
		parts = append(parts, fmt.Sprintf("%s(id=%d,%s)", name, p.ID, state))
	}
	return "现有流程包：" + strings.Join(parts, "、") + "。"
}

func parseRecParams(args map[string]any) ([]recParamSpec, []string) {
	raw, ok := args["params"]
	if !ok || raw == nil {
		return nil, nil
	}
	arr, err := argArray(raw)
	if err != nil {
		return nil, []string{"params 必须是数组：" + err.Error()}
	}
	var problems []string
	out := make([]recParamSpec, 0, len(arr))
	for i, item := range arr {
		m, err := argObject(item)
		if err != nil {
			problems = append(problems, fmt.Sprintf("params[%d] 必须是对象", i))
			continue
		}
		sp := recParamSpec{
			Name: strings.TrimSpace(argStr(m, "name")), From: strings.TrimSpace(argStr(m, "from")),
			Type: strings.TrimSpace(argStr(m, "type")), Description: strings.TrimSpace(argStr(m, "description")),
		}
		if sp.Type != "" && sp.Type != "string" && sp.Type != "number" && sp.Type != "integer" && sp.Type != "boolean" {
			problems = append(problems, fmt.Sprintf("params[%d] 的 type 只能是 string、number、integer 或 boolean", i))
		}
		if sp.From == "" {
			problems = append(problems, fmt.Sprintf("params[%d] 缺少 from（候选字段，例如 query:keyword 或 body:user.id）", i))
		}
		if v, exists := m["required"]; exists && v != nil {
			b, ok := v.(bool)
			if !ok {
				problems = append(problems, fmt.Sprintf("params[%d] 的 required 必须是布尔值", i))
			} else {
				sp.Required = &b
			}
		}
		if v, exists := m["default"]; exists && v != nil {
			s, ok := scalarString(v)
			if !ok {
				problems = append(problems, fmt.Sprintf("params[%d] 的 default 必须是字符串或数字", i))
			} else {
				sp.Default = s
				sp.HasDefault = true
			}
		}
		if sp.From != "" {
			out = append(out, sp)
		}
	}
	return out, problems
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
	for _, p := range []string{"query:", "body:", "form:", "multipart:", "query.", "body.", "form.", "multipart."} {
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

func (a *App) formatCandList(cs []Candidate, lits []string) string {
	if len(cs) == 0 {
		return "（这条请求没有可参数化的 query/body/form 字段）"
	}
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		tag := ""
		if c.Secret || pathSensitive(c.Path) {
			tag = "(敏感，会自动处理)"
		}
		parts = append(parts, a.redactEcho(c.Loc+":"+c.Path, lits)+tag)
		if len(parts) >= 30 {
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

func noteCompact(n *RequestNote) map[string]any {
	if n == nil {
		return nil
	}
	out := map[string]any{}
	if c := strings.TrimSpace(n.Category); c != "" {
		out["c"] = c
	}
	if p := strings.TrimSpace(n.Purpose); p != "" {
		out["p"] = p
	}
	if n.Useful != nil {
		out["u"] = *n.Useful
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func argStringSlice(args map[string]any, key string) ([]string, error) {
	v, ok := args[key]
	if !ok || v == nil {
		return nil, nil
	}
	arr, err := argArray(v)
	if err != nil {
		return nil, fmt.Errorf("%s 必须是字符串数组", key)
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		s, ok := item.(string)
		if !ok {
			return nil, fmt.Errorf("%s 必须是字符串数组", key)
		}
		s = strings.TrimSpace(s)
		if s != "" {
			out = append(out, s)
		}
	}
	return out, nil
}

func scalarInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case float64:
		if x != float64(int64(x)) {
			return 0, false
		}
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
	if !crossFieldLiteral(s) {
		return
	}
	*out = append(*out, s)
}

func considerCookieValue(out *[]string, name, val string) {
	val = strings.Trim(strings.TrimSpace(val), `"`)
	if cookieNameSensitive(name) || len(val) >= 16 {
		addSecret(out, val)
	}
}

func addHeaderSecret(out *[]string, name, v string) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "cookie":
		for _, line := range strings.Split(v, "\n") {
			r := http.Request{Header: http.Header{"Cookie": []string{line}}}
			for _, c := range r.Cookies() {
				considerCookieValue(out, c.Name, c.Value)
			}
			for _, field := range strings.Split(line, ";") {
				n, val, ok := strings.Cut(field, "=")
				if !ok {
					continue
				}
				considerCookieValue(out, strings.TrimSpace(n), val)
			}
		}
	case "set-cookie":
		for _, line := range setCookieLines(v) {
			resp := http.Response{Header: http.Header{"Set-Cookie": []string{strings.TrimSpace(line)}}}
			for _, c := range resp.Cookies() {
				considerCookieValue(out, c.Name, c.Value)
			}
			first, _, _ := strings.Cut(line, ";")
			if n, val, ok := strings.Cut(first, "="); ok {
				considerCookieValue(out, strings.TrimSpace(n), val)
			}
		}
	default:
		addSecret(out, v)
		fields := strings.Fields(v)
		if len(fields) == 2 && !strings.Contains(v, "=") {
			addSecret(out, fields[len(fields)-1])
		}
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
		for _, v := range vs {
			v = fullyUnescapeQuery(v)
			if isSensitiveKey(k) {
				addSecret(&out, v)
			}
			// A non-sensitive key can still carry URL-encoded JSON with a token.
			collectSecretsFromString(v, 0, &out)
		}
	}
	return out
}

func fullyUnescapeQuery(s string) string {
	cur := s
	for i := 0; i < 3; i++ {
		if !strings.ContainsAny(cur, "%+") {
			break
		}
		dec, err := url.QueryUnescape(cur)
		if err != nil || dec == cur {
			break
		}
		cur = dec
	}
	return cur
}

func collectJSONSecrets(v any, sensitive bool, out *[]string) {
	collectSecretsFromValue(v, sensitive, 0, out)
}

func collectRawCredentialShapes(body string, out *[]string) {
	for _, m := range jwtRe.FindAllString(body, -1) {
		addSecret(out, m)
	}
	for _, sm := range bearerRe.FindAllStringSubmatch(body, -1) {
		if len(sm) >= 3 {
			addSecret(out, sm[2])
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
	collectRawCredentialShapes(body, out)
	kind, params, err := bodyKind(body, contentType)
	if err != nil {
		if bodyWasTruncated(body) {
			if j, ok := decodePartialJSON(body); ok {
				collectSecretsFromValue(j, false, 0, out)
			}
		}
		return
	}
	switch kind {
	case "json":
		if j, err := parseRecJSON(body); err == nil {
			collectSecretsFromValue(j, false, 0, out)
		} else {
			if j, ok := decodePartialJSON(body); ok {
				collectSecretsFromValue(j, false, 0, out)
			}
			collectPartialJSONSecrets(body, out)
		}
	case "form":
		for k, vals := range tolerantForm(body) {
			if isSensitiveKey(k) {
				for _, v := range vals {
					addSecret(out, v)
					collectSecretsFromString(v, 0, out)
				}
			} else {
				for _, v := range vals {
					collectSecretsFromString(v, 0, out)
				}
			}
		}
	case "multipart":
		if parts, err := parseRecMultipart(body, params["boundary"]); err == nil {
			for _, p := range parts {
				if p.filename != "" && !textualPart(p.contentType, p.value) {
					continue
				}
				if isSensitiveKey(p.name) {
					addSecret(out, p.value)
				}
				collectBodySecrets(p.value, p.contentType, out)
			}
		}
	default:
		collectSecretsFromString(body, 0, out)
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
		if lit == "" || lit == secretMask || seen[lit] || isWholePlaceholder(lit) {
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

func (a *App) maskURLSensitive(raw string, lits []string) string {
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
			v = fullyUnescapeQuery(v)
			if v != "" && isSensitiveKey(k) {
				v = secretMask
			} else if v != "" {
				v = a.sanitizeString(v, false, 0, lits)
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
		return string(compactJSON(a.sanitizeValue(j, false, 0, lits))), false
	case "form":
		vals := tolerantForm(body)
		for k, vs := range vals {
			for i, v := range vs {
				if isSensitiveKey(k) && strings.TrimSpace(v) != "" {
					vs[i] = secretMask
				} else {
					vs[i] = a.sanitizeString(v, false, 0, lits)
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
			value := p.value
			if p.filename != "" && !textualPart(p.contentType, p.value) {
				value = omittedFileValue
			} else if isSensitiveKey(p.name) && strings.TrimSpace(p.value) != "" {
				value = secretMask
			} else {
				value = a.sanitizeString(p.value, false, 0, lits)
			}
			out = append(out, map[string]any{"name": a.sanitizeString(p.name, false, 0, lits), "filename": a.sanitizeString(p.filename, false, 0, lits), "value": value})
		}
		return string(compactJSON(out)), false
	default:
		return a.sanitizeString(body, false, 0, lits), false
	}
}

func (a *App) sanitizedTruncated(body, ct string, lits []string) (string, any) {
	prefix := cutAtTruncMarker(body)
	kind, params, err := bodyKind(prefix, ct)
	if multipartContent(ct) || (err == nil && kind == "multipart") || looksLikeMultipart(prefix) {
		boundary := ""
		if params != nil {
			boundary = params["boundary"]
		}
		return "", a.multipartPartialOutline(prefix, boundary, lits)
	}
	if structuredKind(prefix) != "" {
		safe := a.sanitizeString(prefix, false, 0, lits)
		if safe == structuredOmitted || safe == "" {
			return "", map[string]any{}
		}
		return safe, nil
	}
	return a.sanitizeString(prefix, false, 0, lits), nil
}

func multipartContent(ct string) bool {
	return strings.Contains(strings.ToLower(ct), "multipart/")
}

func looksLikeMultipart(body string) bool {
	line := body
	if i := strings.IndexAny(body, "\r\n"); i >= 0 {
		line = body[:i]
	}
	line = strings.TrimSpace(line)
	return strings.HasPrefix(line, "--") && strings.Contains(strings.ToLower(body), "content-disposition:")
}

func sniffBoundary(body string) string {
	line := body
	if i := strings.IndexAny(body, "\r\n"); i >= 0 {
		line = body[:i]
	}
	line = strings.TrimSpace(line)
	if strings.HasPrefix(line, "--") && len(line) > 2 {
		return strings.TrimPrefix(line, "--")
	}
	return ""
}

func textualPart(contentType, value string) bool {
	if strings.Contains(value, "\x00") || !utf8.ValidString(value) {
		return false
	}
	ct := strings.ToLower(contentType)
	switch {
	case strings.HasPrefix(ct, "text/"), strings.Contains(ct, "json"), strings.Contains(ct, "xml"),
		strings.Contains(ct, "javascript"), strings.Contains(ct, "form-urlencoded"), ct == "":
		return true
	case strings.HasPrefix(ct, "image/"), strings.HasPrefix(ct, "audio/"), strings.HasPrefix(ct, "video/"):
		return false
	}
	for _, r := range value {
		if r != '\n' && r != '\r' && r != '\t' && (r < 32 || r == 0x7f) {
			return false
		}
	}
	return true
}

func completeMultipartParts(body, boundary string) []recPart {
	if boundary == "" {
		boundary = sniffBoundary(body)
	}
	if boundary == "" {
		return nil
	}
	chunks := strings.Split(body, "--"+boundary)
	if len(chunks) < 3 {
		return nil
	}
	var parts []recPart
	// The last chunk is the epilogue or an incomplete tail. Only chunks with a
	// following boundary are complete, so the raw cut is never returned.
	for _, chunk := range chunks[1 : len(chunks)-1] {
		if p, ok := parsePartChunk(chunk); ok {
			parts = append(parts, p)
		}
	}
	return parts
}

func parsePartChunk(chunk string) (recPart, bool) {
	chunk = strings.TrimLeft(chunk, "\r\n")
	if chunk == "" || chunk == "--" || strings.HasPrefix(chunk, "--") {
		return recPart{}, false
	}
	head, rest, ok := strings.Cut(chunk, "\r\n\r\n")
	if !ok {
		head, rest, ok = strings.Cut(chunk, "\n\n")
		if !ok {
			return recPart{}, false
		}
	}
	rest = strings.TrimRight(rest, "\r\n")
	var name, filename, ct string
	for _, line := range strings.Split(strings.ReplaceAll(head, "\r\n", "\n"), "\n") {
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "content-disposition:") {
			_, params, err := mime.ParseMediaType(strings.TrimSpace(line[len("content-disposition:"):]))
			if err != nil {
				continue
			}
			name, filename = params["name"], params["filename"]
		} else if strings.HasPrefix(low, "content-type:") {
			ct = strings.TrimSpace(line[len("content-type:"):])
		}
	}
	if name == "" {
		return recPart{}, false
	}
	return recPart{name: name, filename: filename, contentType: ct, value: rest}, true
}

func (a *App) multipartPartialOutline(body, boundary string, lits []string) any {
	parts := completeMultipartParts(body, boundary)
	if boundary == "" && len(parts) == 0 {
		return map[string]any{"multipart": "partial"}
	}
	out := make([]any, 0, len(parts))
	for _, p := range parts {
		item := map[string]any{"name": a.sanitizeString(p.name, false, 0, lits)}
		if p.filename != "" {
			item["filename"] = a.sanitizeString(p.filename, false, 0, lits)
		}
		switch {
		case p.filename != "" && !textualPart(p.contentType, p.value):
			item["value"] = omittedFileValue
		case isSensitiveKey(p.name) && strings.TrimSpace(p.value) != "":
			item["value"] = secretMask
		default:
			item["value"] = a.sanitizeString(p.value, false, 0, lits)
		}
		out = append(out, item)
	}
	return map[string]any{"multipart": "partial", "parts": out}
}

func (a *App) recBodyView(body, ct string, lits []string, max int) (recSafeText, int, bool, bool, bool, any) {
	total := len(body)
	if strings.TrimSpace(body) == "" {
		return "", total, false, false, false, nil
	}
	if bodyWasTruncated(body) {
		shown, outline := a.sanitizedTruncated(body, ct, lits)
		if outline != nil {
			return "", total, false, false, true, outline
		}
		s, _, cut := clipText(shown, max)
		return recSafeText(s), total, cut, false, true, nil
	}
	safe, hidden := a.sanitizeRecBody(body, ct, lits)
	if hidden {
		return recSafeText(safe), total, false, true, false, nil
	}
	shown, _, cut := clipText(safe, max)
	return recSafeText(shown), total, cut, false, false, nil
}

// bodyTruncationInfo makes a cut body obvious to the reader. A body can be cut
// at capture time (partial: the recording kept only the first maxBody bytes) or
// when shown (cut: max_body is smaller than the body). In both cases the shown
// text ends with an explicit marker and a note explains how much is missing.
func bodyTruncationInfo(label string, shown recSafeText, total int, partial, cut bool, max int) (recSafeText, string) {
	if !partial && !cut {
		return shown, ""
	}
	var parts []string
	if partial {
		parts = append(parts, fmt.Sprintf("%s在录制采集时超过 %d KB 上限，已被截断，只保留了前面一部分，后面的内容录制里没有。", label, maxBody/1024))
	}
	if cut {
		parts = append(parts, fmt.Sprintf("%s太长，已截断：这里显示脱敏后内容的前 %d 字节（原始体积 %d 字节）；需要更多可调大 max_body（上限 100000）。", label, len(shown), total))
	}
	text := string(shown)
	if text != "" {
		text += "\n…[已截断]"
	}
	return recSafeText(text), strings.Join(parts, "")
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
			v = headerURLs(k, v, func(raw string) string { return a.maskURLSensitive(raw, lits) })
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
		v = fullyUnescapeQuery(v)
		if isSensitiveKey(k) && v != "" {
			v = secretMask
		} else if a != nil {
			v = a.sanitizeString(v, false, 0, lits)
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
		if !crossFieldLiteral(p.value) {
			continue
		}
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
	t.Params = append(t.Params, Param{Name: name, Type: recScalarType(v), Required: true, Description: removedSecretDesc, Secret: true})
	return "{{" + name + "}}"
}

// Work on decoded field values, never on a serialized JSON document. Keep
// existing references intact and leave non-sensitive numbers/booleans typed.
func parameterizeRawSecrets(t *Tool, q *ReqRecord) error {
	var err error
	t.URL, err = transformRecURL(t.URL, func(key, value string) string {
		if isSensitiveKey(key) && value != "" && !isWholePlaceholder(value) {
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
				if sensitive && v != nil && fmt.Sprint(v) != "" && !isWholePlaceholder(fmt.Sprint(v)) {
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
				if isSensitiveKey(k) && v != "" && !isWholePlaceholder(v) {
					vs[i] = newRecSecretParam(t, k, v)
				}
			}
		}
		t.Body = encodeRecForm(vals)
	case "multipart":
		return parameterizeMultipartBody(t, q)
	}
	return nil
}

func parameterizeMultipartBody(t *Tool, q *ReqRecord) error {
	_, params, err := bodyKind(t.Body, headerValue(q.ReqHeaders, "Content-Type"))
	if err != nil || params["boundary"] == "" {
		return fmt.Errorf("multipart 请求体无法安全保存")
	}
	parts, err := parseRecMultipart(t.Body, params["boundary"])
	if err != nil {
		return fmt.Errorf("multipart 请求体无法安全保存")
	}
	repl := map[string]string{}
	for _, p := range parts {
		val := p.value
		if p.filename != "" && !textualPart(p.contentType, p.value) {
			repl[p.name] = omittedFileValue
			continue
		}
		if isSensitiveKey(p.name) && strings.TrimSpace(val) != "" && !isWholePlaceholder(val) {
			val = newRecSecretParam(t, p.name, val)
		}
		if val != p.value {
			repl[p.name] = val
		}
	}
	if len(repl) == 0 {
		return nil
	}
	body, err := rebuildMultipart(t.Body, params["boundary"], repl)
	if err != nil {
		return fmt.Errorf("multipart 请求体无法安全保存")
	}
	t.Body = body
	return nil
}

func (a *App) redactToolSecrets(t *Tool, q *ReqRecord) error {
	lits := sensitiveLiterals(q)
	if err := parameterizeRawSecrets(t, q); err != nil {
		return err
	}
	var err error
	t.URL, err = transformRecURL(t.URL, func(_, v string) string { return a.parameterizeStringValue(t, v, lits, 0) })
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
					return a.parameterizeStringValue(t, x, lits, 0)
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
					vs[i] = a.parameterizeStringValue(t, v, lits, 0)
				}
			}
			t.Body = encodeRecForm(vals)
		case "multipart":
			_, mp, err := bodyKind(t.Body, headerValue(q.ReqHeaders, "Content-Type"))
			if err != nil || mp["boundary"] == "" {
				return fmt.Errorf("multipart 请求体无法安全保存")
			}
			parts, err := parseRecMultipart(t.Body, mp["boundary"])
			if err != nil {
				return fmt.Errorf("multipart 请求体无法安全保存")
			}
			repl := map[string]string{}
			for _, p := range parts {
				if p.filename != "" && !textualPart(p.contentType, p.value) {
					repl[p.name] = omittedFileValue
					continue
				}
				repl[p.name] = a.parameterizeStringValue(t, p.value, lits, 0)
			}
			body, err := rebuildMultipart(t.Body, mp["boundary"], repl)
			if err != nil {
				return err
			}
			t.Body = body
		default:
			t.Body = a.parameterizeStringValue(t, t.Body, lits, 0)
		}
	}
	t.Title = a.sanitizeString(t.Title, false, 0, lits)
	t.Description = a.sanitizeString(t.Description, false, 0, lits)
	if a.revealsSecret(t.Name, lits) {
		return fmt.Errorf("工具标识含有密钥或凭证")
	}
	for k, v := range t.Headers {
		if isSensitiveHeader(k) && !placeholderRe.MatchString(v) {
			delete(t.Headers, k)
			continue
		}
		if isURLHeader(k) {
			v = headerURLs(k, v, func(raw string) string {
				safe, err := transformRecURL(raw, func(_, value string) string { return a.parameterizeStringValue(t, value, lits, 0) })
				if err != nil {
					return secretMask
				}
				return safe
			})
		}
		t.Headers[k] = a.parameterizeStringValue(t, v, lits, 0)
	}
	for i := range t.Params {
		p := &t.Params[i]
		if p.Default == secretMask || isSensitiveKey(p.Name) || a.revealsSecret(p.Default, lits) {
			p.Default, p.Required = "", true
		}
		p.Description = a.sanitizeString(p.Description, false, 0, lits)
	}
	return nil
}
