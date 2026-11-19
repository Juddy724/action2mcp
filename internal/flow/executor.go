package flow

import (
	"action2mcp/internal/credential"
	"action2mcp/internal/domain"
	"action2mcp/internal/execution"
	"action2mcp/internal/vault"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ToolInvoker func(ctx context.Context, toolName string, args map[string]any, explanation string) (output any, rawText string, err error)

type Options struct {
	Vault      *vault.Vault
	InvokeTool ToolInvoker
}

type Executor struct {
	opts Options
}

func New(o Options) *Executor {
	return &Executor{opts: o}
}

type SubCallTrace struct {
	ToolName   string `json:"tool_name"`
	Status     string `json:"status"` // "ok" | "error"
	DurationMs int64  `json:"duration_ms"`
	Input      any    `json:"input,omitempty"`
	Output     any    `json:"output,omitempty"`
	Error      string `json:"error,omitempty"`
}

type StepTrace struct {
	ID         string         `json:"id"`
	Name       string         `json:"name,omitempty"`
	Kind       string         `json:"kind"`
	Runtime    string         `json:"runtime,omitempty"`
	ToolName   string         `json:"tool_name,omitempty"`
	Stage      int            `json:"stage"`
	Parallel   bool           `json:"parallel"`
	Status     string         `json:"status"` // "ok" | "error"
	DurationMs int64          `json:"duration_ms"`
	Input      any            `json:"input,omitempty"`
	Output     any            `json:"output,omitempty"`
	Logs       string         `json:"logs,omitempty"`
	Error      string         `json:"error,omitempty"`
	SubCalls   []SubCallTrace `json:"sub_calls,omitempty"`
}

type RunResult struct {
	OK          bool        `json:"ok"`
	Status      int         `json:"status"`
	Body        string      `json:"body"`
	FinalOutput any         `json:"final_output,omitempty"`
	DurationMs  int64       `json:"duration_ms"`
	Error       string      `json:"error,omitempty"`
	StepsTrace  []StepTrace `json:"steps_trace"`
}

type stageGroup struct {
	stage int
	items []int // indices into flow.Steps
}

// Run executes a FLOW custom tool, orchestrating serial stages and intra-stage parallel steps.
func (e *Executor) Run(ctx context.Context, t *execution.Tool, rawArgs map[string]any, explanation string) (*RunResult, error) {
	if t == nil || t.Config.Flow == nil || len(t.Config.Flow.Steps) == 0 {
		return nil, errors.New("自定义工具缺少有效的节点编排配置")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	start := time.Now()
	inputMap, err := t.BindInputArgs(rawArgs)
	if err != nil {
		return nil, errors.New(e.scrubText(err.Error()))
	}

	steps := t.Config.Flow.Steps
	stages := groupStages(steps)

	var mu sync.RWMutex
	stepsOut := make(map[string]any, len(steps))
	traces := make([]StepTrace, len(steps))

	for _, stg := range stages {
		if len(stg.items) == 1 {
			idx := stg.items[0]
			mu.RLock()
			snap := copyAnyMap(stepsOut)
			mu.RUnlock()
			out, trace := e.runStep(ctx, steps[idx], stg.stage, inputMap, snap, explanation)
			traces[idx] = trace
			if trace.Status == "error" {
				return e.failResult(start, traces, idx, trace.Error), errors.New(e.scrubText(trace.Error))
			}
			mu.Lock()
			stepsOut[steps[idx].ID] = out
			mu.Unlock()
			continue
		}

		// Concurrent stage execution for parallel steps
		mu.RLock()
		snap := copyAnyMap(stepsOut)
		mu.RUnlock()

		var wg sync.WaitGroup
		outs := make([]any, len(stg.items))
		stageTraces := make([]StepTrace, len(stg.items))
		for pos, idx := range stg.items {
			wg.Add(1)
			go func(pos, idx int) {
				defer wg.Done()
				outs[pos], stageTraces[pos] = e.runStep(ctx, steps[idx], stg.stage, inputMap, copyAnyMap(snap), explanation)
			}(pos, idx)
		}
		wg.Wait()

		firstErr := ""
		maxIdx := -1
		for pos, idx := range stg.items {
			traces[idx] = stageTraces[pos]
			if idx > maxIdx {
				maxIdx = idx
			}
			if stageTraces[pos].Status == "error" && firstErr == "" {
				firstErr = stageTraces[pos].Error
			} else if stageTraces[pos].Status == "ok" {
				mu.Lock()
				stepsOut[steps[idx].ID] = outs[pos]
				mu.Unlock()
			}
		}
		if firstErr != "" {
			return e.failResult(start, traces, maxIdx, firstErr), errors.New(e.scrubText(firstErr))
		}
	}

	finalOut, err := e.resolveFinalOutput(t.Config.Flow, stages[len(stages)-1], inputMap, stepsOut)
	if err != nil {
		msg := e.scrubText(err.Error())
		return &RunResult{
			OK:         false,
			Status:     500,
			Error:      msg,
			Body:       msg,
			DurationMs: time.Since(start).Milliseconds(),
			StepsTrace: traces,
		}, errors.New(msg)
	}
	scrubbedFinal := e.scrubAny(finalOut)
	bodyText := formatOutputBody(scrubbedFinal)
	return &RunResult{
		OK:          true,
		Status:      200,
		Body:        bodyText,
		FinalOutput: scrubbedFinal,
		DurationMs:  time.Since(start).Milliseconds(),
		StepsTrace:  traces,
	}, nil
}

func (e *Executor) failResult(start time.Time, traces []StepTrace, upToIdx int, errMsg string) *RunResult {
	var partial []StepTrace
	for i := 0; i <= upToIdx && i < len(traces); i++ {
		if traces[i].ID != "" {
			partial = append(partial, traces[i])
		}
	}
	msg := e.scrubText(errMsg)
	return &RunResult{
		OK:         false,
		Status:     500,
		Error:      msg,
		Body:       msg,
		DurationMs: time.Since(start).Milliseconds(),
		StepsTrace: partial,
	}
}

func groupStages(steps []execution.FlowStep) []stageGroup {
	var stages []stageGroup
	for i, s := range steps {
		if i == 0 || !s.ParallelWithPrev {
			stages = append(stages, stageGroup{stage: len(stages) + 1, items: []int{i}})
		} else {
			last := &stages[len(stages)-1]
			last.items = append(last.items, i)
		}
	}
	return stages
}

func (e *Executor) runStep(ctx context.Context, step execution.FlowStep, stage int, inputMap, stepsOut map[string]any, explanation string) (any, StepTrace) {
	start := time.Now()
	tr := StepTrace{
		ID:       step.ID,
		Name:     step.Name,
		Kind:     step.Kind,
		Runtime:  step.Runtime,
		ToolName: step.ToolName,
		Stage:    stage,
		Parallel: step.ParallelWithPrev,
	}
	flowCtx := map[string]any{
		"input": inputMap,
		"steps": stepsOut,
	}

	switch strings.ToLower(strings.TrimSpace(step.Kind)) {
	case "tool":
		if e.opts.InvokeTool == nil {
			tr.Status = "error"
			tr.Error = fmt.Sprintf("节点 %s：未注入工具调用器", step.ID)
			tr.DurationMs = time.Since(start).Milliseconds()
			return nil, tr
		}
		resolvedArgs, err := e.resolveStepArgs(step.ArgsFrom, step.Args, flowCtx)
		tr.Input = e.scrubAny(resolvedArgs)
		if err != nil {
			tr.Status = "error"
			tr.Error = e.scrubText(fmt.Sprintf("节点 %s 参数解析失败：%v", step.ID, err))
			tr.DurationMs = time.Since(start).Milliseconds()
			return nil, tr
		}
		out, rawText, err := e.opts.InvokeTool(ctx, step.ToolName, resolvedArgs, explanation)
		tr.DurationMs = time.Since(start).Milliseconds()
		if err != nil {
			tr.Status = "error"
			tr.Error = e.scrubText(fmt.Sprintf("节点 %s (%s) 执行失败：%v", step.ID, step.ToolName, err))
			if rawText != "" {
				tr.Logs = e.scrubText(rawText)
			}
			return nil, tr
		}
		if out == nil && rawText != "" {
			out = parseScriptOutputJSON(rawText)
		}
		tr.Status = "ok"
		tr.Output = e.scrubAny(out)
		if rawText != "" {
			tr.Logs = e.scrubText(rawText)
		}
		return out, tr

	case "script":
		rt := strings.ToLower(strings.TrimSpace(step.Runtime))
		if rt == "" {
			rt = "builtin_js"
		}
		tr.Runtime = rt

		stepParams := map[string]any{}
		if len(step.Args) > 0 || strings.TrimSpace(step.ArgsFrom) != "" {
			resolvedParams, perr := e.resolveStepArgs(step.ArgsFrom, step.Args, flowCtx)
			if perr != nil {
				tr.Status = "error"
				tr.Error = e.scrubText(fmt.Sprintf("节点 %s 入参映射失败：%v", step.ID, perr))
				tr.DurationMs = time.Since(start).Milliseconds()
				return nil, tr
			}
			stepParams = resolvedParams
		}
		scriptInput := make(map[string]any, len(inputMap)+len(stepParams))
		for k, v := range inputMap {
			scriptInput[k] = v
		}
		for k, v := range stepParams {
			scriptInput[k] = v
		}
		scriptCtx := map[string]any{
			"input":  scriptInput,
			"params": stepParams,
			"steps":  stepsOut,
		}
		if len(stepParams) > 0 {
			tr.Input = e.scrubAny(scriptCtx)
		} else {
			tr.Input = e.scrubAny(flowCtx)
		}

		code, err := e.resolveVaultRefsInString(step.Code)
		if err != nil {
			tr.Status = "error"
			tr.Error = e.scrubText(fmt.Sprintf("节点 %s 配置引用失败：%v", step.ID, err))
			tr.DurationMs = time.Since(start).Milliseconds()
			return nil, tr
		}

		var out any
		var logs string
		if rt == "builtin_js" {
			var subCalls []SubCallTrace
			callToolFn := func(toolName string, args map[string]any) (any, error) {
				if e.opts.InvokeTool == nil {
					return nil, errors.New("未注入工具调用器，无法调用 callTool")
				}
				if args == nil {
					args = map[string]any{}
				}
				subStart := time.Now()
				subOut, subRaw, subErr := e.opts.InvokeTool(ctx, toolName, args, explanation)
				subDur := time.Since(subStart).Milliseconds()
				st := SubCallTrace{
					ToolName:   toolName,
					DurationMs: subDur,
					Input:      e.scrubAny(args),
				}
				if subErr != nil {
					st.Status = "error"
					st.Error = e.scrubText(subErr.Error())
					subCalls = append(subCalls, st)
					return nil, errors.New(st.Error)
				}
				if subOut == nil && subRaw != "" {
					subOut = parseScriptOutputJSON(subRaw)
				}
				st.Status = "ok"
				st.Output = e.scrubAny(subOut)
				subCalls = append(subCalls, st)
				return subOut, nil
			}
			out, logs, err = runBuiltinJS(ctx, code, scriptInput, stepsOut, stepParams, callToolFn)
			if len(subCalls) > 0 {
				tr.SubCalls = subCalls
			}
		} else {
			payload, merr := json.Marshal(scriptCtx)
			if merr != nil {
				err = merr
			} else {
				out, logs, err = runExternalScript(ctx, rt, code, payload)
			}
		}
		tr.DurationMs = time.Since(start).Milliseconds()
		tr.Logs = e.scrubText(logs)
		if err != nil {
			tr.Status = "error"
			tr.Error = e.scrubText(fmt.Sprintf("节点 %s (%s) 执行失败：%v", step.ID, rt, err))
			return nil, tr
		}
		tr.Status = "ok"
		tr.Output = e.scrubAny(out)
		return out, tr

	default:
		tr.Status = "error"
		tr.DurationMs = time.Since(start).Milliseconds()
		tr.Error = fmt.Sprintf("未知节点类型：%s", step.Kind)
		return nil, tr
	}
}

var tplRe = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_\.\[\]-]+)\s*\}\}`)

func (e *Executor) resolveStepArgs(argsFrom string, args map[string]any, flowCtx map[string]any) (map[string]any, error) {
	out := map[string]any{}
	if strings.TrimSpace(argsFrom) != "" {
		base, err := e.resolveTemplateValue(strings.TrimSpace(argsFrom), flowCtx)
		if err != nil {
			return nil, err
		}
		if base != nil {
			m, ok := base.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("args_from 表达式 %q 必须解析为 JSON 对象", argsFrom)
			}
			for k, v := range m {
				out[k] = v
			}
		}
	}
	resolved, err := e.resolveArgsMap(args, flowCtx)
	if err != nil {
		return nil, err
	}
	for k, v := range resolved {
		out[k] = v
	}
	return out, nil
}

func (e *Executor) resolveArgsMap(args map[string]any, flowCtx map[string]any) (map[string]any, error) {
	if len(args) == 0 {
		return map[string]any{}, nil
	}
	out := make(map[string]any, len(args))
	for k, v := range args {
		rv, err := e.resolveTemplateValue(v, flowCtx)
		if err != nil {
			return nil, err
		}
		out[k] = rv
	}
	return out, nil
}

func (e *Executor) resolveTemplateValue(val any, flowCtx map[string]any) (any, error) {
	switch x := val.(type) {
	case map[string]any:
		return e.resolveArgsMap(x, flowCtx)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			rv, err := e.resolveTemplateValue(item, flowCtx)
			if err != nil {
				return nil, err
			}
			out[i] = rv
		}
		return out, nil
	case string:
		trimmed := strings.TrimSpace(x)
		if m := tplRe.FindStringSubmatch(trimmed); m != nil && strings.TrimSpace(m[0]) == trimmed {
			// Whole placeholder: preserve raw typed value (array, object, number, bool, string).
			rv, err := e.lookupTemplateExpr(m[1], flowCtx)
			if err != nil {
				return nil, err
			}
			return rv, nil
		}
		var firstErr error
		rendered := tplRe.ReplaceAllStringFunc(x, func(match string) string {
			sub := tplRe.FindStringSubmatch(match)
			rv, err := e.lookupTemplateExpr(sub[1], flowCtx)
			if err != nil && firstErr == nil {
				firstErr = err
				return match
			}
			return domain.ArgumentText(rv)
		})
		if firstErr != nil {
			return nil, firstErr
		}
		return rendered, nil
	default:
		return val, nil
	}
}

func (e *Executor) resolveVaultRefsInString(s string) (string, error) {
	var firstErr error
	out := tplRe.ReplaceAllStringFunc(s, func(match string) string {
		sub := tplRe.FindStringSubmatch(match)
		expr := sub[1]
		if !credential.IsRefName(expr) {
			return match
		}
		if e.opts.Vault == nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("无法读取配置项 %s", expr)
			}
			return match
		}
		v, err := e.opts.Vault.Resolve(expr)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			return match
		}
		return v
	})
	return out, firstErr
}

func (e *Executor) lookupTemplateExpr(expr string, flowCtx map[string]any) (any, error) {
	if credential.IsRefName(expr) {
		if e.opts.Vault == nil {
			return nil, fmt.Errorf("配置项 %s 无法读取", expr)
		}
		return e.opts.Vault.Resolve(expr)
	}
	if expr == "input" {
		return flowCtx["input"], nil
	}
	if expr == "steps" {
		return flowCtx["steps"], nil
	}
	if strings.HasPrefix(expr, "input.") {
		v, ok := lookupDotPath(flowCtx["input"], strings.TrimPrefix(expr, "input."))
		if !ok {
			return "", nil
		}
		return v, nil
	}
	if strings.HasPrefix(expr, "steps.") {
		v, ok := lookupDotPath(flowCtx["steps"], strings.TrimPrefix(expr, "steps."))
		if !ok {
			return nil, nil
		}
		return v, nil
	}
	if v, ok := lookupDotPath(flowCtx["input"], expr); ok {
		return v, nil
	}
	if v, ok := lookupDotPath(flowCtx["steps"], expr); ok {
		return v, nil
	}
	return "{{" + expr + "}}", nil
}

func lookupDotPath(root any, path string) (any, bool) {
	if root == nil || path == "" {
		return root, root != nil
	}
	cur := root
	// Support both a.b.0.c and a.b[0].c
	normalized := strings.ReplaceAll(path, "[", ".")
	normalized = strings.ReplaceAll(normalized, "]", "")
	parts := strings.Split(normalized, ".")
	for _, seg := range parts {
		if seg == "" {
			continue
		}
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return nil, false
			}
			cur = node[idx]
		default:
			return nil, false
		}
	}
	return cur, true
}

func (e *Executor) resolveFinalOutput(flow *execution.FlowConfig, lastStage stageGroup, inputMap, stepsOut map[string]any) (any, error) {
	flowCtx := map[string]any{"input": inputMap, "steps": stepsOut}
	if strings.EqualFold(strings.TrimSpace(flow.Output.Mode), "template") && strings.TrimSpace(flow.Output.Template) != "" {
		raw := strings.TrimSpace(flow.Output.Template)
		// If template is JSON container with placeholders, unmarshal & resolve recursively to preserve structure.
		if strings.HasPrefix(raw, "{") || strings.HasPrefix(raw, "[") {
			var parsed any
			if json.Unmarshal([]byte(raw), &parsed) == nil {
				return e.resolveTemplateValue(parsed, flowCtx)
			}
		}
		return e.resolveTemplateValue(raw, flowCtx)
	}
	if len(lastStage.items) == 1 {
		id := flow.Steps[lastStage.items[0]].ID
		return stepsOut[id], nil
	}
	merged := make(map[string]any, len(lastStage.items))
	for _, idx := range lastStage.items {
		id := flow.Steps[idx].ID
		merged[id] = stepsOut[id]
	}
	return merged, nil
}

func formatOutputBody(v any) string {
	if v == nil {
		return "{}"
	}
	if s, ok := v.(string); ok {
		return s
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

func copyAnyMap(src map[string]any) map[string]any {
	if src == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func (e *Executor) scrubText(s string) string {
	if e != nil && e.opts.Vault != nil {
		return e.opts.Vault.Scrub(s)
	}
	return s
}

func (e *Executor) scrubAny(v any) any {
	if e == nil || e.opts.Vault == nil || v == nil {
		return v
	}
	switch x := v.(type) {
	case string:
		return e.opts.Vault.Scrub(x)
	case []any:
		out := make([]any, len(x))
		for i, item := range x {
			out[i] = e.scrubAny(item)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			out[k] = e.scrubAny(val)
		}
		return out
	default:
		return v
	}
}
