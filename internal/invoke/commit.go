package invoke

import (
	"action2mcp/internal/approval"
	"action2mcp/internal/domain"
	"action2mcp/internal/execution"
	"context"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
)

// Approved is a user decision on a frozen prepared call; Record and Prepared
// are what callers commit, the rest feeds CommitValid and EditPrefix.
type Approved struct {
	Record          approval.Record
	tool            *execution.Tool
	args, finalArgs map[string]any
	Prepared        *execution.PreparedCall
	confirmedHash   string
}

func notifyApproval(tool string) {
	if runtime.GOOS != "darwin" {
		return
	}
	tool = strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", " ", "\r", " ").Replace(tool)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	exec.CommandContext(ctx, "osascript", "-e", `display notification "工具 `+tool+` 等待审批" with title "Action2MCP"`).Run()
}

func (a *Gateway) CommitValid(p *Approved) bool {
	if p.tool != nil && p.tool.ConsoleBinding().ID != 0 {
		m, err := a.repo.GetMiddleware(p.tool.ConsoleBinding().ID)
		if err != nil || !m.Config.IsSQLConsole() {
			return false
		}
		exposed, _ := a.repo.ExposedMiddleware()
		found := false
		for _, x := range exposed {
			if x.ID == m.ID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
		if p.tool.ConsoleBinding().Fingerprint != m.SQLConsoleFingerprint() {
			return false
		}
		return p.Prepared.Fingerprint() == p.confirmedHash
	}
	rev, err := a.repo.EnabledToolRevision(p.tool.ID)
	return err == nil && rev == p.Record.ToolRev && p.Prepared.Fingerprint() == p.confirmedHash
}

func (a *Gateway) EditPrefix(p *Approved) string {
	if p.Record.Status != "edited" {
		return ""
	}
	keys := map[string]bool{}
	for key := range p.args {
		keys[key] = true
	}
	for key := range p.finalArgs {
		keys[key] = true
	}
	names := []string{}
	for key := range keys {
		if js(p.args[key]) != js(p.finalArgs[key]) {
			names = append(names, key)
		}
	}
	sort.Strings(names)
	params := map[string]domain.Param{}
	for _, param := range p.tool.Params {
		params[param.Name] = param
	}
	changes := []string{}
	for _, name := range names {
		param := params[name]
		param.Name = name
		if a.engine().ParamIsSecret(p.tool, param, p.args[name], p.finalArgs[name]) {
			changes = append(changes, name)
		} else {
			changes = append(changes, name+"："+p.Record.FinalArgsDisplay[name])
		}
	}
	secrets := a.engine().ApprovalSecretValues(p.tool, p.args)
	return "（用户修改了参数；修改的参数：" + a.engine().ScrubPrepared(a.engine().ScrubApprovalText(strings.Join(changes, "，"), secrets), p.Prepared, false) + "）\n"
}
