package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	ApprovalSecretUnchanged = "******（未改动）"
	maxPendingApprovals     = 20
	maxApprovalArgs         = 256 * 1024
)

type ApprovalError struct {
	Status  int
	Message string
}

func (e *ApprovalError) Error() string { return e.Message }

func approvalErr(status int, message string) error {
	return &ApprovalError{status, message}
}

type pendingApproval struct {
	record        ApprovalRecord
	tool          *Tool
	args          map[string]any
	finalArgs     map[string]any
	prepared      *PreparedCall
	confirmedHash string
	nonce         string
	deadline      time.Time
	done          chan struct{}
	err           error
}

// Edits use the same float64 integer precision as MCP's JSON input.
func copyApprovalArgs(args map[string]any) (map[string]any, error) {
	b, err := json.Marshal(args)
	if err != nil {
		return nil, approvalErr(400, "参数无法序列化，未执行")
	}
	if len(b) > maxApprovalArgs {
		return nil, approvalErr(400, "参数过大，无法审批，未执行")
	}
	var copy map[string]any
	if err := json.Unmarshal(b, &copy); err != nil {
		return nil, err
	}
	if copy == nil {
		copy = map[string]any{}
	}
	return copy, nil
}

func (a *App) waitApproval(ctx context.Context, t *Tool, args map[string]any, prepared *PreparedCall, client string) (*pendingApproval, error) {
	args, err := copyApprovalArgs(args)
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.New("审批记录保存失败，未执行")
	}
	timeout := a.approvalTimeout
	if timeout <= 0 {
		timeout = a.store.ApprovalTimeout()
	}
	// Keep sensitivity once detected, even if the vault changes while waiting.
	snapshot := *t
	snapshot.Params = append([]Param{}, t.Params...)
	for i := range snapshot.Params {
		param := &snapshot.Params[i]
		param.Secret = a.paramIsSecret(t, *param, args[param.Name])
	}
	p := &pendingApproval{tool: &snapshot, args: args, prepared: prepared, nonce: hex.EncodeToString(nonce[:]), deadline: time.Now().Add(timeout), done: make(chan struct{})}
	p.record = ApprovalRecord{TS: now(), Tool: a.scrubApprovalText(t.Name, prepared.secretValues), ToolID: t.ID, ToolRev: t.Rev,
		Title: a.scrubApprovalText(t.Title, prepared.secretValues), Client: a.scrubApprovalText(client, prepared.secretValues),
		ArgsDisplay: a.approvalArgs(p.tool, args, prepared.secretValues), Status: "pending", Preview: prepared.Preview, PreviewHash: prepared.PreviewHash,
		Params: a.approvalParams(p.tool, args, prepared.secretValues)}
	a.approvalMu.Lock()
	if a.approvals == nil {
		a.approvals = map[int64]*pendingApproval{}
	}
	if err := a.store.sweepOrphanApprovals(a.approvals); err != nil {
		a.approvalMu.Unlock()
		return nil, errors.New("审批记录保存失败，未执行")
	}
	if len(a.approvals) >= maxPendingApprovals {
		a.approvalMu.Unlock()
		return nil, approvalErr(429, "待审批调用过多，未执行，请稍后再次调用")
	}
	if a.approvalInsertHook != nil {
		err = a.approvalInsertHook()
	}
	if err == nil {
		err = a.store.insertApproval(&p.record)
	}
	if err != nil {
		a.approvalMu.Unlock()
		var ae *ApprovalError
		if errors.As(err, &ae) && ae.Status == 429 {
			return nil, err
		}
		return nil, errors.New("审批记录保存失败，未执行")
	}
	a.approvals[p.record.ID] = p
	notificationTool := p.record.Tool
	a.approvalMu.Unlock()
	go notifyApproval(notificationTool)
	timer := time.NewTimer(time.Until(p.deadline))
	defer timer.Stop()
	// Session DELETE and stdio exit do not guarantee cancellation; reject or timeout still works.
	select {
	case <-p.done:
	case <-timer.C:
		a.endPending(p, "timeout")
	case <-ctx.Done():
		a.endPending(p, "cancelled")
	case <-a.quit:
		a.endPending(p, "cancelled")
	}
	<-p.done
	if p.err != nil {
		return nil, p.err
	}
	switch p.record.Status {
	case "approved", "edited":
		return p, nil
	case "rejected":
		return nil, fmt.Errorf("用户未批准本次调用。用户意见：%s。请按意见修改参数后再次调用本工具（会再次请求审批）；不要绕过审批。", p.record.Feedback)
	case "timeout":
		return nil, errors.New("审批超时，未执行。如需继续请再次调用。")
	default:
		return nil, errors.New("审批已取消，未执行")
	}
}

// Cancellation applies only while pending; Send has no context and cannot be withdrawn.
func (a *App) endPending(p *pendingApproval, status string) {
	a.approvalMu.Lock()
	defer a.approvalMu.Unlock()
	if p.record.Status != "pending" {
		return
	}
	r := p.record
	r.Status, r.DecidedAt = status, now()
	if err := a.store.finishApproval(&r); err != nil {
		log.Printf("审批 #%d 结束记录保存失败", r.ID)
	}
	p.record = r
	delete(a.approvals, r.ID)
	close(p.done)
}

func (a *App) pendingWithNonce(id int64, nonce string) (*pendingApproval, error) {
	p := a.approvals[id]
	if p == nil {
		var exists int
		if err := a.store.db.QueryRow(`SELECT 1 FROM approvals WHERE id=?`, id).Scan(&exists); err == sql.ErrNoRows {
			return nil, approvalErr(404, "审批不存在")
		} else if err != nil {
			return nil, approvalErr(500, "读取审批失败")
		}
		return nil, approvalErr(409, "本次审批已结束")
	}
	if p.record.Status != "pending" {
		return nil, approvalErr(409, "本次审批已结束")
	}
	if subtle.ConstantTimeCompare([]byte(p.nonce), []byte(nonce)) != 1 {
		return nil, approvalErr(403, "审批凭证不正确")
	}
	if !time.Now().Before(p.deadline) {
		return nil, approvalErr(409, "本次审批已过期")
	}
	return p, nil
}

func (a *App) editApprovalArgs(p *pendingApproval, args map[string]any) (map[string]any, error) {
	edits, err := copyApprovalArgs(args)
	if err != nil {
		return nil, err
	}
	merged, err := copyApprovalArgs(p.args)
	if err != nil {
		return nil, err
	}
	params := map[string]Param{}
	for _, param := range p.tool.Params {
		params[param.Name] = param
	}
	for key, value := range edits {
		param := params[key]
		param.Name = key
		merged[key], err = mergeApprovalValue(p.args[key], value, a.paramIsSecret(p.tool, param, p.args[key]))
		if err != nil {
			return nil, err
		}
	}
	return copyApprovalArgs(merged)
}

func (a *App) PreviewApproval(id int64, nonce string, args map[string]any) (*ApprovalPreview, error) {
	a.approvalMu.Lock()
	defer a.approvalMu.Unlock()
	p, err := a.pendingWithNonce(id, nonce)
	if err != nil {
		return nil, err
	}
	edited, err := a.editApprovalArgs(p, args)
	if err != nil {
		return nil, err
	}
	prepared, err := a.Prepare(p.tool, edited)
	if err != nil {
		return nil, approvalErr(400, a.scrubSQLConsoleText(err.Error(), p.prepared.secretValues, p.prepared.configValues, true))
	}
	prepared.Preview = a.scrubApprovalPreview(prepared.Preview, p.prepared.secretValues)
	prepared.Preview = scrubPreviewConfigTokens(prepared.Preview, p.prepared.configValues)
	return &ApprovalPreview{prepared.Preview, prepared.PreviewHash}, nil
}

func (a *App) DecideApproval(id int64, nonce, action string, args map[string]any, feedback, previewHash string) error {
	a.approvalMu.Lock()
	defer a.approvalMu.Unlock()
	p, err := a.pendingWithNonce(id, nonce)
	if err != nil {
		return err
	}
	r := p.record
	r.DecidedAt = now()
	var prepared *PreparedCall
	var finalArgs map[string]any
	switch action {
	case "reject":
		feedback = strings.TrimSpace(feedback)
		if feedback == "" {
			return approvalErr(400, "拒绝时请填写意见")
		}
		r.Status = "rejected"
		r.Feedback = a.scrubApprovalText(feedback, p.prepared.secretValues)
	case "approve", "edit":
		if previewHash == "" {
			return approvalErr(400, "请提供 preview_hash")
		}
		finalArgs = p.args
		if action == "edit" {
			finalArgs, err = a.editApprovalArgs(p, args)
			if err != nil {
				return err
			}
		}
		prepared, err = a.Prepare(p.tool, finalArgs)
		if err != nil {
			return approvalErr(400, a.scrubSQLConsoleText(err.Error(), p.prepared.secretValues, p.prepared.configValues, true))
		}
		if prepared.PreviewHash != previewHash {
			return approvalErr(409, "预览已过期，请刷新后重新确认")
		}
		prepared.secretValues = append(prepared.secretValues, p.prepared.secretValues...)
		prepared.configValues = append(prepared.configValues, p.prepared.configValues...)
		prepared.Preview = a.scrubApprovalPreview(prepared.Preview, prepared.secretValues)
		prepared.Preview = scrubPreviewConfigTokens(prepared.Preview, prepared.configValues)
		r.Status = "approved"
		if action == "edit" {
			r.Status = "edited"
		}
		r.FinalArgsDisplay = a.approvalArgs(p.tool, finalArgs, prepared.secretValues)
		r.Preview, r.PreviewHash = prepared.Preview, prepared.PreviewHash
	default:
		return approvalErr(400, "审批操作只能是 approve、edit 或 reject")
	}
	if prepared != nil && a.approvalDecideHook != nil {
		err = a.approvalDecideHook()
	}
	if err == nil {
		err = a.store.finishApproval(&r)
	}
	if err != nil {
		// No execution right on a failed decision write. Wake the caller fail-closed.
		p.err = errors.New("审批决定保存失败，未执行")
		cancelled := p.record
		cancelled.Status, cancelled.DecidedAt = "cancelled", now()
		if saveErr := a.store.finishApproval(&cancelled); saveErr != nil {
			log.Printf("审批 #%d 取消记录保存失败", r.ID)
		}
		p.record = cancelled
		delete(a.approvals, r.ID)
		close(p.done)
		return approvalErr(500, p.err.Error())
	}
	p.record, p.finalArgs = r, finalArgs
	if prepared != nil {
		p.prepared, p.confirmedHash = prepared, previewHash
	}
	delete(a.approvals, r.ID)
	close(p.done)
	return nil
}

func (a *App) ListApprovals(status string, limit int) ([]ApprovalRecord, error) {
	if status == "" {
		status = "pending"
	}
	if status != "pending" && status != "all" {
		return nil, approvalErr(400, "审批状态只能是 pending 或 all")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	a.approvalMu.Lock()
	defer a.approvalMu.Unlock()
	if err := a.store.sweepOrphanApprovals(a.approvals); err != nil {
		return nil, err
	}
	rows, err := a.store.listApprovals(status, limit)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if p := a.approvals[rows[i].ID]; rows[i].Status == "pending" && p != nil {
			rows[i].Nonce = p.nonce
		}
	}
	return rows, nil
}

func (a *App) approvalCommitValid(p *pendingApproval) bool {
	if p.tool != nil && p.tool.mwID != 0 {
		m, err := a.store.GetMiddleware(p.tool.mwID)
		if err != nil || !m.Config.isSQLConsole() {
			return false
		}
		exposed, _ := a.store.ExposedMiddleware()
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
		if p.tool.mwFingerprint != m.sqlConsoleFingerprint() {
			return false
		}
		return p.prepared.fingerprint() == p.confirmedHash
	}
	var rev int64
	err := a.store.db.QueryRow(`SELECT rev FROM tools WHERE id=? AND EXISTS (SELECT 1 FROM pack_tools pt JOIN packs p ON p.id=pt.pack_id WHERE pt.tool_id=tools.id AND p.enabled=1)`, p.tool.ID).Scan(&rev)
	return err == nil && rev == p.record.ToolRev && p.prepared.fingerprint() == p.confirmedHash
}

const (
	approvalResultPreviewBytes = 2 * 1024
	approvalResultPreviewLines = 20
	approvalResultFullMax      = 1 << 20 // 1 MB
	approvalResultTruncMark    = "…[已截断]"
	approvalResultFullCapNote  = "…[已截断]（结果超过 1MB，已截断保存）"
)

func cutUTF8(s string, n int) string {
	if n >= len(s) {
		return s
	}
	if n < 0 {
		return ""
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// previewApprovalResult keeps the first ~20 lines or ~2KB, whichever is
// shorter, and appends a truncation marker when anything is dropped.
func previewApprovalResult(s string) string {
	if s == "" {
		return s
	}
	cut := len(s)
	lines := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines++
			if lines >= approvalResultPreviewLines {
				cut = i
				break
			}
		}
		if i+1 >= approvalResultPreviewBytes && cut == len(s) {
			cut = i + 1
			break
		}
	}
	if cut >= len(s) {
		return s
	}
	return strings.TrimRight(cutUTF8(s, cut), "\r\n") + "\n" + approvalResultTruncMark
}

func capApprovalResultFull(s string) (string, bool) {
	if len(s) <= approvalResultFullMax {
		return s, false
	}
	return cutUTF8(s, approvalResultFullMax) + "\n" + approvalResultFullCapNote, true
}

func (a *App) approvalResult(id int64, result string) {
	full, _ := capApprovalResultFull(result)
	summary := previewApprovalResult(full)
	if _, err := a.store.db.Exec(`UPDATE approvals SET result=?, result_full=? WHERE id=?`, summary, full, id); err != nil {
		log.Printf("审批 #%d 执行结果保存失败", id)
	}
}

func (a *App) GetApprovalResult(id int64) (string, bool, error) {
	if id <= 0 {
		return "", false, approvalErr(404, "审批记录不存在")
	}
	var result, full string
	err := a.store.db.QueryRow(`SELECT result, COALESCE(result_full,'') FROM approvals WHERE id=?`, id).Scan(&result, &full)
	if err == sql.ErrNoRows {
		return "", false, approvalErr(404, "审批记录不存在")
	}
	if err != nil {
		return "", false, err
	}
	if full == "" {
		full = result
	}
	truncated := strings.Contains(full, approvalResultFullCapNote)
	return full, truncated, nil
}

func (a *App) approvalEditPrefix(p *pendingApproval) string {
	if p.record.Status != "edited" {
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
	params := map[string]Param{}
	for _, param := range p.tool.Params {
		params[param.Name] = param
	}
	changes := []string{}
	for _, name := range names {
		param := params[name]
		param.Name = name
		if a.paramIsSecret(p.tool, param, p.args[name], p.finalArgs[name]) {
			changes = append(changes, name)
		} else {
			changes = append(changes, name+"："+p.record.FinalArgsDisplay[name])
		}
	}
	secrets := append(append([]string{}, p.prepared.secretValues...), a.approvalSecretValues(p.tool, p.args)...)
	return "（用户修改了参数；修改的参数：" + a.scrubApprovalText(strings.Join(changes, "，"), secrets) + "）\n"
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
