// Package invoke owns approval-gated tool invocation: pending approval records, waits, edits/previews and the commit gate around frozen prepared calls.
package invoke

import (
	"action2mcp/internal/approval"
	"action2mcp/internal/domain"
	"action2mcp/internal/execution"
	"action2mcp/internal/mwconfig"
	"context"
	"encoding/json"
	"sync"
	"time"
)

// gatewayRepository is the persistence surface of approval-gated invocation.
type Repository interface {
	ApprovalTimeout() time.Duration
	GetMiddleware(id int64) (*mwconfig.Middleware, error)
	ExposedMiddleware() ([]*mwconfig.Middleware, map[int64][]string)
	EnabledToolRevision(id int64) (int64, error)
}

type Options struct {
	Repository Repository
	Approvals  *approval.SQLStore
	Quit       <-chan struct{}
	Engine     func() *execution.Engine
	// Timeout, InsertHook and DecideHook are read on each use, preserving the
	// previous late-bound override semantics.
	Timeout    func() time.Duration
	InsertHook func() error
	DecideHook func() error
}

// Gateway owns the approval lifecycle around prepared tool calls: pending
// records, waits, edits/previews and the final commit gate. It holds no App.
type Gateway struct {
	repo       Repository
	approvals  *approval.SQLStore
	quit       <-chan struct{}
	engine     func() *execution.Engine
	timeout    func() time.Duration
	insertHook func() error
	decideHook func() error
	once       sync.Once
	service    *approval.Service[*operation]
}

func New(o Options) *Gateway {
	return &Gateway{repo: o.Repository, approvals: o.Approvals, quit: o.Quit, engine: o.Engine, timeout: o.Timeout, insertHook: o.InsertHook, decideHook: o.DecideHook}
}

type approvalRepository struct {
	*approval.SQLStore
	g *Gateway
}

type operation struct {
	g        *Gateway
	tool     *execution.Tool
	Prepared *execution.PreparedCall
}

func (r approvalRepository) Insert(record *approval.Record) error {
	if err := r.g.insertHook(); err != nil {
		return err
	}
	return r.SQLStore.Insert(record)
}

func (r approvalRepository) Finish(record *approval.Record) error {
	if record.Status == "approved" || record.Status == "edited" {
		if err := r.g.decideHook(); err != nil {
			return err
		}
	}
	return r.SQLStore.Finish(record)
}

func (a *Gateway) Service() *approval.Service[*operation] {
	a.once.Do(func() {
		a.service = approval.NewService[*operation](approvalRepository{a.approvals, a}, approval.Options{Quit: a.quit, Notify: notifyApproval})
	})
	return a.service
}

func (e *operation) Edit(original, edits map[string]any) (map[string]any, error) {
	params := map[string]domain.Param{}
	for _, param := range e.tool.Params {
		params[param.Name] = param
	}
	return approval.EditArgs(original, edits, func(name string, value any) bool {
		param := params[name]
		param.Name = name
		return e.g.engine().ParamIsSecret(e.tool, param, value)
	})
}

func (e *operation) Feedback(text string) string {
	return e.g.engine().ScrubPrepared(text, e.Prepared, false)
}

func (e *operation) Preview(args map[string]any) (approval.Preview, error) {
	prepared, err := e.g.engine().Prepare(e.tool, args)
	if err != nil {
		return approval.Preview{}, approval.NewError(400, e.g.engine().ScrubPrepared(err.Error(), e.Prepared, true))
	}
	e.g.engine().ReviewPreview(prepared, e.Prepared, false)
	return approval.Preview{Preview: prepared.Preview, PreviewHash: prepared.PreviewHash}, nil
}

func (e *operation) Confirm(args map[string]any) (*operation, approval.Preview, map[string]string, error) {
	prepared, err := e.g.engine().Prepare(e.tool, args)
	if err != nil {
		return nil, approval.Preview{}, nil, approval.NewError(400, e.g.engine().ScrubPrepared(err.Error(), e.Prepared, true))
	}
	e.g.engine().ReviewPreview(prepared, e.Prepared, true)
	return &operation{e.g, e.tool, prepared}, approval.Preview{Preview: prepared.Preview, PreviewHash: prepared.PreviewHash}, e.g.engine().ApprovalArgs(e.tool, args, nil), nil
}

func (a *Gateway) Wait(ctx context.Context, t *execution.Tool, args map[string]any, prepared *execution.PreparedCall, client string) (*Approved, error) {
	timeout := a.timeout()
	if timeout <= 0 {
		timeout = a.repo.ApprovalTimeout()
	}
	decision, err := a.Service().Wait(ctx, args, timeout, func(args map[string]any) (*operation, approval.Record, error) {
		snapshot := *t
		snapshot.Params = append([]domain.Param{}, t.Params...)
		for i := range snapshot.Params {
			param := &snapshot.Params[i]
			param.Secret = a.engine().ParamIsSecret(t, *param, args[param.Name])
		}
		operation := &operation{a, &snapshot, prepared}
		record := approval.Record{TS: now(), Tool: a.engine().ScrubPrepared(t.Name, prepared, false), ToolID: t.ID, ToolRev: t.Rev,
			Title: a.engine().ScrubPrepared(t.Title, prepared, false), Client: a.engine().ScrubPrepared(client, prepared, false),
			ArgsDisplay: a.engine().ApprovalArgs(&snapshot, args, nil), Status: "pending", Preview: prepared.Preview, PreviewHash: prepared.PreviewHash,
			Params: a.engine().PreparedParams(&snapshot, args, prepared)}
		return operation, record, nil
	})
	if err != nil {
		return nil, err
	}
	return &Approved{Record: decision.Record, tool: decision.Operation.tool, args: decision.OriginalArgs, finalArgs: decision.Args, Prepared: decision.Operation.Prepared, confirmedHash: decision.Hash}, nil
}

func (a *Gateway) Preview(id int64, nonce string, args map[string]any) (*approval.Preview, error) {
	return a.Service().Preview(id, nonce, args)
}

func (a *Gateway) Decide(id int64, nonce, action string, args map[string]any, feedback, hash string) error {
	return a.Service().Decide(id, nonce, action, args, feedback, hash)
}

func (a *Gateway) List(status string, limit int) ([]approval.Record, error) {
	return a.Service().List(status, limit)
}

func (a *Gateway) Result(id int64) (string, bool, error) {
	return a.Service().Result(id)
}

func now() string { return time.Now().Format("2006-01-02 15:04:05") }

func js(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
