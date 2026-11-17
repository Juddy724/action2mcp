package approval

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
)

const MaxPending = 20

// Operation is the execution-owned approval port. It retains the immutable tool
// and prepared-request snapshots; the approval service never sees browser state,
// executable credentials, or mutable application internals. Confirm must prepare
// again and retain the original sensitivity floor. No method executes a request.
type Operation[T any] interface {
	Edit(original, edits map[string]any) (map[string]any, error)
	Preview(args map[string]any) (Preview, error)
	Confirm(args map[string]any) (T, Preview, map[string]string, error)
	Feedback(text string) string
}

// Repository persists approval records, not raw args, nonces or prepared calls.
// Sweep is invoked under the service lock so only genuinely live ids survive.
type Repository interface {
	Insert(*Record) error
	Finish(*Record) error
	Sweep(live []int64) error
	List(status string, limit int) ([]Record, error)
	Exists(id int64) (bool, error)
	SaveResult(id int64, result string) error
	Result(id int64) (string, bool, error)
}

type Options struct {
	Quit   <-chan struct{}
	Notify func(tool string)
}

type pending[T Operation[T]] struct {
	record               Record
	operation            T
	args, finalArgs      map[string]any
	confirmedHash, nonce string
	deadline             time.Time
	done                 chan struct{}
	err                  error
}

// Decision is returned only after durable approval. It is a completed execution
// handoff, never a pointer into the live pending map. The caller must revalidate
// tool exposure/revision and the confirmed request fingerprint before sending.
type Decision[T Operation[T]] struct {
	Record       Record         `json:"-"`
	Operation    T              `json:"-"`
	OriginalArgs map[string]any `json:"-"`
	Args         map[string]any `json:"-"`
	Hash         string         `json:"-"`
}

// Service owns pending approval state and all terminal transitions. Its mutex,
// nonce/deadline map and completion channels are private to this package.
type Service[T Operation[T]] struct {
	mu      sync.Mutex
	pending map[int64]*pending[T]
	repo    Repository
	options Options
}

func NewService[T Operation[T]](repo Repository, options Options) *Service[T] {
	return &Service[T]{repo: repo, options: options, pending: map[int64]*pending[T]{}}
}

// Wait first copies/bounds MCP args, then creates the execution-owned sensitivity
// snapshot. Only the scrubbed record goes to persistence or notifications.
func (s *Service[T]) Wait(ctx context.Context, args map[string]any, timeout time.Duration, create func(map[string]any) (T, Record, error)) (*Decision[T], error) {
	args, err := CopyArgs(args)
	if err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.New("审批记录保存失败，未执行")
	}
	operation, record, err := create(args)
	if err != nil {
		return nil, err
	}
	record.Status = "pending"
	p := &pending[T]{operation: operation, args: args, record: record, nonce: hex.EncodeToString(nonce[:]), deadline: time.Now().Add(timeout), done: make(chan struct{})}
	s.mu.Lock()
	if err := s.repo.Sweep(s.liveIDs()); err != nil {
		s.mu.Unlock()
		return nil, errors.New("审批记录保存失败，未执行")
	}
	if len(s.pending) >= MaxPending {
		s.mu.Unlock()
		return nil, NewError(429, "待审批调用过多，未执行，请稍后再次调用")
	}
	if err := s.repo.Insert(&p.record); err != nil {
		s.mu.Unlock()
		var ae *Error
		if errors.As(err, &ae) && ae.Status == 429 {
			return nil, err
		}
		return nil, errors.New("审批记录保存失败，未执行")
	}
	s.pending[p.record.ID] = p
	notificationTool := p.record.Tool
	s.mu.Unlock()
	if s.options.Notify != nil {
		go s.options.Notify(notificationTool)
	}
	timer := time.NewTimer(time.Until(p.deadline))
	defer timer.Stop()
	select {
	case <-p.done:
	case <-timer.C:
		s.end(p, "timeout")
	case <-ctx.Done():
		s.end(p, "cancelled")
	case <-s.options.Quit:
		s.end(p, "cancelled")
	}
	<-p.done
	if p.err != nil {
		return nil, p.err
	}
	switch p.record.Status {
	case "approved", "edited":
		return &Decision[T]{Record: p.record, Operation: p.operation, OriginalArgs: p.args, Args: p.finalArgs, Hash: p.confirmedHash}, nil
	case "rejected":
		return nil, fmt.Errorf("用户未批准本次调用。用户意见：%s。请按意见修改参数后再次调用本工具（会再次请求审批）；不要绕过审批。", p.record.Feedback)
	case "timeout":
		return nil, errors.New("审批超时，未执行。如需继续请再次调用。")
	default:
		return nil, errors.New("审批已取消，未执行")
	}
}

func (s *Service[T]) liveIDs() []int64 {
	ids := make([]int64, 0, len(s.pending))
	for id := range s.pending {
		ids = append(ids, id)
	}
	return ids
}

func (s *Service[T]) end(p *pending[T], status string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.record.Status != "pending" {
		return
	}
	r := p.record
	r.Status, r.DecidedAt = status, now()
	if err := s.repo.Finish(&r); err != nil {
		log.Printf("审批 #%d 结束记录保存失败", r.ID)
	}
	p.record = r
	delete(s.pending, r.ID)
	close(p.done)
}

func (s *Service[T]) pendingWithNonce(id int64, nonce string) (*pending[T], error) {
	p := s.pending[id]
	if p == nil {
		exists, err := s.repo.Exists(id)
		if err != nil {
			return nil, NewError(500, "读取审批失败")
		}
		if !exists {
			return nil, NewError(404, "审批不存在")
		}
		return nil, NewError(409, "本次审批已结束")
	}
	if p.record.Status != "pending" {
		return nil, NewError(409, "本次审批已结束")
	}
	if subtle.ConstantTimeCompare([]byte(p.nonce), []byte(nonce)) != 1 {
		return nil, NewError(403, "审批凭证不正确")
	}
	if !time.Now().Before(p.deadline) {
		return nil, NewError(409, "本次审批已过期")
	}
	return p, nil
}

func (s *Service[T]) Preview(id int64, nonce string, args map[string]any) (*Preview, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.pendingWithNonce(id, nonce)
	if err != nil {
		return nil, err
	}
	edited, err := p.operation.Edit(p.args, args)
	if err != nil {
		return nil, err
	}
	preview, err := p.operation.Preview(edited)
	if err != nil {
		return nil, err
	}
	return &preview, nil
}

func (s *Service[T]) Decide(id int64, nonce, action string, args map[string]any, feedback, previewHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, err := s.pendingWithNonce(id, nonce)
	if err != nil {
		return err
	}
	r := p.record
	r.DecidedAt = now()
	var operation T
	var finalArgs map[string]any
	switch action {
	case "reject":
		feedback = strings.TrimSpace(feedback)
		if feedback == "" {
			return NewError(400, "拒绝时请填写意见")
		}
		r.Status = "rejected"
		r.Feedback = p.operation.Feedback(feedback)
	case "approve", "edit":
		if previewHash == "" {
			return NewError(400, "请提供 preview_hash")
		}
		finalArgs = p.args
		if action == "edit" {
			finalArgs, err = p.operation.Edit(p.args, args)
			if err != nil {
				return err
			}
		}
		var preview Preview
		operation, preview, r.FinalArgsDisplay, err = p.operation.Confirm(finalArgs)
		if err != nil {
			return err
		}
		if preview.PreviewHash != previewHash {
			return NewError(409, "预览已过期，请刷新后重新确认")
		}
		r.Status = "approved"
		if action == "edit" {
			r.Status = "edited"
		}
		r.Preview, r.PreviewHash = preview.Preview, preview.PreviewHash
	default:
		return NewError(400, "审批操作只能是 approve、edit 或 reject")
	}
	if err := s.repo.Finish(&r); err != nil {
		p.err = errors.New("审批决定保存失败，未执行")
		cancelled := p.record
		cancelled.Status, cancelled.DecidedAt = "cancelled", now()
		if saveErr := s.repo.Finish(&cancelled); saveErr != nil {
			log.Printf("审批 #%d 取消记录保存失败", r.ID)
		}
		p.record = cancelled
		delete(s.pending, r.ID)
		close(p.done)
		return NewError(500, p.err.Error())
	}
	p.record, p.finalArgs = r, finalArgs
	if action == "approve" || action == "edit" {
		p.operation, p.confirmedHash = operation, previewHash
	}
	delete(s.pending, r.ID)
	close(p.done)
	return nil
}

func (s *Service[T]) List(status string, limit int) ([]Record, error) {
	if status == "" {
		status = "pending"
	}
	if status != "pending" && status != "all" {
		return nil, NewError(400, "审批状态只能是 pending 或 all")
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.repo.Sweep(s.liveIDs()); err != nil {
		return nil, err
	}
	rows, err := s.repo.List(status, limit)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if p := s.pending[rows[i].ID]; rows[i].Status == "pending" && p != nil {
			rows[i].Nonce = p.nonce
		}
	}
	return rows, nil
}

func (s *Service[T]) RecordResult(id int64, result string) {
	if err := s.repo.SaveResult(id, result); err != nil {
		log.Printf("审批 #%d 执行结果保存失败", id)
	}
}
func (s *Service[T]) Result(id int64) (string, bool, error) { return s.repo.Result(id) }
