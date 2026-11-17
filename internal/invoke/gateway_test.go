package invoke

import (
	"action2mcp/internal/approval"
	"action2mcp/internal/domain"
	"action2mcp/internal/execution"
	"action2mcp/internal/mwconfig"
	"database/sql"
	"errors"
	"testing"
	"time"
)

type fakeRepository struct {
	rev map[int64]int64
}

func (f fakeRepository) ApprovalTimeout() time.Duration { return time.Minute }
func (f fakeRepository) GetMiddleware(int64) (*mwconfig.Middleware, error) {
	return nil, sql.ErrNoRows
}
func (f fakeRepository) ExposedMiddleware() ([]*mwconfig.Middleware, map[int64][]string) {
	return nil, nil
}
func (f fakeRepository) EnabledToolRevision(id int64) (int64, error) {
	rev, ok := f.rev[id]
	if !ok {
		return 0, sql.ErrNoRows
	}
	return rev, nil
}

func testGateway(repo Repository) *Gateway {
	engine := execution.New(execution.Options{})
	return New(Options{Repository: repo, Engine: func() *execution.Engine { return engine },
		Timeout: func() time.Duration { return 0 }, InsertHook: func() error { return nil }, DecideHook: func() error { return nil }})
}

func testTool() *execution.Tool {
	return &execution.Tool{ID: 7, Rev: 3, Name: "gate", Method: "POST", URL: "http://127.0.0.1:9/api",
		Headers: map[string]string{"Content-Type": "application/json"}, Body: `{"value":"{{value}}"}`,
		Params: []domain.Param{{Name: "value", Type: "string", Required: true}}}
}

func TestCommitValidRequiresUnchangedPreparedRequest(t *testing.T) {
	tool := testTool()
	g := testGateway(fakeRepository{rev: map[int64]int64{7: 3}})
	prepared, err := g.engine().Prepare(tool, map[string]any{"value": "one"})
	if err != nil {
		t.Fatal(err)
	}
	p := &Approved{tool: tool, Record: approval.Record{ToolRev: tool.Rev}, Prepared: prepared, confirmedHash: prepared.PreviewHash}
	if !g.CommitValid(p) {
		t.Fatal("unchanged prepared request failed integrity check")
	}
	changed := *tool
	changed.Body += " "
	if p.Prepared, err = g.engine().Prepare(&changed, map[string]any{"value": "one"}); err != nil {
		t.Fatal(err)
	}
	if g.CommitValid(p) {
		t.Fatal("modified prepared request passed integrity check")
	}
	p.Prepared = prepared
	if testGateway(fakeRepository{rev: map[int64]int64{7: 4}}).CommitValid(p) {
		t.Fatal("tool revision change passed commit gate")
	}
	if testGateway(fakeRepository{}).CommitValid(p) {
		t.Fatal("tool outside enabled packs passed commit gate")
	}
}

func TestOperationEditKeepsOriginalsAndReportsChangedKeys(t *testing.T) {
	tool := testTool()
	tool.Params = append(tool.Params, domain.Param{Name: "count", Type: "integer"})
	g := testGateway(fakeRepository{})
	original := map[string]any{"value": "keep", "count": float64(1)}
	merged, err := (&operation{g: g, tool: tool}).Edit(original, map[string]any{"count": "2"})
	if err != nil || merged["value"] != "keep" || merged["count"] != "2" || original["count"] != float64(1) {
		t.Fatalf("partial edit merged incorrectly: %v %v", merged, err)
	}
	prepared, err := g.engine().Prepare(tool, merged)
	if err != nil {
		t.Fatal(err)
	}
	prefix := g.EditPrefix(&Approved{Record: approval.Record{Status: "edited", FinalArgsDisplay: map[string]string{"count": "2"}}, tool: tool, args: original, finalArgs: merged, Prepared: prepared})
	if prefix != "（用户修改了参数；修改的参数：count：2）\n" {
		t.Fatalf("edit prefix = %q", prefix)
	}
	if g.EditPrefix(&Approved{Record: approval.Record{Status: "approved"}}) != "" {
		t.Fatal("unedited approval must not add a prefix")
	}
}

func TestRepositoryHooksAreLateBound(t *testing.T) {
	var fail error
	g := New(Options{InsertHook: func() error { return fail }, DecideHook: func() error { return fail }})
	repo := approvalRepository{g: g}
	fail = errors.New("injected")
	if err := repo.Insert(&approval.Record{}); !errors.Is(err, fail) {
		t.Fatalf("insert hook not consulted at call time: %v", err)
	}
	if err := repo.Finish(&approval.Record{Status: "edited"}); !errors.Is(err, fail) {
		t.Fatalf("decide hook not consulted for edited decision: %v", err)
	}
}
