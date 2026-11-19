package flow

import (
	"action2mcp/internal/domain"
	"action2mcp/internal/execution"
	"action2mcp/internal/vault"
	"context"
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func testVault(t *testing.T) *vault.Vault {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE vault(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT UNIQUE, type TEXT, value_enc TEXT, site TEXT DEFAULT '', note TEXT DEFAULT '', created_at TEXT, updated_at TEXT);`); err != nil {
		t.Fatal(err)
	}
	v, err := vault.OpenVault(db, filepath.Join(t.TempDir(), "vault.key"))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestDetectRuntimesAlwaysHasBuiltinJS(t *testing.T) {
	rts := DetectRuntimes()
	if len(rts) < 5 {
		t.Fatalf("expected all runtimes listed, got %d", len(rts))
	}
	if rts[0].ID != "builtin_js" || !rts[0].Builtin || !rts[0].Available {
		t.Fatalf("expected builtin_js first and available, got %+v", rts[0])
	}
	for _, rt := range rts {
		if !rt.Available && rt.Hint == "" {
			t.Fatalf("unavailable runtime %s must include helpful hint", rt.ID)
		}
	}
}

func TestBuiltinJSExecution(t *testing.T) {
	code := `
function main(input, steps) {
  const active = (steps.a.users || []).filter(u => u.active).map(u => u.id);
  const out = [];
  for (let i = 0; i < active.length; i++) {
    out.push(input.prefix + "-" + String(active[i]));
  }
  console.log("count=" + out.length);
  return {
    ids: out,
    region: steps.b?.region ?? "default",
    total: active.length * 10
  };
}
`
	in := map[string]any{"prefix": "USR"}
	steps := map[string]any{
		"a": map[string]any{
			"users": []any{
				map[string]any{"id": 101, "active": true},
				map[string]any{"id": 102, "active": false},
				map[string]any{"id": 103, "active": true},
			},
		},
		"b": map[string]any{"region": "cn-hz"},
	}
	res, logs, err := runBuiltinJS(context.Background(), code, in, steps, nil, nil)
	if err != nil {
		t.Fatalf("runBuiltinJS failed: %v (logs=%s)", err, logs)
	}
	if logs != "count=2" {
		t.Fatalf("logs=%q want count=2", logs)
	}
	m, ok := res.(map[string]any)
	if !ok {
		t.Fatalf("expected map result, got %T (%#v)", res, res)
	}
	if m["region"] != "cn-hz" || m["total"] != int64(20) {
		t.Fatalf("unexpected result: %#v", m)
	}
	ids, ok := m["ids"].([]any)
	if !ok || len(ids) != 2 || ids[0] != "USR-101" || ids[1] != "USR-103" {
		t.Fatalf("unexpected ids: %#v", m["ids"])
	}
}

func TestSerialToolChainABC(t *testing.T) {
	exec := New(Options{
		InvokeTool: func(_ context.Context, name string, args map[string]any, _ string) (any, string, error) {
			switch name {
			case "tool_a":
				return map[string]any{"userId": "u-99", "phone": args["phone"]}, "", nil
			case "tool_b":
				return map[string]any{"orderNo": "ORD-" + args["uid"].(string)}, "", nil
			case "tool_c":
				return map[string]any{"status": "DELIVERED", "order": args["orderNo"]}, "", nil
			default:
				return nil, "", nil
			}
		},
	})

	tool := &execution.Tool{
		Name:   "serial_abc",
		Method: "FLOW",
		Params: []domain.Param{{Name: "phone", Type: "string", Required: true, Default: "13800138000"}},
		Config: execution.ToolConfig{
			Flow: &execution.FlowConfig{
				Steps: []execution.FlowStep{
					{ID: "step_a", Kind: "tool", ToolName: "tool_a", Args: map[string]any{"phone": "{{input.phone}}"}},
					{ID: "step_b", Kind: "tool", ToolName: "tool_b", Args: map[string]any{"uid": "{{steps.step_a.userId}}"}},
					{ID: "step_c", Kind: "tool", ToolName: "tool_c", Args: map[string]any{"orderNo": "{{steps.step_b.orderNo}}"}},
				},
				Output: execution.FlowOutput{Mode: "last"},
			},
		},
	}
	if err := tool.Normalize(); err != nil {
		t.Fatal(err)
	}
	if len(tool.Params) != 1 || tool.Params[0].Name != "phone" {
		t.Fatalf("unexpected params after normalize (step placeholders must not leak into params): %+v", tool.Params)
	}

	res, err := exec.Run(context.Background(), tool, map[string]any{"phone": "13800138000"}, "")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if !res.OK || len(res.StepsTrace) != 3 {
		t.Fatalf("unexpected result: %+v", res)
	}
	outMap, ok := res.FinalOutput.(map[string]any)
	if !ok || outMap["order"] != "ORD-u-99" || outMap["status"] != "DELIVERED" {
		t.Fatalf("unexpected final output: %#v", res.FinalOutput)
	}
}

func TestParallelABThenScriptMergeThenC(t *testing.T) {
	var inFlight atomic.Int32
	var maxConcurrent atomic.Int32
	var mu sync.Mutex
	var cArgs map[string]any

	exec := New(Options{
		InvokeTool: func(_ context.Context, name string, args map[string]any, _ string) (any, string, error) {
			switch name {
			case "tool_a", "tool_b":
				cur := inFlight.Add(1)
				for {
					prev := maxConcurrent.Load()
					if cur <= prev || maxConcurrent.CompareAndSwap(prev, cur) {
						break
					}
				}
				time.Sleep(60 * time.Millisecond)
				inFlight.Add(-1)
				if name == "tool_a" {
					return map[string]any{"uid": 42, "tags": []any{"vip"}}, "", nil
				}
				return map[string]any{"region": "shanghai"}, "", nil
			case "tool_c":
				mu.Lock()
				cArgs = args
				mu.Unlock()
				return map[string]any{"final": "ok", "received": args}, "", nil
			default:
				return nil, "", nil
			}
		},
	})

	tool := &execution.Tool{
		Name:   "parallel_merge_c",
		Method: "FLOW",
		Params: []domain.Param{
			{Name: "mobile", Type: "string", Required: true, Default: "13900001111"},
			{Name: "city", Type: "string", Required: true, Default: "SH"},
		},
		Config: execution.ToolConfig{
			Flow: &execution.FlowConfig{
				Steps: []execution.FlowStep{
					{ID: "step_a", Kind: "tool", ToolName: "tool_a", Args: map[string]any{"mobile": "{{input.mobile}}"}},
					{ID: "step_b", Kind: "tool", ParallelWithPrev: true, ToolName: "tool_b", Args: map[string]any{"city": "{{input.city}}"}},
					{ID: "step_merge", Kind: "script", Runtime: "builtin_js", Code: `function main(input, steps) { return { uid: steps.step_a.uid, loc: steps.step_b.region, tags: steps.step_a.tags }; }`},
					{ID: "step_c", Kind: "tool", ToolName: "tool_c", Args: map[string]any{"uid": "{{steps.step_merge.uid}}", "tags": "{{steps.step_merge.tags}}", "desc": "{{steps.step_merge.loc}}-{{input.city}}"}},
				},
			},
		},
	}

	res, err := exec.Run(context.Background(), tool, map[string]any{"mobile": "13900001111", "city": "SH"}, "")
	if err != nil {
		t.Fatalf("Run failed: %v", err)
	}
	if maxConcurrent.Load() < 2 {
		t.Fatalf("expected step_a and step_b to execute concurrently, maxConcurrent=%d", maxConcurrent.Load())
	}
	if cArgs["desc"] != "shanghai-SH" {
		t.Fatalf("unexpected cArgs: %#v", cArgs)
	}
	// Verify typed array preservation for "{{steps.step_merge.tags}}"
	if tags, ok := cArgs["tags"].([]any); !ok || len(tags) != 1 || tags[0] != "vip" {
		t.Fatalf("expected typed []any preserved in args, got %T %#v", cArgs["tags"], cArgs["tags"])
	}
	if len(res.StepsTrace) != 4 || res.StepsTrace[0].Stage != 1 || res.StepsTrace[1].Stage != 1 || res.StepsTrace[2].Stage != 2 || res.StepsTrace[3].Stage != 3 {
		t.Fatalf("unexpected stage grouping in traces: %+v", res.StepsTrace)
	}
}

func TestVaultScrubAndExternalScriptShellOrPython(t *testing.T) {
	v := testVault(t)
	if err := v.Upsert("api_key", "secret", "super-secret-xyz", "", ""); err != nil {
		t.Fatal(err)
	}
	exec := New(Options{Vault: v})

	// Test missing runtime error hint
	missingTool := &execution.Tool{
		Name:   "bad_rt",
		Method: "FLOW",
		Config: execution.ToolConfig{
			Flow: &execution.FlowConfig{
				Steps: []execution.FlowStep{{ID: "s1", Kind: "script", Runtime: "nonexistent_lang", Code: "print(1)"}},
			},
		},
	}
	if _, err := exec.Run(context.Background(), missingTool, nil, ""); err == nil || !strings.Contains(err.Error(), "不支持") {
		t.Fatalf("expected unsupported runtime error, got %v", err)
	}

	// Test shell runtime if available and verify secret scrubbing
	for _, rt := range DetectRuntimes() {
		if rt.ID == "shell" && rt.Available {
			shTool := &execution.Tool{
				Name:   "sh_test",
				Method: "FLOW",
				Params: []domain.Param{{Name: "name", Type: "string", Default: "world"}},
				Config: execution.ToolConfig{
					Flow: &execution.FlowConfig{
						Steps: []execution.FlowStep{
							{
								ID:      "s1",
								Kind:    "script",
								Runtime: "shell",
								Code:    `printf '{"hello":"world","token":"super-secret-xyz"}'`,
							},
						},
					},
				},
			}
			res, err := exec.Run(context.Background(), shTool, nil, "")
			if err != nil {
				t.Fatalf("shell script failed: %v", err)
			}
			if strings.Contains(res.Body, "super-secret-xyz") {
				t.Fatalf("secret leaked in response body: %s", res.Body)
			}
			break
		}
	}
}

func TestBuiltinJSRegexAndCallToolLoop(t *testing.T) {
	calls := []string{}
	exec := New(Options{
		InvokeTool: func(_ context.Context, name string, args map[string]any, _ string) (any, string, error) {
			calls = append(calls, name+":"+strings.TrimSpace(args["cid"].(string)))
			switch name {
			case "query_logs":
				if args["cid"] == "1000200030007" {
					return map[string]any{"total": 2, "list": []any{"log1", "log2"}}, "", nil
				}
				return map[string]any{"total": 0, "list": []any{}}, "", nil
			default:
				return nil, "", nil
			}
		},
	})

	tool := &execution.Tool{
		Name:   "loop_and_regex",
		Method: "FLOW",
		Params: []domain.Param{{Name: "rawKey", Type: "string", Required: true}},
		Config: execution.ToolConfig{
			Flow: &execution.FlowConfig{
				Steps: []execution.FlowStep{
					{
						ID:      "run",
						Kind:    "script",
						Runtime: "builtin_js",
						Code: `
function main(input, steps) {
  const clean = String(input.rawKey).replace(/^0+/, "");
  const isDigits = /^\d+$/.test(clean);
  const parts = "a, b; c".split(/[,;]\s*/);
  const candidates = ["8000100020003000", "1000200030008", "1000200030007"];
  for (const cid of candidates) {
    const res = callTool("query_logs", { cid: cid });
    if (res && res.total > 0) {
      return { clean, isDigits, parts, matchedCid: cid, total: res.total };
    }
  }
  return { matchedCid: "" };
}`,
					},
				},
			},
		},
	}

	res, err := exec.Run(context.Background(), tool, map[string]any{"rawKey": "001000200030007"}, "")
	if err != nil {
		t.Fatalf("flow run failed: %v", err)
	}
	m := res.FinalOutput.(map[string]any)
	if m["clean"] != "1000200030007" || m["isDigits"] != true || m["matchedCid"] != "1000200030007" || m["total"] != int64(2) {
		t.Fatalf("unexpected output: %#v", m)
	}
	if len(calls) != 3 {
		t.Fatalf("expected 3 sub-calls, got %v", calls)
	}
	if len(res.StepsTrace) != 1 || len(res.StepsTrace[0].SubCalls) != 3 {
		t.Fatalf("expected 3 recorded SubCalls, got %+v", res.StepsTrace)
	}
}

func TestToolStepArgsFromAndOverride(t *testing.T) {
	var gotArgs map[string]any
	exec := New(Options{
		InvokeTool: func(_ context.Context, name string, args map[string]any, _ string) (any, string, error) {
			if name == "target_tool" {
				gotArgs = args
				return map[string]any{"ok": true}, "", nil
			}
			return nil, "", nil
		},
	})

	tool := &execution.Tool{
		Name:   "args_from_test",
		Method: "FLOW",
		Config: execution.ToolConfig{
			Flow: &execution.FlowConfig{
				Steps: []execution.FlowStep{
					{
						ID:      "prep",
						Kind:    "script",
						Runtime: "builtin_js",
						Code:    `function main() { return { payload: { a: "from_obj", b: 42, c: "keep" } }; }`,
					},
					{
						ID:       "call",
						Kind:     "tool",
						ToolName: "target_tool",
						ArgsFrom: "{{steps.prep.payload}}",
						Args:     map[string]any{"a": "overridden"},
					},
				},
			},
		},
	}

	if _, err := exec.Run(context.Background(), tool, nil, ""); err != nil {
		t.Fatalf("args_from flow failed: %v", err)
	}
	if gotArgs["a"] != "overridden" || gotArgs["b"] != int64(42) || gotArgs["c"] != "keep" {
		t.Fatalf("unexpected resolved args: %#v", gotArgs)
	}
}

func TestScriptStepInputArgsMapping(t *testing.T) {
	exec := New(Options{
		InvokeTool: func(_ context.Context, name string, args map[string]any, _ string) (any, string, error) {
			if name == "fetch_user" {
				return map[string]any{"user": map[string]any{"id": "u-42", "name": "Alice"}}, "", nil
			}
			return nil, "", nil
		},
	})
	tool := &execution.Tool{
		Name:   "script_args_mapping",
		Method: "FLOW",
		Params: []domain.Param{{Name: "tag", Type: "string", Required: true}},
		Config: execution.ToolConfig{
			Flow: &execution.FlowConfig{
				Steps: []execution.FlowStep{
					{ID: "u", Kind: "tool", ToolName: "fetch_user", Args: map[string]any{}},
					{
						ID:      "fmt",
						Kind:    "script",
						Runtime: "builtin_js",
						Args: map[string]any{
							"uid":   "{{steps.u.user.id}}",
							"uname": "{{steps.u.user.name}}",
							"label": "{{input.tag}}",
						},
						Code: `function main(input, steps) {
  return { byDirect: uid + ":" + uname, byParams: params.label, byInput: input.uid + "/" + input.label };
}`,
					},
				},
			},
		},
	}
	res, err := exec.Run(context.Background(), tool, map[string]any{"tag": "vip"}, "")
	if err != nil {
		t.Fatalf("script args mapping failed: %v", err)
	}
	m := res.FinalOutput.(map[string]any)
	if m["byDirect"] != "u-42:Alice" || m["byParams"] != "vip" || m["byInput"] != "u-42/vip" {
		t.Fatalf("unexpected output: %#v", m)
	}
}
