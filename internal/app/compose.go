package app

import (
	"action2mcp/internal/analysis"
	"action2mcp/internal/catalog"
	"action2mcp/internal/console"
	"action2mcp/internal/execution"
	"action2mcp/internal/flow"
	"action2mcp/internal/invoke"
	"action2mcp/internal/mcp"
	"action2mcp/internal/mcpserver"
	"action2mcp/internal/mwtools"
	"action2mcp/internal/transfer"
	"action2mcp/internal/updater"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Composition of feature services. Each factory wires explicit ports; no service
// receives the App itself.

func (a *App) recAnalysis() *analysis.Service {
	a.analysisOnce.Do(func() {
		a.analysisService = analysis.New(analysis.Options{
			Repository: a.store, Vault: a.vault,
			InputSchema:        func(t *execution.Tool) map[string]any { return a.executor().McpInputSchema(t) },
			ValidateTool:       func(t *execution.Tool) error { return a.tools().Validate(t) },
			ToolsChanged:       a.broadcastToolsChanged,
			LoadedPackNames:    func(s *mcp.Session) []string { return a.mcpServer().LoadedPackNames(s) },
			ResetLoginFailures: func() { a.loginRuntime().ResetSiteFailures() },
		})
	})
	return a.analysisService
}

func (a *App) approvals() *invoke.Gateway {
	a.gatewayOnce.Do(func() {
		a.gatewayService = invoke.New(invoke.Options{
			Repository: a.store, Approvals: a.store.Approvals, Quit: a.quit, Engine: a.executor,
			Timeout: func() time.Duration { return a.approvalTimeout },
			InsertHook: func() error {
				if a.approvalInsertHook != nil {
					return a.approvalInsertHook()
				}
				return nil
			},
			DecideHook: func() error {
				if a.approvalDecideHook != nil {
					return a.approvalDecideHook()
				}
				return nil
			},
		})
	})
	return a.gatewayService
}

func (a *App) middlewares() *mwtools.Service {
	a.middlewareOnce.Do(func() {
		a.middlewareService = mwtools.New(mwtools.Options{
			Repository: a.store, Secrets: a.vault, Drivers: &a.drivers, Cookies: a.CookiesFor,
			Login:     func() mwtools.Login { return a.loginRuntime() },
			Engine:    a.executor,
			Approvals: a.approvals,
		})
	})
	return a.middlewareService
}

func (a *App) mcpServer() *mcpserver.Server {
	a.mcpOnce.Do(func() {
		a.mcpService = mcpserver.New(mcpserver.Options{
			Version: Version, Repository: a.store, Sessions: &a.mcpSessions, Engine: a.executor,
			Analysis: a.recAnalysis, Middlewares: a.middlewares, Approvals: a.approvals, Flow: a.flowRuntime,
		})
	})
	return a.mcpService
}

func (a *App) flowRuntime() *flow.Executor {
	a.flowOnce.Do(func() {
		a.flowService = flow.New(flow.Options{
			Vault: a.vault,
			InvokeTool: func(ctx context.Context, toolName string, args map[string]any, explanation string) (any, string, error) {
				toolName = strings.TrimSpace(toolName)
				if toolName == "" {
					return nil, "", errors.New("子节点缺少 tool_name")
				}
				if _, ok := mwtools.IsTool(toolName); ok {
					text, isErr := a.middlewares().Call(ctx, "自定义工具编排", toolName, args)
					if isErr {
						return nil, text, errors.New(text)
					}
					var parsed any
					if json.Unmarshal([]byte(strings.TrimSpace(text)), &parsed) != nil {
						parsed = text
					}
					return parsed, text, nil
				}
				subTool, err := a.store.GetToolByName(toolName)
				if err != nil || subTool == nil {
					return nil, "", fmt.Errorf("未找到名为 %s 的子工具", toolName)
				}
				var pending *invoke.Approved
				prepared, err := a.executor().Prepare(subTool, args)
				if err != nil {
					return nil, "", err
				}
				if subTool.Approval == "always" {
					pending, err = a.approvals().Wait(ctx, subTool, args, prepared, "自定义工具编排", explanation)
					if err != nil {
						return nil, "", err
					}
					cur, gerr := a.store.GetTool(subTool.ID)
					if gerr != nil || cur == nil || cur.Rev != pending.Record.ToolRev || cur.Approval != "always" || pending.Prepared == nil {
						msg := "未执行：子工具在审批期间已变更"
						a.approvals().Service().RecordResult(pending.Record.ID, msg)
						return nil, "", errors.New(msg)
					}
					prepared = pending.Prepared
				}
				if execution.IsFlowMethod(subTool.Method) {
					res, err := a.flowRuntime().Run(ctx, subTool, args, explanation)
					if err != nil {
						if pending != nil {
							a.approvals().Service().RecordResult(pending.Record.ID, "调用失败："+err.Error())
						}
						return nil, "", err
					}
					if pending != nil {
						a.approvals().Service().RecordResult(pending.Record.ID, res.Body)
					}
					if !res.OK {
						return nil, res.Body, errors.New(execution.FirstNonEmpty(res.Error, res.Body, "子流程执行失败"))
					}
					return res.FinalOutput, res.Body, nil
				}
				res, err := a.executor().Send(prepared)
				if err != nil {
					if pending != nil {
						a.approvals().Service().RecordResult(pending.Record.ID, "调用失败："+err.Error())
					}
					return nil, "", err
				}
				if pending != nil {
					a.approvals().Service().RecordResult(pending.Record.ID, res.Body)
				}
				if res.Outcome != "" && res.Outcome != execution.OutcomeSuccess {
					return nil, res.Body, errors.New(execution.FirstNonEmpty(res.Error, res.Body))
				}
				if res.Error != "" {
					return nil, res.Body, errors.New(res.Error)
				}
				if res.Status >= 400 {
					return nil, res.Body, fmt.Errorf("HTTP %d: %s", res.Status, res.Body)
				}
				var parsed any
				if json.Unmarshal([]byte(strings.TrimSpace(res.Body)), &parsed) != nil {
					parsed = res.Body
				}
				return parsed, res.Body, nil
			},
		})
	})
	return a.flowService
}

// Application events invalidate discovery for every connected transport session.
func (a *App) broadcastToolsChanged() { a.mcpSessions.BroadcastToolsChanged() }

func (a *App) transfer() *transfer.Service {
	a.transferOnce.Do(func() {
		a.transferService = transfer.New(transfer.Options{
			Repository: a.store, Secrets: a.vault,
			MarkSecretParams: func(t *execution.Tool) { a.executor().MarkSecretParams(t) },
			DropDriver:       a.drivers.Drop,
		})
	})
	return a.transferService
}

func (a *App) tools() *catalog.Service {
	a.catalogOnce.Do(func() {
		a.catalogService = catalog.New(catalog.Options{
			Repository: a.store, Secrets: a.vault,
			MarkSecretParams: func(t *execution.Tool) { a.executor().MarkSecretParams(t) },
			ToolsChanged:     a.broadcastToolsChanged,
		})
	})
	return a.catalogService
}

// Handler is the local web console plus the MCP endpoint.
func (a *App) Handler() http.Handler { return a.console().Handler() }

func (a *App) updaterRuntime() *updater.Service {
	a.updaterOnce.Do(func() {
		a.updaterService = updater.New(updater.Options{
			CurrentVersion: Version,
			HTTPClient:     a.httpClient,
		})
	})
	return a.updaterService
}

func (a *App) console() *console.Server {
	a.consoleOnce.Do(func() {
		a.consoleService = console.New(console.Options{
			Port: a.cfg.Port, Store: a.store, Vault: a.vault, Sessions: &a.mcpSessions, Quit: a.quit,
			Status:   func() any { return a.Status() },
			Shutdown: a.Shutdown,
			Exit:     func() { exitServer() },
			Browser:  func() console.Browser { return a.browserRuntime() },
			Login:    func() console.Login { return a.loginRuntime() },
			Engine:   a.executor, Analysis: a.recAnalysis, Middlewares: a.middlewares, Approvals: a.approvals, Flow: a.flowRuntime,
			Transfer: a.transfer, Tools: a.tools, MCPServer: a.mcpServer,
			Updater: a.updaterRuntime,
			Restart: func(exePath string) error { return spawnRestart(exePath, a.dataDir) },
			ToolsChanged: a.broadcastToolsChanged, DropDriver: a.drivers.Drop,
		})
	})
	return a.consoleService
}
