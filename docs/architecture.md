# Architecture

Action2MCP remains version **0.6.1**, with database user version **12**. Package extraction does not change the CLI, HTTP routes, MCP methods, configuration JSON, saved-data paths or approval policy.

## Packages

| Path | Responsibility |
|---|---|
| `cmd/a2m` | Process entry; calls `app.Main`. |
| `internal/app` | Composition root only: `App` lifecycle (`NewApp`, `Status`, `Shutdown`), CLI/stdio bridge and lazy `sync.Once` service factories (`compose.go`, `*_adapter.go`). No feature behaviour; `TestAppIsCompositionOnly` fails if a feature file is added. |
| `internal/config` | Configuration file/environment precedence and executable-relative data-path resolution. No services or application dependencies. |
| `internal/credential` | Configuration-reference syntax, canonical credential origins, header bindings and immutable replay-header policy. Stores no credentials. |
| `internal/vault` | Encrypted configuration storage; associated-data-bound site-header encryption; bounded, encoding-aware secret scrubbing. Key, cache and locks remain private. Recording receives copied secret-value snapshots rather than accessing the vault cache. |
| `internal/recording` | Request/annotation DTOs, HTTP and WebSocket CDP-event capture, frame limits, recording SQL repository, annotation validation and override cache, URL grouping and noise policy. Browser launch lives in `browser`; MCP recording-analysis tools live in `analysis`. |
| `internal/site` | Login-site/configuration DTOs, login-response classification, site SQL repository and synchronized updates, recorded WeCom-login evidence detection and safe read/merge/write. Does not open a browser or perform automatic relogin. |
| `internal/browser` | Dedicated browser/profile process and CDP/page runtime, visible/headless leases, ignored internal tabs, overlays, cookies, capture routing and recording start/stop lifecycle. Private manager/session locks; repository, capture and login/header callbacks are injected. |
| `internal/login` | Per-site login generation/semaphore, pending/cooldown/cancellation/window/replay/keepalive runtime; encrypted header SQL and stale-hop generations. Explicit browser/surface, repository, HTTP/probe and middleware-header projection ports; no App/Store/shared-state getters. |
| `internal/mcp` | Per-transport client identity and loaded-pack state, session expiry, bounded notifications, SSE stream replacement/cleanup and session deletion. Tool discovery/execution lives in `mcpserver`. |
| `internal/domain` | Parameter and request-preview wire contracts, deterministic argument text conversion. No services or state. |
| `internal/approval` | Typed approval lifecycle service; private pending map/mutex/nonces/deadlines; durable decisions, bounded whole-argument edits, history/results SQL repository. Execution preview/confirm policy and host notifications are explicit ports. |
| `internal/result` | HTML cleaning/fallback, alert and JSON business-failure detection, HTTP-only presentation truncation. Operates on a presentation projection, not mutable browser/session/prepared state. |
| `internal/execution` | Tool models/configuration/draft building, template binding/rendering, complete sensitivity/preview policy, frozen prepared calls, HTTP/WS send/retry/relogin orchestration, WS SQL/EXPLAIN handling, presentation and final secret scrubbing. Login state, cookies/header acquisition and generated-console refresh are explicit ports; no App/Store/browser instance is passed in. |
| `internal/middleware` | Native MySQL/OceanBase, Redis and Kafka/RabbitMQ/RocketMQ drivers; SQL AST and key/topic scope enforcement, execution/result budgets, client pool and invalidation. No App/browser/store/vault imports. WebSocket and SQL-console orchestration live in `mwtools`. |
| `internal/mwconfig` | Middleware/datasource configuration DTOs, normalization, permission labels, SQL-console tool generation/fingerprints and legacy SQL default promotion. Password overrides are private and never serialized. |
| `internal/store` | SQLite schema/migrations (user version 12), settings, tools/packs, cookies, middleware CRUD and the bounded audit log. Shares one handle with recording/site/approval repositories. |
| `internal/analysis` | MCP recording-analysis pack (`rec_*` tools): listing, annotation, draft preparation, sanitization/parameterization and saving, behind a consumer-owned `Repository` and callbacks for schema, validation, list_changed and loaded packs. |
| `internal/invoke` | Approval-gated invocation: pending records, waits, edit/preview operations, edit-prefix and the final commit gate (pack exposure, tool revision, console fingerprint, prepared fingerprint). Test hooks/timeouts are read late through callbacks. |
| `internal/mwtools` | Middleware MCP tools: catalog/descriptions, permission checks and audit, native driver routing, WebSocket terminals and SQL consoles (through `invoke`). Repository/secrets/login are narrow ports. |
| `internal/mcpserver` | Streamable-HTTP MCP adapter: JSON-RPC framing, flat/tiered discovery, pack load/unload, tools/call routing and annotations. Sessions are the App-owned `mcp.Manager`. |
| `internal/catalog` | Single write path for recorded tools: vault references, normalization, reserved names, secret flags, site row, list_changed. |
| `internal/transfer` | Secret-free export/import of tools, packs, middleware and sites; only empty vault placeholders are created. |
| `internal/console` | Local web console HTTP API and loopback/origin guards. Administers the store/vault directly; every runtime collaborator (browser, login, engine, analysis, middleware, approvals, transfer, catalog, MCP) is an injected callback or narrow interface. |
| `internal/cdp` | Chrome DevTools Protocol connection. Unchanged. |
| `internal/htmlmd` | HTML classification, selector validation and Markdown conversion. Unchanged. |
| `internal/ahocorasick` | Multi-pattern byte matcher used by secret scrubbing. Unchanged. |
| `internal/sqlguard` | Read-only single-statement SELECT/LIMIT policy; never opens a database connection. Unchanged. |
| `web` | Explicitly embeds only `index.html`, `app.js` and `style.css`. Unchanged. |

## Dependency direction

```text
cmd/a2m -> app (composition root) -> every feature package below
console   -> analysis, approval, browser, catalog, credential, domain, execution, invoke, login, mcp, mcpserver, mwconfig, mwtools, recording, site, store, transfer, vault, web
mcpserver -> analysis, approval, execution, invoke, mcp, mwconfig, mwtools, store
mwtools   -> credential, execution, invoke, mcp, middleware, mwconfig, site, sqlguard, store, vault
invoke    -> approval, domain, execution, mwconfig
analysis  -> credential, domain, execution, login, mcp, recording, site, store, vault
catalog   -> analysis, execution, mcp, site
transfer  -> credential, domain, execution, mwconfig, site, store, vault
store     -> approval, domain, execution, mwconfig, recording, site
mwconfig  -> credential, domain, execution
browser   -> cdp, domain, execution, recording, site
login     -> browser, credential, execution, site, vault
approval  -> domain, vault (argument-size limit only; no Vault instance)
execution -> credential, domain, vault, recording, result, htmlmd, sqlguard
result -> domain, htmlmd;  site -> credential, recording, domain;  vault -> credential, ahocorasick;  recording -> cdp
mcp, config, credential, middleware, domain -> no application packages
```

`web` is embedded by the console; CDP enters through browser/recording, and HTML presentation/selector dependencies through execution/result. No extracted production package imports app. `TestFeaturePackageDependencyDirection` enforces these boundaries; the Go compiler checks cycles.

The recording `Repository` interface is owned by its consumer and exposes only insert/update operations. `Hooks` injects classification, credential-header harvesting, ignored-target checks and CDP body-fetch commands. The browser manager connects these ports to its private session/page state and injected recording repository and login-header callbacks. The recorder neither launches a browser nor obtains application globals.

`store.Store` is a repository aggregate: it shares its existing SQLite connection with `recording.Store` and `site.Repository`. These repositories keep their database handles, caches and locks private. Schema creation and versioned migrations run in `store.OpenStore`, including recording annotation backfill and site-origin migration. There is no new database or migration version.

`site.Repository.UpdateSite` holds the same writer lock used by manual saves while automatic login detection reads, merges and optionally writes a site. Detection cannot bypass that lock by using an exported mutex or an unlocked save method. The merge callback must not recursively invoke a site writer.

MCP session methods atomically load/unload packs and copy visible pack IDs. Only the transport package manipulates session locks/channels. Stream replacement closes the old stream under its lock; an old request's cleanup cannot remove its replacement. Notification sends remain non-blocking with the original 32-message buffer.

Native `middleware.Drivers` owns the complete SQL/Redis/MQ implementations, not wrappers around App methods. It has a zero-value concurrent pool and three public operations: `Test`, `Execute`, and `Drop`. A call receives a typed native `Target`/`Config` snapshot and a just-in-time password resolver. Its caller-owned `Observer` port carries permission requests, blocked actions and completion results/errors; the `mwtools` observer preserves the existing audit and secret-scrubbing policy. Pool mutexes, maps, clients, SQL plans, Redis command tables and MQ consumers stay private. Cache identity still hashes the full persisted configuration plus the current password; save/delete/import/test routes invalidate the package-owned pool directly.

`mwconfig` owns middleware DTOs and labels, `store` the audit SQL, `mwtools` WebSocket/SQL-console orchestration and `invoke` approval orchestration. `mwtools/native.go` deliberately maps only native connection/scope/budget fields; it does not pass App, Store, Vault, browser state, WS auth configuration or arbitrary getter access into drivers. Native unit tests moved with the implementation; app adapter tests cover unchanged configuration mapping, audit actions and secret scrubbing.

`approval.Service[T]` owns registration, cap enforcement, nonce/expiry validation, approval/edit/rejection, competing cancellation/timeout/shutdown transitions, orphan repair and list limits. Its `Repository` persists scrubbed records only. `Operation[T]` is a typed execution-owned port for edits, preview, fresh confirmation and feedback scrubbing; it never sends a request. A completed `Decision[T]` is returned only after durable approval, has no pointer into the live pending map, and explicitly excludes raw argument/operation fields from JSON serialization. Nonces and executable prepared requests are never persisted. `invoke.Gateway.CommitValid` revalidates enabled-pack exposure, tool revision and prepared-request fingerprint immediately before send; SQL-console fingerprint checks are unchanged.

`approval.SQLStore` uses the existing SQLite handle; construction, export and import do not cancel pending rows. Server startup invokes cancellation explicitly. Terminal persistence errors still release the in-memory slot and wake callers fail-closed; later polls/calls repair orphan rows. Result persistence still caps complete results at 1 MiB and list previews at 2 KiB/20 lines. `invoke` wires typed operations to execution-owned sensitivity, prepare and review APIs, and retains the existing private fault-injection repository adapter for integration tests. Historical redaction lists stay private inside PreparedCall; no pending locks/maps/channels exist in App.

`result.Present` receives only format/selector/detection and HTTP/WS/SQL-guard flags plus a result projection. The execution engine applies it after relogin and before secret scrubbing, copying only body/error/outcome/truncation back into the full call result. SQL-guard WS results and pre-existing non-success outcomes are still untouched; WS output does not acquire the HTTP 60 KiB presentation cap. HTTP status, URL, request metadata and redirect/login traces remain transport-owned.

`execution.Engine` owns the full prepared-tool/send business boundary, not just transport helpers. It binds one preparation-time clock snapshot; credential references and their encoding locations are deferred and frozen privately. `PreparedCall.Fingerprint` reads the frozen request, not mutable display fields. `ReviewPreview` carries earlier secret/configuration redaction into confirmed edits without exposing raw lists or changing execution. The tool/config DTO JSON is unchanged; console bindings and malformed stored configuration remain private and excluded from serialization. Public configuration/template APIs are only the operations used by recorder/persistence adapters; there is no blanket private-field export.

`execution.Sessions.Begin` obtains the existing generation snapshot and pending-login check before cookies or transport. Its opaque Session delegates validation/relogin/status persistence without leaking App locks or maps. HTTP stale-profile refresh, one automatic relogin, and the second-HTTP-403 exception are unchanged. The WS relogin port explicitly preserves whether post-login header harvesting is required, including the former callback early-return behavior. Cookie/header/profile ports are synchronous and retain the existing call order; Engine introduces no state lock or background worker. The App `executionConsole` adapter refreshes generated SQL tools via `mwtools` and supplies display-only console metadata; final pack/revision/console-fingerprint approval checks remain in the caller.

`execution.HTTPGuard` takes only the configured console port and an existing HTTP client; its clone wraps logical requests and redirects and pins dialing to checked IPs. The native transport's private pool is closed without mutating the source client. Direct WebSocket dial/peer checks use the same `CheckIP` policy. Domain/approval/result/execution package ownership is explicitly enforced by the architecture regression test.

## Browser and login ownership

`browser.Manager` owns only process/page/profile leases and recording lifecycle; it does not own login state. `login.Service` independently owns all generation/cooldown/pending/cancellation and header-generation locks, plus its dedicated SQL handle. Both receive narrow consumer-defined repository ports, not App or Store. Recording-login detection belongs to `site.RecordingDetector` and uses the same synchronized site update as manual saves. Its wire result lives in `domain`.

Browser launch configuration and login HTTP/client/console settings are read through callbacks at use time, preserving the previous runtime/test semantics. Header-harvest callbacks resolve login lazily to avoid a browser/login `sync.Once` construction cycle. Capture event ordering, cookie rules, delayed overlay close and pending-login timing are unchanged. Stop/status projections are copied under the manager lock, including the nested login result; consumers cannot mutate its retained last-stop state.

Original private wait/window/detector tests moved to their owners. New loopback CDP tests cover tab/session routing and cookie wire policy; manager seams cover dynamic launch configuration, concurrent leases, copied state, ignored tabs, detach cleanup, event forwarding, pending WebSocket flush and overlay stop. Login seams cover captured execution generations, collapse of stale concurrent relogins, pending gating/expiry and cooldown reset without damaging pending state.

## Compatibility and security boundaries

- `config.ResolveDataDir`: `A2M_DATA` wins; otherwise use the executable directory plus `data`, not the working directory. Environment/file precedence is unchanged.
- Vault key format, encryption format and site-header associated-data string are unchanged. Snapshot APIs do not make the console or local data directory safe against a hostile local user.
- Existing approval limits, parser budgets, masking floors and result/config-token masking policies are unchanged. Vault's exported read-only decoding limits are also used by approval parsing.
- Request-body/frame limits and recording timestamps are unchanged. Finishing a capture returns a locked statistics snapshot rather than leaking mutable internal recording state.
- Loopback/origin guards and all HTTP/stdio behavior remain in the existing adapters. No container/public binding, Docker support or remote browser exposure is added.

## Build and verification

```sh
go test ./... -count=1
go vet ./...
go test -race ./... -count=1
go build -o a2m ./cmd/a2m
python3 build.py
python3 e2e/smoke/smoke.py /absolute/path/to/a2m
python3 e2e/tiered/run_fake.py /absolute/path/to/a2m --sdk-python /path/to/venv/bin/python
```

The fake executable tests use temporary data and loopback peers, not saved user sessions or production services. A successful cross-build does not establish native Windows/macOS or real browser/database/MQ compatibility.

## Composition rules

Each service is built once by a `sync.Once` factory in `internal/app/compose.go` from explicit options. Cross-service references are closures resolved at call time (e.g. analysis -> MCP loaded packs, MCP -> analysis), so no factory re-enters another `Once` during construction. No package receives `*App`, an App getter bag, exposed locks or shared mutable state.
