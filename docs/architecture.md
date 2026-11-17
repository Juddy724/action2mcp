# Architecture

Action2MCP 0.6.0 keeps the same executable behavior as 0.5.12 and splits the source tree. The database user version stays 12. Flags, stdio, and the MCP methods are unchanged.

## Packages

| Path | Role |
|---|---|
| `cmd/a2m` | Process entry. `main` calls `app.Main` and nothing else. |
| `internal/app` | Console, CLI, store, vault, MCP, approvals, recording, browser session, and middleware execution. The CLI stays in `cli.go`; command functions are not exported. |
| `internal/htmlmd` | Classify a tool body as JSON, HTML, or other; validate a small CSS selector; clean HTML to Markdown; count visible Markdown characters. No `App` or store types. |
| `internal/ahocorasick` | Byte-wise multi-pattern matcher. `New` / `Find` return `Span` ranges. No secret policy lives here. |
| `internal/sqlguard` | Parse one statement with the TiDB parser and reject anything that is not a single read-only `SELECT` with an explicit `LIMIT`. `MaxRowsCap` is 200. It does not open a connection. |
| `internal/cdp` | Chrome DevTools Protocol client. Unchanged. |
| `web` | Embeds `app.js`, `index.html`, and `style.css` as `web.FS`. Paths are package-relative. `internal/app` serves that `fs.FS`. |

`go build -o a2m ./cmd/a2m` from the module root produces the same kind of single binary as before. `python3 build.py` tests `./...` and builds `./cmd/a2m` for the four release targets.

## Data directory

`resolveDataDir` in `internal/app` is unchanged: `A2M_DATA` wins, otherwise the directory of `os.Executable` plus `data`. The working directory is not the data directory. Static files come from the embed, so the process can be started from any directory.

## What stayed in `internal/app`

These pieces call each other through `App`, `Store`, `Tool`, and the vault. Splitting them would export that whole graph or add pass-through wrappers.

- CLI, HTTP server, and MCP session state.
- Approval cards, secret scrubbing policy, and the decode-view walk. The walk calls `ahocorasick` and keeps its own span type for decoded views.
- Result presentation. It calls `htmlmd` and then applies failure detection, truncation, and the write-operation prefix.
- Direct MySQL / Redis / MQ middleware, including `classifySQL` in `mw_sql.go`. That classifier is the permission plan for a live connection, not the read-only guard.
- WebSocket SQL console execution and `EXPLAIN`. They call `sqlguard.Check` and then dial.
- Browser launch, cookie jar, relogin, and recording capture.
- The row cap is `sqlguard.MaxRowsCap`. `internal/app` keeps the name `sqlGuardMaxRowsCap` as that constant so config validation did not need a second copy of `200`.

## Dependency direction

`cmd/a2m` → `internal/app` → `web`, `htmlmd`, `ahocorasick`, `sqlguard`, `cdp`.

The extracted packages do not import `internal/app` or each other. `web` does not import application code.
