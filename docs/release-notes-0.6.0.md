# Action2MCP 0.6.0

0.6.0 is a source-layout and version milestone. The running program behaves as 0.5.12 did. Release archives are built with `build.py`; this refactor does not add a database migration or change the runtime interfaces.

## Compatibility

- The version string is `0.6.0`. `a2m version` prints `Action2MCP 0.6.0`.
- The database user version stays 12. Startup does not run a new migration. Existing `data/` directories from 0.5.12 open as before.
- Data still lives in the `data` directory next to the executable. `A2M_DATA` still overrides that. The process working directory is not the data directory.
- CLI commands, flags, and exit behavior are unchanged: `serve` / `start`, `rec` / `record`, `stop`, `login` / `browser`, `status`, `export`, `import`, `mcp` / `stdio`, `quit` / `shutdown`, `version`, `help`.
- MCP methods, the stdio bridge, and the console HTTP API are unchanged.
- Install scripts are still `start.sh`, `start.command`, and `start.bat`. They run `./a2m` or `a2m.exe` beside themselves.

From a git checkout, build with:

```
go test ./...
go build -o a2m ./cmd/a2m
python3 build.py
```

`python3 build.py` runs `go test -count=1 ./...` and `go build ./cmd/a2m` for Windows amd64, macOS arm64, macOS amd64, and Linux amd64.

## What changed in the tree

- `cmd/a2m/main.go` is the only process entry. It calls `internal/app.Main`.
- Orchestration stays in `internal/app`. The CLI is `internal/app/cli.go` and its command functions are not exported.
- HTML classification, selector checks, and Markdown cleaning are `internal/htmlmd`.
- The Aho–Corasick secret scan is `internal/ahocorasick`.
- The read-only SQL guard is `internal/sqlguard`.
- Console files are embedded by `web.FS` (`app.js`, `index.html`, `style.css`).
- `internal/cdp` is unchanged.
- There are no Go files in the repository root.

Package boundaries and the pieces left in `internal/app` are described in [architecture.md](architecture.md).

## What this verification actually ran

Checked on this machine against loopback and `example.com` fixtures only. No browser, no company system, and no live Redis, MySQL, or message broker (the tiered runner uses a minimal fake RESP/PING peer).

| Check | Result |
|---|---|
| `go test ./... -count=1` | Pass. 273 top-level tests and 429 subtests (702 pass events), 0 failures. |
| `go vet ./...` | Pass, empty output. |
| `go test -race ./... -count=1` | Pass. No race reported. |
| `python3 build.py` | Pass. Four zips named `Action2MCP-0.6.0-*`. |
| Linux zip binary, cwd `/tmp` | `Action2MCP 0.6.0`. With `A2M_DATA` unset, `data_dir` is the `data` folder next to that binary. `GET /app.js` is the embedded file (126838 bytes). |
| `e2e/smoke/smoke.py` on that Linux binary | Pass. Fake `127.0.0.1` upstream only. |
| `node --test e2e/approvals/args_test.js` | Pass, 1 test. |
| `e2e/tiered/stdio_console.py` | Pass against a fresh fake fixture and `127.0.0.1:18999` echo server. |
| `e2e/tiered/raw_http.py` | Pass on the disposable fake fixture, including Redis PING, SSE, and session DELETE. |
| `e2e/tiered/sdk_client.py` | Pass using an isolated official Python MCP 1.x SDK over HTTP and stdio, including list-changed notifications. |
| `e2e/packs_ui/ui_e2e.js` | Not executed. It drives headless Chrome. `node --check` succeeded. |
| Seeded recording analysis | `TestSmokeSeededRecordingAnalysis` passed. The HTTP API cannot insert a captured request, so the test writes a fake `example.com` row through the store. |

`e2e/smoke/smoke.py` covered: `version`, `serve --no-open`, `status`, `quit`; console bytes for `/`, `app.js`, `index.html`, `style.css`; settings read/update and vault create/update/list/delete; tool, pack, and middleware create/update/list/delete; MCP `initialize`, `tools/list`, `load_pack`, and `tools/call`; a read call; a JSON `success: false` business error marked `isError`; HTML cleaned to Markdown with the script removed; approval deny with zero upstream hits; approval allow with one upstream hit; `load_pack` of 录制分析 and `rec_list_recordings` on an empty store.

`e2e/tiered/run_fake.py` supplies a fresh fixture with the optional recording-analysis pack disabled (the historical script expects two visible user packs), an echo HTTP peer, and a minimal RESP/PING peer. The historical raw HTTP assertions are unchanged. After these fixture prerequisites were supplied, raw HTTP, stdio, and official SDK HTTP/stdio all passed. This checks the Redis adapter's mock handshake/PING path and permission denials, not a real Redis installation.

Not covered here: recording in a real browser, CDP attach, SSO or form relogin against a live site, MySQL or OceanBase, Redis success paths, Kafka, RocketMQ, RabbitMQ, WebSocket terminal or SQL console against a live peer, macOS or Windows binaries (they were cross-compiled only), and any non-loopback host.
