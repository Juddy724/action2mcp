# 0.4.0 tiered discovery E2E

Build the binary from the repository root with `go build -o a2m ./cmd/a2m`. The scripts below take that binary path; they do not compile `package main` at the root.

Fixture: upstream.py (echo server on :18999), a DB created by 0.3.0 with tools
echo_order (uses {{secret.svc_pw}}), log_hours, secret_tool, Redis middleware 「缓存」 (read-only),
packs 订单查询(echo_order+缓存) / 工时(log_hours) / 机密包(disabled, secret_tool); then copied and opened by 0.4.0.

    python3 raw_http.py 17802                       # raw Streamable HTTP incl. GET SSE stream
    python sdk_client.py 17802 ./a2m ./data         # official Python MCP SDK (1.x and 2.x), HTTP + stdio
    python3 stdio_console.py 17802 ./a2m ./data     # stdio bridge + console-driven list_changed + mode switch


## Disposable fake regression (0.6.0)

```
go build -o /tmp/a2m ./cmd/a2m
python3 e2e/tiered/run_fake.py /tmp/a2m
# Optional: official Python MCP SDK, installed in a separate virtualenv
python3 e2e/tiered/run_fake.py /tmp/a2m --sdk-python /path/to/venv/bin/python
```

This runner uses random loopback ports, a fresh temporary `A2M_DATA`, an echo
HTTP peer, and a minimal RESP handshake/PING peer (not a real Redis deployment).
It runs the unchanged historical raw HTTP assertions and the stdio console
client, plus the SDK client when supplied. The fixture disables the optional
recording-analysis pack to match the historical two-visible-pack expectation.
No user data, browser, or external host is used; child processes and temporary
data are cleaned up. `prepare_fake_fixture.py BASE [UPSTREAM [REDIS_PORT]]`
can seed the same fixture manually; BASE and UPSTREAM must be loopback URLs.
