# 0.4.0 tiered discovery E2E

Fixture: upstream.py (echo server on :18999), a DB created by 0.3.0 with tools
echo_order (uses {{secret.svc_pw}}), log_hours, secret_tool, Redis middleware 「缓存」 (read-only),
packs 订单查询(echo_order+缓存) / 工时(log_hours) / 机密包(disabled, secret_tool); then copied and opened by 0.4.0.

    python3 raw_http.py 17802                       # raw Streamable HTTP incl. GET SSE stream
    python sdk_client.py 17802 ./a2m ./data         # official Python MCP SDK (1.x and 2.x), HTTP + stdio
    python3 stdio_console.py 17802 ./a2m ./data     # stdio bridge + console-driven list_changed + mode switch
