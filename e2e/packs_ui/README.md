# Pack membership UI e2e (0.4.1)

Headless Chrome (puppeteer-core) drives the 流程包 page: open「+ 添加工具」, search, check 2 tools, 确定,
verify chips; click × to remove; same for middleware. A raw MCP session (with GET SSE stream) checks
`notifications/tools/list_changed`, tools/list, list_packs, load_pack and flat mode after each change.

    npm i puppeteer-core   # in some dir D
    NODE_PATH=D/node_modules node ui_e2e.js http://localhost:PORT ../screens

Expects a pack named 工时 containing only log_hours, plus tools submit_daily / list_tasks not in it,
and at least one middleware. Screenshots: ../screens/packs-{1-before,2-modal,3-after-add,4-after-remove,5-middleware}.png
