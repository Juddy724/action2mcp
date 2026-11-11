# Action2MCP

把网页上的业务操作录制下来，自动变成 AI 可调用的 MCP 工具。单个可执行文件，解压即用。

## 下载

最新版本：[Releases 页面](https://github.com/Juddy724/action2mcp/releases/latest)

| 平台 | 安装包 (v0.5.7) |
|---|---|
| macOS (Apple 芯片) | [Action2MCP-0.5.7-macOS-AppleSilicon.zip](https://github.com/Juddy724/action2mcp/releases/download/v0.5.7/Action2MCP-0.5.7-macOS-AppleSilicon.zip) |
| macOS (Intel) | [Action2MCP-0.5.7-macOS-Intel.zip](https://github.com/Juddy724/action2mcp/releases/download/v0.5.7/Action2MCP-0.5.7-macOS-Intel.zip) |
| Windows x64 | [Action2MCP-0.5.7-Windows-x64.zip](https://github.com/Juddy724/action2mcp/releases/download/v0.5.7/Action2MCP-0.5.7-Windows-x64.zip) |
| Linux x64 | [Action2MCP-0.5.7-Linux-x64.zip](https://github.com/Juddy724/action2mcp/releases/download/v0.5.7/Action2MCP-0.5.7-Linux-x64.zip) |

解压后运行 `start.command`（macOS）、`start.bat`（Windows）或 `start.sh`（Linux），然后打开 http://localhost:7788 。详细说明见安装包里的 README.md。

## 主要功能

- 一键开始/停止录制，自动识别业务请求并保存为 MCP 工具
- 录制分析：对 AI 说「帮我把录制记录里的『线上问题排查』识别一下并保存成工具」。AI 会先看录制全貌，给业务请求写清作用，再把完成流程所需的最少请求保存成工具；没说保存到哪个流程包时会先问你。可在「接入 AI / 设置」里关闭
- 流程包：按场景打包工具，AI 先看包列表、再按需加载包内工具。每个包可以写一份使用说明，加载后 AI 先按说明调用
- 登录中心：企业微信单点登录 / 表单登录自动续登，录制时自动识别企业微信扫码登录
- 配置管理：账号密码等加密保存，对 AI 不可见
- 中间件管理：MySQL/OceanBase、Redis、MQ、WebSocket（终端或 SQL 控制台），按操作开关权限
- MCP 接入：Streamable HTTP（http://localhost:7788/mcp）或 stdio（`a2m mcp`）
- 工具审批：在工具编辑页的「审批模式」选择不审批（off）或每次都审批（always）；写入工具默认每次都审批。WebSocket SQL 控制台每次执行都要审批。AI 调用时，控制台会出现待审批卡片，可以通过、修改参数后通过或拒绝；等待超时可在「接入 AI / 设置」调整
- WebSocket SQL 控制台：在「中间件管理」里把数据平台的 SQL 查询登记为中间件，AI 通过 `ws_sql_query` 按数据源别名查询；只读 SELECT、显式 LIMIT、EXPLAIN 预检、200 行封顶，令牌从本机收获的请求头注入。一个库由数据源 ID、envId、envType 三个值确定（0.5.7）

### 工具审批的范围与限制

- 审批只约束通过 MCP 发起的 AI 调用；能直接访问 localhost HTTP 的客户端仍可伪造请求，审批不能代替本机访问权限管理。
- 请求已经发出后无法撤回。
- MCP 会话 DELETE 和 stdio 桥退出不保证取消待审批调用；这类调用会继续等待用户拒绝或超时。
- 大整数精度与现有 MCP JSON 的 float64 解码路径一致，超过其精确表示范围的整数可能丢失精度。
- 参数按整体替换，未提交的参数保留原值；非秘密参数原样展示、原样替换，不解析或重写内部 JSON/form。秘密参数整体遮罩；未改动的 ****** 保留原值，输入完整新值则替换整个参数；提交值内部夹带 ****** 则 400，未执行。


### WebSocket SQL 控制台（0.5.5，数据源三元组见 0.5.7）

数据平台这类「一条 WebSocket 消息执行 SQL」的能力，放在「中间件管理」里，和 Phoenix 终端一样是 WebSocket 中间件，只是模式选「SQL 控制台」。加入已开启的流程包后，AI 会看到通用工具 `ws_sql_query`（参数是中间件名、数据源别名、SQL），与直接连库的 `db_query` 不是同一个工具。

升级到 0.5.5 时，若本地还有 0.5.4 那样带 SQL 护栏的 `WS` 工具，启动时会自动转成 SQL 控制台中间件（例如 `demo_sql_query` 会变成中间件 `demo_sql`），并把它从所属流程包里改挂到新中间件上，原工具删除。迁移是事务性的、可重复执行。也可在「工具」页对尚未迁移的护栏工具点「转为 SQL 控制台」。

- 每次执行都要在控制台审批，不能关掉。审批预览只显示中间件名、数据源别名和即将执行的 SQL，不会出现数据源 ID、环境参数或登录令牌；批准前不会向目标发送业务消息。
- 只允许单条只读 SELECT（含 WITH），必须带显式 `LIMIT`（最多 200 行）。执行前会另开连接做 `EXPLAIN` 索引预检；预检失败或护栏拒绝时不会发送业务 SQL。结果若超过上限会截断并注明。
- 登录令牌不要写进配置。调用时从本机已收获的自定义请求头注入，例如 `{{header.sso-epctoken}}`（不会误用同名 Cookie）。若尚未收获到令牌，测试连接和调用都会失败，不会发出 SQL。「测试连接」只做握手，不会执行任何用户 SQL。
- `EXPLAIN` 只是执行前预检，不保证第二次连接的实际计划与预检完全一致，也不提供远端只读事务。

**配置数据源：** 在中间件表单里按行填写「名称」「数据源 ID」「envId」「envType」「说明（给 AI 看）」，可添加 / 删除。名称是 AI 使用的别名；说明会出现在 `ws_sql_query` 的工具描述里，方便 AI 根据用户的问题自己选库。一个库由「数据源 ID + envId + envType」三个值一起确定。envType 默认为 PROD，也可以改成其他值。这些标识以及 spaceCode、dbType 只保存在本机，不会出现在工具说明、审批预览或审计里。spaceCode 和 dbType 在中间件级填写默认值；某一行需要不同值时，再点该行「高级」覆盖。

要添加或核对这些值：在数据平台的 SQL 控制台对该库执行一次查询并录制，然后从录到的 `execute` 消息里复制 `dsId`、`envId`、`envType`。同一个站点上有多套库时，再点「添加」补一行即可。保存后，已连接的 AI 客户端会收到工具列表变更通知，`tools/list` 立即反映当前的别名和说明。

升级到 0.5.7 时，若本地还有 0.5.5 / 0.5.6 把 envId / envType 写在中间件默认环境参数里的配置，启动时会把这两个值拷到每一行数据源上，并去掉旧的默认字段；迁移是事务性的、可重复执行。


### 登录中心（0.5.6）

- 从 WebSocket 中间件（终端或 SQL 控制台）自动创建登录配置时，网站地址使用对应的 http(s) 源（`wss://` → `https://`，`ws://` → `http://`），不再把 `wss://` 填进登录中心。登录入口、登录页和检测地址必须是 `http://` 或 `https://`。
- 「测试重新登录 / 打开浏览器登录」时，如果浏览器里已经处于登录状态，会马上判定成功并关闭窗口；若还缺 `sso-epctoken` 这类必要请求头，会刷新或再次打开该网站以捕获请求头，全部收获后才算成功。
- 等待登录最多 5 分钟，超时会结束并显示失败原因；等待过程中可以点「取消」，关闭弹出的窗口也会结束等待，状态不会一直停在「等待登录」。

## 从源码构建

需要 Go 1.27+：

```
go test ./...
python3 build.py   # 生成 dist/ 下四个平台的 zip
```

你的数据（录制记录、工具、密钥）只保存在本地 `data/` 目录，不会进入仓库。
