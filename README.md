# Action2MCP

把网页上的业务操作录制下来，自动变成 AI 可调用的 MCP 工具。单个可执行文件，解压即用。

## 下载

最新版本：[Releases 页面](https://github.com/Juddy724/action2mcp/releases/latest)

| 平台 | 安装包 (v0.5.3) |
|---|---|
| macOS (Apple 芯片) | [Action2MCP-0.5.3-macOS-AppleSilicon.zip](https://github.com/Juddy724/action2mcp/releases/download/v0.5.3/Action2MCP-0.5.3-macOS-AppleSilicon.zip) |
| macOS (Intel) | [Action2MCP-0.5.3-macOS-Intel.zip](https://github.com/Juddy724/action2mcp/releases/download/v0.5.3/Action2MCP-0.5.3-macOS-Intel.zip) |
| Windows x64 | [Action2MCP-0.5.3-Windows-x64.zip](https://github.com/Juddy724/action2mcp/releases/download/v0.5.3/Action2MCP-0.5.3-Windows-x64.zip) |
| Linux x64 | [Action2MCP-0.5.3-Linux-x64.zip](https://github.com/Juddy724/action2mcp/releases/download/v0.5.3/Action2MCP-0.5.3-Linux-x64.zip) |

解压后运行 `start.command`（macOS）、`start.bat`（Windows）或 `start.sh`（Linux），然后打开 http://localhost:7788 。详细说明见安装包里的 README.md。

## 主要功能

- 一键开始/停止录制，自动识别业务请求并保存为 MCP 工具
- 录制分析：对 AI 说「帮我把录制记录里的『线上问题排查』识别一下并保存成工具」。AI 会先看录制全貌，给业务请求写清作用，再把完成流程所需的最少请求保存成工具；没说保存到哪个流程包时会先问你。可在「接入 AI / 设置」里关闭
- 流程包：按场景打包工具，AI 先看包列表、再按需加载包内工具。每个包可以写一份使用说明，加载后 AI 先按说明调用
- 登录中心：企业微信单点登录 / 表单登录自动续登，录制时自动识别企业微信扫码登录
- 配置管理：账号密码等加密保存，对 AI 不可见
- 中间件管理：MySQL/OceanBase、Redis、MQ、WebSocket，按操作开关权限
- MCP 接入：Streamable HTTP（http://localhost:7788/mcp）或 stdio（`a2m mcp`）
- 工具审批：在工具编辑页的「审批模式」选择不审批（off）或每次都审批（always）；写入工具默认每次都审批。AI 调用时，控制台会出现待审批卡片，可以通过、修改参数后通过或拒绝；等待超时可在「接入 AI / 设置」调整

### 工具审批的范围与限制

- 审批只约束通过 MCP 发起的 AI 调用；能直接访问 localhost HTTP 的客户端仍可伪造请求，审批不能代替本机访问权限管理。
- 请求已经发出后无法撤回。
- MCP 会话 DELETE 和 stdio 桥退出不保证取消待审批调用；这类调用会继续等待用户拒绝或超时。
- 大整数精度与现有 MCP JSON 的 float64 解码路径一致，超过其精确表示范围的整数可能丢失精度。

## 从源码构建

需要 Go 1.27+：

```
go test ./...
python3 build.py   # 生成 dist/ 下四个平台的 zip
```

你的数据（录制记录、工具、密钥）只保存在本地 `data/` 目录，不会进入仓库。
