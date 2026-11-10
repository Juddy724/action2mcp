# Action2MCP

把网页上的业务操作录制下来，自动变成 AI 可调用的 MCP 工具。单个可执行文件，解压即用。

## 下载

最新版本：[Releases 页面](https://github.com/Juddy724/action2mcp/releases/latest)

| 平台 | 安装包 (v0.4.4) |
|---|---|
| macOS (Apple 芯片) | [Action2MCP-0.4.4-macOS-AppleSilicon.zip](https://github.com/Juddy724/action2mcp/releases/download/v0.4.4/Action2MCP-0.4.4-macOS-AppleSilicon.zip) |
| macOS (Intel) | [Action2MCP-0.4.4-macOS-Intel.zip](https://github.com/Juddy724/action2mcp/releases/download/v0.4.4/Action2MCP-0.4.4-macOS-Intel.zip) |
| Windows x64 | [Action2MCP-0.4.4-Windows-x64.zip](https://github.com/Juddy724/action2mcp/releases/download/v0.4.4/Action2MCP-0.4.4-Windows-x64.zip) |
| Linux x64 | [Action2MCP-0.4.4-Linux-x64.zip](https://github.com/Juddy724/action2mcp/releases/download/v0.4.4/Action2MCP-0.4.4-Linux-x64.zip) |

解压后运行 `start.command`（macOS）、`start.bat`（Windows）或 `start.sh`（Linux），然后打开 http://localhost:7788 。详细说明见安装包里的 README.md。

## 主要功能

- 一键开始/停止录制，自动识别业务请求并保存为 MCP 工具
- 流程包：按场景打包工具，AI 先看包列表、再按需加载包内工具。每个包可以写一份使用说明，加载后 AI 先按说明调用
- 登录中心：企业微信单点登录 / 表单登录自动续登，录制时自动识别企业微信扫码登录
- 配置管理：账号密码等加密保存，对 AI 不可见
- 中间件管理：MySQL/OceanBase、Redis、MQ、WebSocket，按操作开关权限
- MCP 接入：Streamable HTTP（http://localhost:7788/mcp）或 stdio（`a2m mcp`）

## 从源码构建

需要 Go 1.27+：

```
go test ./...
python3 build.py   # 生成 dist/ 下四个平台的 zip
```

你的数据（录制记录、工具、密钥）只保存在本地 `data/` 目录，不会进入仓库。
