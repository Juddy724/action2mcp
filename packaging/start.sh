#!/bin/sh
# Action2MCP 启动脚本（Linux / macOS 终端）
cd "$(dirname "$0")" || exit 1
chmod +x ./a2m 2>/dev/null
echo "正在启动 Action2MCP，浏览器会自动打开控制台 http://localhost:7788"
echo "按 Ctrl+C 或关闭此终端即可停止服务。"
exec ./a2m
