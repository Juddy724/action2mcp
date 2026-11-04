#!/bin/sh
# Action2MCP 启动脚本（macOS 双击运行）
cd "$(dirname "$0")" || exit 1
# 解除 macOS 对下载文件的隔离标记，否则未签名程序会被拦截
xattr -dr com.apple.quarantine . 2>/dev/null
chmod +x ./a2m 2>/dev/null
echo "正在启动 Action2MCP，浏览器会自动打开控制台 http://localhost:7788"
echo "关闭此窗口即可停止服务。"
./a2m
