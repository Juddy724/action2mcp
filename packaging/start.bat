@echo off
chcp 65001 >nul
cd /d "%~dp0"
title Action2MCP
echo 正在启动 Action2MCP，浏览器会自动打开控制台 http://localhost:7788
echo 关闭这个窗口即可停止服务。
echo.
a2m.exe
