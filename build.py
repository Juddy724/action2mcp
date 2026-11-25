#!/usr/bin/env python3
"""Cross-compile Action2MCP and produce portable zips in dist/."""
import os, re, shutil, subprocess, sys, zipfile, stat

ROOT = os.path.dirname(os.path.abspath(__file__))
PKG = os.path.join(ROOT, "packaging")
DIST = os.path.join(ROOT, "dist")
REPO = "Juddy724/action2mcp"
GITEE_REPO = "tricycle/action2mcp"

TARGETS = [
    ("windows", "amd64", "Windows-x64"),
    ("darwin", "arm64", "macOS-AppleSilicon"),
    ("darwin", "amd64", "macOS-Intel"),
    ("linux", "amd64", "Linux-x64"),
]

DOWNLOAD_ROWS = [
    ("macOS (Apple 芯片)", "macOS-AppleSilicon"),
    ("macOS (Intel)", "macOS-Intel"),
    ("Windows x64", "Windows-x64"),
    ("Linux x64", "Linux-x64"),
]

def read_version():
    app_go = open(os.path.join(ROOT, "internal", "app", "app.go"), encoding="utf-8").read()
    m = re.search(r'const\s+Version\s*=\s*"([^"]+)"', app_go)
    if not m:
        raise RuntimeError("failed to read Version from internal/app/app.go")
    return m.group(1)

VERSION = read_version()

def replace_marked_block(text, marker, body):
    start = f"<!-- {marker}:start -->"
    end = f"<!-- {marker}:end -->"
    pattern = re.compile(re.escape(start) + r".*?" + re.escape(end), re.S)
    if not pattern.search(text):
        raise RuntimeError(f"missing marker {start} ... {end}")
    return pattern.sub(f"{start}\n{body}\n{end}", text, count=1)

def sync_version_files(version=None):
    ver = version or read_version()
    readme_path = os.path.join(ROOT, "README.md")
    readme_text = open(readme_path, encoding="utf-8").read()
    ver_line = (
        f"> **最新版本：v{ver}** ｜ "
        f"[国内下载（Gitee Releases）](https://gitee.com/{GITEE_REPO}/releases) ｜ "
        f"[国际下载（GitHub Releases）](https://github.com/{REPO}/releases/latest)\n"
        "> 升级时保留原 `data/` 目录和 `secret.key`，即可无缝继承已有工具、流程包与配置；内置定时更新会自动按网络环境选择国内（Gitee）或国际（GitHub）源。"
    )
    table_lines = [
        f"| 平台 | 国内下载（Gitee · v{ver}） | 国际下载（GitHub · v{ver}） |",
        "|---|---|---|",
    ]
    for platform_label, asset_suffix in DOWNLOAD_ROWS:
        fname = f"Action2MCP-{ver}-{asset_suffix}.zip"
        gitee_url = f"https://gitee.com/{GITEE_REPO}/releases/download/v{ver}/{fname}"
        github_url = f"https://github.com/{REPO}/releases/download/v{ver}/{fname}"
        table_lines.append(f"| {platform_label} | [{fname}]({gitee_url}) | [{fname}]({github_url}) |")
    table_lines.append("")
    table_lines.append(
        f"> 也可直接访问 [Gitee Releases（国内）](https://gitee.com/{GITEE_REPO}/releases) 或 "
        f"[GitHub Releases（国际）](https://github.com/{REPO}/releases/latest) 查看完整更新日志并下载。"
    )

    updated = replace_marked_block(readme_text, "version-banner", ver_line)
    updated = replace_marked_block(updated, "download-table", "\n".join(table_lines))
    updated = re.sub(
        r'(https://img\.shields\.io/badge/release-v)[0-9]+\.[0-9]+\.[0-9]+',
        rf'\g<1>{ver}',
        updated,
    )
    if updated != readme_text:
        open(readme_path, "w", encoding="utf-8").write(updated)
        print(f"synced README.md -> v{ver}")

    index_path = os.path.join(ROOT, "web", "index.html")
    if os.path.exists(index_path):
        idx_text = open(index_path, encoding="utf-8").read()
        idx_updated = re.sub(r'(\b(?:style\.css|app\.js)\?v=)[^"]+', rf'\g<1>{ver}', idx_text)
        if idx_updated != idx_text:
            open(index_path, "w", encoding="utf-8").write(idx_updated)
            print(f"synced web/index.html -> v{ver}")

def readme(goos):
    t = open(os.path.join(PKG, "README.tmpl.md"), encoding="utf-8").read()
    if goos == "windows":
        rows = "| Windows | 双击 `start.bat`（或直接双击 `a2m.exe`） |"
        cli, ex, ext = "a2m", r"C:\\Tools\\Action2MCP\\a2m.exe", r"C:\\Tools\\Action2MCP\\a2m.exe"
        note = ("- Windows 首次运行时，如果出现「Windows 已保护你的电脑」，点「更多信息」→「仍要运行」。\n"
                "- 命令行用法：在程序文件夹的地址栏输入 `cmd` 并回车，然后执行 `a2m rec ...`。")
        ex_toml = r"C:\\Tools\\Action2MCP\\a2m.exe"
    elif goos == "darwin":
        rows = "| macOS | 双击 `start.command`。第一次如果提示“无法验证开发者”：**右键 → 打开**，再点「打开」 |"
        cli, ex = "./a2m", "/Users/你的用户名/Action2MCP/a2m"
        note = ("- macOS 第一次运行需要 **右键 → 打开**。`start.command` 会自动解除隔离标记。如果仍然被拦截，在终端执行：\n"
                "  `xattr -dr com.apple.quarantine 解压目录`\n"
                "- 请选择与芯片对应的版本：M1/M2/M3/M4 选 AppleSilicon，老款 Intel Mac 选 Intel。")
        ex_toml = ex
    else:
        rows = "| Linux | 终端执行 `./start.sh`（或 `./a2m`） |"
        cli, ex = "./a2m", "/home/你的用户名/Action2MCP/a2m"
        note = "- Linux 需要图形桌面才能显示录制浏览器。以 root 身份运行 Chrome 时，请在 `data/config.json` 里设置 `\"no_sandbox\": true`。"
        ex_toml = ex
    return (t.replace("{{START_ROWS}}", rows).replace("{{CLI}}", cli)
             .replace("{{EXAMPLE_PATH_TOML}}", ex_toml.replace("\\\\", "\\\\"))
             .replace("{{EXAMPLE_PATH}}", ex).replace("{{OS_NOTE}}", note))

def add(z, path, arc, exe=False):
    info = zipfile.ZipInfo(arc, date_time=(2026, 11, 2, 0, 0, 0))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.create_system = 3
    info.external_attr = ((0o755 if exe else 0o644) | stat.S_IFREG) << 16
    with open(path, "rb") as f:
        z.writestr(info, f.read())

def main():
    if "--sync-version" in sys.argv[1:]:
        sync_version_files()
        return
    sync_version_files()
    shutil.rmtree(DIST, ignore_errors=True)
    os.makedirs(DIST)
    subprocess.check_call(["go", "test", "-count=1", "./..."], cwd=ROOT)
    for goos, arch, label in TARGETS:
        binname = "a2m.exe" if goos == "windows" else "a2m"
        out = os.path.join(DIST, f"build-{goos}-{arch}", binname)
        env = dict(os.environ, CGO_ENABLED="0", GOOS=goos, GOARCH=arch)
        subprocess.check_call(["go", "build", "-trimpath", "-ldflags", "-s -w", "-o", out, "./cmd/a2m"], cwd=ROOT, env=env)
        folder = f"Action2MCP-{VERSION}-{label}"
        zpath = os.path.join(DIST, folder + ".zip")
        rd = os.path.join(DIST, f"build-{goos}-{arch}", "README.md")
        open(rd, "w", encoding="utf-8").write(readme(goos))
        with zipfile.ZipFile(zpath, "w") as z:
            add(z, out, f"{folder}/{binname}", exe=True)
            add(z, rd, f"{folder}/README.md")
            if goos == "windows":
                add(z, os.path.join(PKG, "start.bat"), f"{folder}/start.bat")
            else:
                add(z, os.path.join(PKG, "start.sh"), f"{folder}/start.sh", exe=True)
                if goos == "darwin":
                    add(z, os.path.join(PKG, "start.command"), f"{folder}/start.command", exe=True)
        shutil.rmtree(os.path.join(DIST, f"build-{goos}-{arch}"))
        print(zpath, os.path.getsize(zpath) // 1024, "KB")

if __name__ == "__main__":
    main()
