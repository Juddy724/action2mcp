#!/usr/bin/env python3
"""Isolated Action2MCP smoke against a fake loopback upstream.

Usage (from anywhere):
    python3 e2e/smoke/smoke.py /path/to/a2m

A2M_DATA is a new temporary directory, not the repo data/ folder.
The binary is started with cwd /tmp. No browser, and no host other than
127.0.0.1. Recording rows cannot be inserted through the HTTP API; seeded
analysis is TestSmokeSeededRecordingAnalysis in internal/app.
"""
import json, os, socket, subprocess, sys, tempfile, threading, time, urllib.error, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

EXE = sys.argv[1] if len(sys.argv) > 1 else ""
if not EXE or not os.path.isfile(EXE):
    print("usage: smoke.py /path/to/a2m", file=sys.stderr)
    sys.exit(2)
EXE = os.path.abspath(EXE)
FAILS = []

def ok(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond:
        FAILS.append(msg)

def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port

class Hits:
    def __init__(self):
        self.lock = threading.Lock()
        self.n = {}
    def add(self, path):
        with self.lock:
            self.n[path] = self.n.get(path, 0) + 1
            return self.n[path]
    def get(self, path):
        with self.lock:
            return self.n.get(path, 0)

HITS = Hits()

class Upstream(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype):
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    def do_GET(self):
        HITS.add(self.path)
        if self.path.startswith("/page"):
            self._send(200, "<!doctype html><html><body><h1>示例标题</h1><p>示例正文</p><script>alert(1)</script></body></html>", "text/html; charset=utf-8")
            return
        if self.path.startswith("/fail"):
            self._send(200, json.dumps({"success": False, "message": "示例业务失败"}), "application/json")
            return
        self._send(200, json.dumps({"ok": True, "item": "demo-row", "path": self.path}), "application/json")
    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n).decode() if n else ""
        HITS.add(self.path)
        if self.path.startswith("/fail"):
            self._send(200, json.dumps({"success": False, "message": "示例业务失败", "echo": body}), "application/json")
            return
        self._send(200, json.dumps({"ok": True, "path": self.path, "body": body}), "application/json")
    def log_message(self, *a):
        pass

def serve_upstream(port):
    httpd = ThreadingHTTPServer(("127.0.0.1", port), Upstream)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd

def api(base, method, path, body=None, origin=None, timeout=30):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if origin:
        req.add_header("Origin", origin)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = raw.decode(errors="replace")
        return e.code, parsed

def mcp(base, sid_box, method, params=None, note=False, timeout=30):
    msg = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        msg["params"] = params
    if not note:
        sid_box["n"] += 1
        msg["id"] = sid_box["n"]
    req = urllib.request.Request(base + "/mcp", data=json.dumps(msg).encode(), method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("Accept", "application/json")
    if sid_box.get("sid"):
        req.add_header("Mcp-Session-Id", sid_box["sid"])
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        sid = resp.headers.get("Mcp-Session-Id")
        if sid:
            sid_box["sid"] = sid
        raw = resp.read()
        if note:
            return resp.status, None
        return resp.status, json.loads(raw)

def tool_text(result):
    res = result["result"]
    return res["content"][0]["text"], bool(res.get("isError"))

def wait_pending(base, origin, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        code, rows = api(base, "POST", "/api/approvals/list", {"status": "pending", "limit": 10}, origin=origin)
        if code == 200 and rows:
            return rows[0]
        time.sleep(0.05)
    return None

def main():
    up_port = free_port()
    app_port = free_port()
    upstream = serve_upstream(up_port)
    data = tempfile.mkdtemp(prefix="a2m-smoke-")
    log_path = os.path.join(data, "serve.log")
    logf = open(log_path, "w")
    env = os.environ.copy()
    env["A2M_DATA"] = data
    env["A2M_PORT"] = str(app_port)
    env.pop("A2M_OPEN", None)
    print("data", data)
    print("upstream", up_port, "app", app_port)
    ver = subprocess.run([EXE, "version"], cwd="/tmp", env=env, capture_output=True, text=True)
    ok(ver.returncode == 0 and ver.stdout.strip() == "Action2MCP 0.6.1", "version from /tmp: " + ver.stdout.strip() + ver.stderr.strip())
    proc = subprocess.Popen([EXE, "serve", "--no-open"], cwd="/tmp", env=env, stdout=logf, stderr=subprocess.STDOUT)
    base = f"http://127.0.0.1:{app_port}"
    origin = base
    try:
        status = None
        for _ in range(50):
            try:
                code, status = api(base, "GET", "/api/status")
                if code == 200:
                    break
            except Exception:
                time.sleep(0.1)
        else:
            print(open(log_path).read()[-2000:])
            ok(False, "server did not become ready")
            raise RuntimeError("server did not become ready")
        ok(status.get("version") == "0.6.1", "status version " + str(status.get("version")))
        ok(os.path.realpath(status.get("data_dir", "")) == os.path.realpath(data), "A2M_DATA honored: " + str(status.get("data_dir")))
        st = subprocess.run([EXE, "status"], cwd="/tmp", env=env, capture_output=True, text=True)
        ok(st.returncode == 0 and "服务运行中" in st.stdout, "cli status: " + st.stdout.strip())

        repo = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
        for name in ("index.html", "app.js", "style.css"):
            with urllib.request.urlopen(base + "/" + name, timeout=10) as resp:
                got = resp.read()
            disk = open(os.path.join(repo, "web", name), "rb").read()
            ok(got == disk, f"asset {name} bytes match embed ({len(got)})")
        with urllib.request.urlopen(base + "/", timeout=10) as resp:
            root = resp.read()
        ok(root == open(os.path.join(repo, "web", "index.html"), "rb").read(), "GET / serves index.html")

        code, settings = api(base, "GET", "/api/settings")
        ok(code == 200 and settings.get("mcp_mode") == "tiered", "settings default tiered")
        code, settings = api(base, "PUT", "/api/settings", {"approval_timeout_secs": 60, "rec_analysis": True})
        ok(code == 200 and settings.get("approval_timeout_secs") == 60 and settings.get("rec_analysis") is True, "settings update")
        code, vault = api(base, "POST", "/api/vault", {"name": "smoke_note", "type": "plain", "value": "example-note", "note": "smoke"})
        ok(code == 200 and vault.get("name") == "smoke_note", "vault create " + str(vault)[:160])
        vid = vault.get("id")
        code, vault = api(base, "PUT", f"/api/vault/{vid}", {"name": "smoke_note", "type": "plain", "value": "example-note-2", "note": "updated"})
        ok(code == 200, "vault update " + str(code))
        code, listed = api(base, "GET", "/api/vault")
        names = [it["name"] for it in listed.get("items", [])] if isinstance(listed, dict) else []
        ok(code == 200 and "smoke_note" in names, "vault list")
        code, _ = api(base, "DELETE", f"/api/vault/{vid}")
        ok(code == 200, "vault delete")

        up = f"http://127.0.0.1:{up_port}"
        def tool(name, method, path, approval, body=""):
            spec = {"name": name, "title": name, "method": method, "url": up + path, "approval": approval,
                    "description": "smoke " + name, "headers": {}, "params": [], "body": body}
            code, got = api(base, "POST", "/api/tools", spec)
            ok(code == 200 and got.get("id"), f"create tool {name}: {code} {str(got)[:180]}")
            return got
        read = tool("smoke_read", "GET", "/read", "off")
        biz = tool("smoke_biz", "GET", "/fail", "off")
        page = tool("smoke_page", "GET", "/page", "off")
        deny = tool("smoke_deny", "POST", "/write-deny", "always", '{"op":"deny"}')
        allow = tool("smoke_allow", "POST", "/write-allow", "always", '{"op":"allow"}')
        code, read2 = api(base, "PUT", f"/api/tools/{read['id']}", {"name": "smoke_read", "title": "读取示例", "method": "GET", "url": up + "/read", "approval": "off", "description": "smoke read", "headers": {}, "params": []})
        ok(code == 200 and read2.get("title") == "读取示例", "tool update")
        code, tools = api(base, "GET", "/api/tools")
        ok(code == 200 and any(t.get("name") == "smoke_read" for t in tools), "tool list")

        code, pack = api(base, "POST", "/api/packs", {"name": "示例包", "description": "smoke", "enabled": True, "scenarios": "演示", "guide": "先读再写"})
        ok(code == 200 and pack.get("id"), "pack create")
        pid = pack["id"]
        code, pack = api(base, "PUT", f"/api/packs/{pid}", {"name": "示例包", "description": "smoke-updated", "enabled": True, "scenarios": "演示", "guide": "先读再写"})
        ok(code == 200 and pack.get("description") == "smoke-updated", "pack update")
        ids = [read["id"], biz["id"], page["id"], deny["id"], allow["id"]]
        code, added = api(base, "POST", f"/api/packs/{pid}/tools", {"ids": ids})
        ok(code == 200 and added.get("added") == len(ids), "pack add tools " + str(added))

        code, mw = api(base, "POST", "/api/middleware", {"name": "示例缓存", "type": "redis", "config": {"host": "127.0.0.1", "port": 1, "redis_mode": "standalone", "perms": {"read": True, "write": False, "delete": False, "script": False}}})
        ok(code == 200 and mw.get("id"), "middleware create " + str(mw)[:200])
        mid = mw.get("id")
        code, mw = api(base, "PUT", f"/api/middleware/{mid}", {"name": "示例缓存", "type": "redis", "config": {"host": "127.0.0.1", "port": 1, "redis_mode": "standalone", "description": "loopback-only", "perms": {"read": True, "write": False, "delete": False, "script": False}}})
        ok(code == 200, "middleware update " + str(code) + " " + str(mw)[:160])
        code, mws = api(base, "GET", "/api/middleware")
        ok(code == 200 and any(it.get("name") == "示例缓存" for it in mws.get("items", [])), "middleware list")
        code, _ = api(base, "DELETE", f"/api/middleware/{mid}")
        ok(code == 200, "middleware delete")

        box = {"n": 0, "sid": ""}
        code, init = mcp(base, box, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "smoke", "version": "0"}})
        ok(code == 200 and init["result"]["serverInfo"]["version"] == "0.6.1" and box.get("sid"), "mcp initialize")
        mcp(base, box, "notifications/initialized", note=True)
        _, listed = mcp(base, box, "tools/list", {})
        names = [t["name"] for t in listed["result"]["tools"]]
        ok(names == ["list_packs", "load_pack", "unload_pack", "call_pack_tool"], "entry tools " + str(names))
        _, loaded = mcp(base, box, "tools/call", {"name": "load_pack", "arguments": {"pack": "示例包"}})
        text, is_err = tool_text(loaded)
        ok(not is_err and "smoke_read" in text and "smoke_page" in text, "load_pack")
        _, listed = mcp(base, box, "tools/list", {})
        names = [t["name"] for t in listed["result"]["tools"]]
        ok("smoke_read" in names and "smoke_biz" in names and "smoke_page" in names, "tools after load " + str(names))

        _, called = mcp(base, box, "tools/call", {"name": "smoke_read", "arguments": {}})
        text, is_err = tool_text(called)
        ok(not is_err and "demo-row" in text and HITS.get("/read") == 1, "read call " + text[:120])
        _, called = mcp(base, box, "tools/call", {"name": "smoke_biz", "arguments": {}})
        text, is_err = tool_text(called)
        ok(is_err and "业务失败" in text and "示例业务失败" in text, "business error " + text[:160])
        _, called = mcp(base, box, "tools/call", {"name": "smoke_page", "arguments": {}})
        text, is_err = tool_text(called)
        ok((not is_err) and "示例标题" in text and "示例正文" in text and "alert(1)" not in text and "<script" not in text.lower(), "html to markdown " + text[:200])

        denied = {}
        def call_deny():
            try:
                _, res = mcp(base, box, "tools/call", {"name": "smoke_deny", "arguments": {}}, timeout=20)
                denied["res"] = res
            except Exception as e:
                denied["err"] = str(e)
        threading.Thread(target=call_deny, daemon=True).start()
        pending = wait_pending(base, origin)
        ok(pending is not None and pending.get("nonce"), "deny card appeared")
        if pending:
            code, _ = api(base, "POST", f"/api/approvals/{pending['id']}/decide", {"action": "reject", "nonce": pending["nonce"], "feedback": "smoke 拒绝"}, origin=origin)
            ok(code == 200, "deny decide " + str(code))
        for _ in range(50):
            if "res" in denied or "err" in denied:
                break
            time.sleep(0.05)
        text, is_err = ("", True)
        if "res" in denied:
            text, is_err = tool_text(denied["res"])
        ok(is_err and "未批准" in text and HITS.get("/write-deny") == 0, "deny did not hit upstream: hits=%s text=%s err=%s" % (HITS.get("/write-deny"), text[:160], denied.get("err")))

        allowed = {}
        def call_allow():
            try:
                _, res = mcp(base, box, "tools/call", {"name": "smoke_allow", "arguments": {}}, timeout=20)
                allowed["res"] = res
            except Exception as e:
                allowed["err"] = str(e)
        threading.Thread(target=call_allow, daemon=True).start()
        pending = wait_pending(base, origin)
        ok(pending is not None, "allow card appeared")
        if pending:
            code, _ = api(base, "POST", f"/api/approvals/{pending['id']}/decide", {"action": "approve", "nonce": pending["nonce"], "preview_hash": pending["preview_hash"]}, origin=origin)
            ok(code == 200, "allow decide " + str(code))
        for _ in range(50):
            if "res" in allowed or "err" in allowed:
                break
            time.sleep(0.05)
        text, is_err = ("", True)
        if "res" in allowed:
            text, is_err = tool_text(allowed["res"])
        ok((not is_err) and HITS.get("/write-allow") == 1 and "allow" in text, "allow hit upstream once: hits=%s text=%s err=%s" % (HITS.get("/write-allow"), text[:160], allowed.get("err")))

        _, loaded = mcp(base, box, "tools/call", {"name": "load_pack", "arguments": {"pack": "录制分析"}})
        text, is_err = tool_text(loaded)
        ok(not is_err and "rec_list_recordings" in text, "load recording-analysis pack")
        _, called = mcp(base, box, "tools/call", {"name": "rec_list_recordings", "arguments": {}})
        text, is_err = tool_text(called)
        ok(not is_err and "recordings" in text and "example.com" not in text, "empty recording list via MCP (no API seed): " + text[:160])

        spare = tool("smoke_spare", "GET", "/spare", "off")
        code, _ = api(base, "DELETE", f"/api/tools/{spare['id']}")
        ok(code == 200, "tool delete")
        code, packs = api(base, "GET", "/api/packs")
        ok(code == 200 and any(p.get("name") == "示例包" for p in packs), "pack list")
        code, _ = api(base, "DELETE", f"/api/packs/{pid}")
        ok(code == 200, "pack delete")
        code, packs = api(base, "GET", "/api/packs")
        ok(code == 200 and not any(p.get("name") == "示例包" for p in packs), "pack absent after delete")
    finally:
        q = subprocess.run([EXE, "quit"], cwd="/tmp", env=env, capture_output=True, text=True, timeout=20)
        ok(q.returncode == 0 and "已关闭" in q.stdout, "cli quit: " + q.stdout.strip() + q.stderr.strip())
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            ok(False, "serve did not exit after quit")
        st = subprocess.run([EXE, "status"], cwd="/tmp", env=env, capture_output=True, text=True)
        ok("服务未运行" in st.stdout, "cli status after quit: " + st.stdout.strip())
        upstream.shutdown()
        logf.close()
        if FAILS:
            print("--- serve log tail ---")
            print(open(log_path).read()[-2000:])
    print("FAILURES:", FAILS)
    sys.exit(1 if FAILS else 0)

if __name__ == "__main__":
    main()
