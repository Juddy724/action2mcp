#!/usr/bin/env python3
"""Seed a fresh fake fixture for e2e/tiered against an already running a2m.

The upstream echo server is e2e/tiered/upstream.py on 127.0.0.1:18999.
Nothing here is a real customer system. Redis is registered as 127.0.0.1
and is not started by this seeder; run_fake.py supplies a minimal PING peer.

    python3 prepare_fake_fixture.py http://127.0.0.1:PORT [UPSTREAM [REDIS_PORT]]
"""
import json, sys, urllib.request
from urllib.parse import urlparse

BASE = sys.argv[1].rstrip("/")
UP = sys.argv[2].rstrip("/") if len(sys.argv) > 2 else "http://127.0.0.1:18999"
REDIS_PORT = int(sys.argv[3]) if len(sys.argv) > 3 else 6379
if any(urlparse(u).hostname != "127.0.0.1" for u in (BASE, UP)):
    raise SystemExit("fake fixtures require 127.0.0.1")
SECRET = "TOPSECRET-e2e-9f8a7"

def api(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(BASE + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=30) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None

def tool(spec):
    got = api("POST", "/api/tools", spec)
    print("tool", got["id"], got["name"])
    return got["id"]

# This historical tiered fixture has exactly two visible user packs. Disable
# the newer optional recording-analysis pack rather than weaken its assertions.
api("PUT", "/api/settings", {"rec_analysis": False})
api("POST", "/api/vault", {"name": "svc_pw", "type": "secret", "value": SECRET, "note": "fake e2e"})
echo = tool({
    "name": "echo_order", "title": "回显订单", "method": "POST", "approval": "off",
    "url": UP + "/order", "description": "fake echo",
    "headers": {}, "body": "order_no={{order_no}} pw={{secret.svc_pw}}",
    "params": [{"name": "order_no", "type": "string", "description": "订单号", "required": True}],
})
hours = tool({
    "name": "log_hours", "title": "记工时", "method": "POST", "approval": "off",
    "url": UP + "/hours", "description": "fake hours",
    "headers": {}, "body": "h={{hours}}",
    "params": [{"name": "hours", "type": "string", "description": "小时", "required": True}],
})
secret = tool({
    "name": "secret_tool", "title": "机密", "method": "GET", "approval": "off",
    "url": UP + "/secret", "description": "disabled pack",
    "headers": {}, "params": [], "body": "",
})
mw = api("POST", "/api/middleware", {
    "name": "缓存", "type": "redis",
    "config": {"host": "127.0.0.1", "port": REDIS_PORT, "redis_mode": "standalone",
               "perms": {"read": True, "write": False, "delete": False, "script": False}},
})
print("middleware", mw["id"], mw["name"])
orders = api("POST", "/api/packs", {"name": "订单查询", "description": "fake", "enabled": True, "scenarios": "订单", "guide": ""})
work = api("POST", "/api/packs", {"name": "工时", "description": "fake", "enabled": True, "scenarios": "工时", "guide": ""})
hidden = api("POST", "/api/packs", {"name": "机密包", "description": "fake", "enabled": False, "scenarios": "机密", "guide": ""})
print("packs", orders["id"], work["id"], hidden["id"])
if orders["id"] != 1 or work["id"] != 2:
    raise SystemExit("stdio_console.py addresses pack id 2; create packs on an empty database")
api("POST", f"/api/packs/{orders['id']}/tools", {"ids": [echo]})
api("POST", f"/api/packs/{orders['id']}/middleware", {"ids": [mw["id"]]})
api("POST", f"/api/packs/{work['id']}/tools", {"ids": [hours]})
api("POST", f"/api/packs/{hidden['id']}/tools", {"ids": [secret]})
print("fixture ready")
