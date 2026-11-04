import asyncio, json, sys
import mcp
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
SECRET='TOPSECRET-e2e-9f8a7'
try:
    from mcp.client.streamable_http import streamablehttp_client as _h; V=1
except ImportError:
    from mcp.client.streamable_http import streamable_http_client as _h; V=2
fails=[]
def ok(c,m): print(('PASS ' if c else 'FAIL ')+m); c or fails.append(m)
async def run(read, write, label):
    changed=asyncio.Event()
    async def handler(msg):
        s=repr(msg)
        if 'ToolListChanged' in s or 'tools/list_changed' in s: changed.set()
    async with ClientSession(read, write, message_handler=handler) as s:
        init=await s.initialize()
        g=lambda o,a,b: getattr(o,a,None) if hasattr(o,a) else getattr(o,b,None)
        si=g(init,'serverInfo','server_info'); print(f"[{label}] server={si.name} {si.version} proto={g(init,'protocolVersion','protocol_version')} listChanged={g(init.capabilities.tools,'listChanged','list_changed')}")
        names=lambda r:[t.name for t in r.tools]
        ok(names(await s.list_tools())==["list_packs","load_pack","unload_pack","call_pack_tool"], f"[{label}] entry-only list")
        r=await s.call_tool("list_packs",{}); packs=json.loads(r.content[0].text)["packs"]
        ok([p["name"] for p in packs]==["订单查询","工时"], f"[{label}] list_packs")
        r=await s.call_tool("load_pack",{"pack":"工时"}); ok(not g(r,'isError','is_error'), f"[{label}] load_pack 工时")
        try: await asyncio.wait_for(changed.wait(),5); got=True
        except asyncio.TimeoutError: got=False
        ok(got, f"[{label}] list_changed notification delivered to SDK message_handler")
        l=names(await s.list_tools()); ok("log_hours" in l and "echo_order" not in l, f"[{label}] tools after load: {l}")
        r=await s.call_tool("log_hours",{"hours":8}); ok(not g(r,'isError','is_error') and "h=8" in r.content[0].text, f"[{label}] call log_hours")
        r=await s.call_tool("call_pack_tool",{"tool":"echo_order","arguments":{"order_no":"Z9"}}); t=r.content[0].text
        ok("Z9" in t and SECRET not in t, f"[{label}] call_pack_tool echo_order, secret scrubbed")
        r=await s.call_tool("call_pack_tool",{"tool":"redis_command","arguments":{"middleware":"缓存","command":"DEL x"}})
        ok("无权限" in r.content[0].text, f"[{label}] middleware denial via fallback")
        changed.clear(); await s.call_tool("unload_pack",{})
        try: await asyncio.wait_for(changed.wait(),5); got=True
        except asyncio.TimeoutError: got=False
        ok(got and len(names(await s.list_tools()))==4, f"[{label}] unload_pack + list_changed")
async def main():
    port=sys.argv[1]; exe=sys.argv[2]; data=sys.argv[3]
    print("mcp SDK", V, getattr(mcp,'__version__',''))
    async with _h(f"http://127.0.0.1:{port}/mcp") as streams:
        await run(streams[0], streams[1], "http")
    params=StdioServerParameters(command=exe,args=["mcp"],env={"A2M_DATA":data,"A2M_PORT":port,"PATH":"/usr/bin:/bin"})
    async with stdio_client(params) as (r,w):
        await run(r,w,"stdio")
    print("FAILURES:",fails); sys.exit(1 if fails else 0)
asyncio.run(main())
