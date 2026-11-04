import json, threading, http.client, time, sys, queue
HOST,PORT='127.0.0.1',int(sys.argv[1]) if len(sys.argv)>1 else 17802
SECRET='TOPSECRET-e2e-9f8a7'
sid=None; nid=0; leaks=[]; ok=lambda c,m: print(('PASS ' if c else 'FAIL ')+m) or (c or fails.append(m))
fails=[]
def post(method, params=None, notify=False):
    global sid,nid
    msg={"jsonrpc":"2.0","method":method}
    if params is not None: msg["params"]=params
    if not notify: nid+=1; msg["id"]=nid
    c=http.client.HTTPConnection(HOST,PORT,timeout=30)
    h={"Content-Type":"application/json","Accept":"application/json, text/event-stream","MCP-Protocol-Version":"2025-06-18"}
    if sid: h["Mcp-Session-Id"]=sid
    c.request("POST","/mcp",json.dumps(msg),h); r=c.getresponse(); body=r.read().decode()
    if SECRET in body: leaks.append(method)
    if r.getheader("Mcp-Session-Id"): sid=r.getheader("Mcp-Session-Id")
    if notify: return r.status, None
    msgs=[]
    if (r.getheader("Content-Type") or '').startswith("text/event-stream"):
        for line in body.splitlines():
            if line.startswith("data:"): msgs.append(json.loads(line[5:].strip()))
    else: msgs=[json.loads(body)]
    return msgs, [m for m in msgs if m.get("id")==nid][0]
notes=queue.Queue()
def stream():
    c=http.client.HTTPConnection(HOST,PORT,timeout=120)
    c.request("GET","/mcp",headers={"Accept":"text/event-stream","Mcp-Session-Id":sid}); r=c.getresponse()
    notes.put(("status",r.status))
    while True:
        line=r.fp.readline()
        if not line: break
        line=line.decode()
        if SECRET in line: leaks.append('stream')
        if line.startswith("data:"): notes.put(("msg",json.loads(line[5:])))
def names(): return [t["name"] for t in post("tools/list",{})[1]["result"]["tools"]]
def call(name,args):
    r=post("tools/call",{"name":name,"arguments":args})[1]
    if "error" in r: return r["error"]["message"], True
    return r["result"]["content"][0]["text"], r["result"].get("isError",False)
def wait_note(t=3):
    end=time.time()+t
    while time.time()<end:
        try:
            k,v=notes.get(timeout=0.2)
            if k=="msg" and v.get("method")=="notifications/tools/list_changed": return True
        except queue.Empty: pass
    return False

_,init=post("initialize",{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"raw-e2e","version":"1"}})
ok(init["result"]["capabilities"]["tools"].get("listChanged") is True, "initialize: listChanged=true, sid="+str(bool(sid)))
post("notifications/initialized",notify=True)
threading.Thread(target=stream,daemon=True).start(); time.sleep(0.5)
ok(notes.get(timeout=3)==("status",200),"GET /mcp SSE stream opened")
n=names(); print("  tools/list:",n)
ok(n==["list_packs","load_pack","unload_pack","call_pack_tool"],"entry-only tools/list")
txt,_=call("list_packs",{}); lp=json.loads(txt); print("  list_packs:",txt)
ok([p["name"] for p in lp["packs"]]==["订单查询","工时"],"list_packs shows only enabled packs")
txt,e=call("load_pack",{"pack":"订单查询"}); lr=json.loads(txt)
ok(not e and [t["name"] for t in lr["tools"]][:1]==["echo_order"] and all("inputSchema" in t for t in lr["tools"]),"load_pack returns tools+schemas: "+str([t["name"] for t in lr["tools"]]))
ok(wait_note(),"list_changed received on GET stream")
n=names(); print("  tools/list after load:",n)
ok("echo_order" in n and "log_hours" not in n and "secret_tool" not in n,"pack tools listed, others not")
txt,e=call("echo_order",{"order_no":"A100"}); print("  echo_order:",txt[:200])
ok(not e and "A100" in txt and SECRET not in txt,"direct call works, secret scrubbed")
txt,e=call("call_pack_tool",{"tool":"log_hours","arguments":{"hours":3}}); print("  fallback log_hours (not loaded):",txt[:160])
ok(not e and "h=3" in txt,"call_pack_tool on enabled-but-unloaded pack works")
txt,e=call("call_pack_tool",{"tool":"echo_order","arguments":"{\"order_no\":\"B7\"}"})
ok(not e and "B7" in txt and SECRET not in txt,"call_pack_tool with stringified args, scrubbed")
txt,e=call("call_pack_tool",{"tool":"redis_command","arguments":{"middleware":"缓存","command":"PING"}}); ok(not e and "PONG" in txt,"redis PING via fallback: "+txt)
txt,e=call("call_pack_tool",{"tool":"redis_command","arguments":{"middleware":"缓存","command":"SET a2m_e2e 1"}}); print("  redis SET via fallback:",txt)
ok("无权限" in txt,"middleware write denied via fallback")
txt,e=call("redis_command",{"middleware":"缓存","command":"SET a2m_e2e 1"}); ok("无权限" in txt,"middleware write denied via direct call")
txt,e=call("secret_tool",{}); print("  disabled direct:",txt); ok(e and "list_packs" in txt,"disabled pack tool rejected with hint")
txt,e=call("call_pack_tool",{"tool":"secret_tool","arguments":{}}); ok(e,"disabled pack tool rejected via fallback: "+txt)
txt,e=call("load_pack",{"pack":"机密包"}); ok(e,"disabled pack cannot be loaded: "+txt)
txt,e=call("unload_pack",{"pack":"订单查询"}); ok(not e and json.loads(txt)["unloaded"],"unload_pack")
ok(wait_note(),"list_changed after unload")
ok(names()==["list_packs","load_pack","unload_pack","call_pack_tool"],"back to entry-only")
ok(not leaks,"no secret leak in any response/stream ("+str(leaks)+")")
c=http.client.HTTPConnection(HOST,PORT); c.request("DELETE","/mcp",headers={"Mcp-Session-Id":sid}); ok(c.getresponse().status in (200,204),"DELETE session")
print("FAILURES:",fails); sys.exit(1 if fails else 0)
