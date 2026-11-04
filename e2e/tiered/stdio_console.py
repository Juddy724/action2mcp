import subprocess, json, os, time, threading, queue, urllib.request, sys
port,exe,data=sys.argv[1:4]
env=dict(os.environ,A2M_DATA=data,A2M_PORT=port)
p=subprocess.Popen([exe,"mcp"],stdin=subprocess.PIPE,stdout=subprocess.PIPE,env=env,text=True)
q=queue.Queue(); threading.Thread(target=lambda:[q.put(json.loads(l)) for l in p.stdout],daemon=True).start()
def send(m): p.stdin.write(json.dumps(m)+"\n"); p.stdin.flush()
seen=[]
def until(pred,t=8):
    for m in list(seen):
        if pred(m): seen.remove(m); return m
    end=time.time()+t
    while time.time()<end:
        try:
            m=q.get(timeout=0.2)
            if pred(m): return m
            seen.append(m)
        except queue.Empty: pass
def api(method,path,body=None):
    r=urllib.request.Request(f"http://127.0.0.1:{port}{path}",data=json.dumps(body).encode() if body is not None else None,method=method,headers={"Content-Type":"application/json"})
    return json.load(urllib.request.urlopen(r))
send({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"stdio-console","version":"1"}}})
print("init:", bool(until(lambda m:m.get("id")==1)))
send({"jsonrpc":"2.0","method":"notifications/initialized"})
time.sleep(1.5)  # bridge opens GET stream
send({"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"load_pack","arguments":{"pack":"2"}}})
until(lambda m:m.get("id")==2)
ch=lambda m:m.get("method")=="notifications/tools/list_changed"
print("list_changed after load (stdio):", bool(until(ch)))
api("POST","/api/packs/2/toggle",{"enabled":False})
print("list_changed after console disables pack:", bool(until(ch)))
send({"jsonrpc":"2.0","id":3,"method":"tools/list","params":{}})
print("tools after disable:", [t["name"] for t in until(lambda m:m.get("id")==3)["result"]["tools"]])
api("POST","/api/packs/2/toggle",{"enabled":True})
print("list_changed after re-enable:", bool(until(ch)))
send({"jsonrpc":"2.0","id":4,"method":"tools/list","params":{}})
print("tools after re-enable (still loaded in session):", [t["name"] for t in until(lambda m:m.get("id")==4)["result"]["tools"]])
api("PUT","/api/settings",{"mcp_mode":"flat"})
print("list_changed after switch to flat:", bool(until(ch)))
send({"jsonrpc":"2.0","id":5,"method":"tools/list","params":{}})
print("flat tools:", [t["name"] for t in until(lambda m:m.get("id")==5)["result"]["tools"]])
api("PUT","/api/settings",{"mcp_mode":"tiered"}); until(ch)
send({"jsonrpc":"2.0","id":6,"method":"tools/list","params":{}})
print("tiered again:", [t["name"] for t in until(lambda m:m.get("id")==6)["result"]["tools"]])
p.stdin.close(); p.wait(5)
