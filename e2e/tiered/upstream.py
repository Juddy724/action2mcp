import http.server, json
class H(http.server.BaseHTTPRequestHandler):
    def _r(self):
        n=int(self.headers.get('Content-Length') or 0); b=self.rfile.read(n).decode() if n else ''
        out=json.dumps({"path":self.path,"method":self.command,"body":b},ensure_ascii=False).encode()
        self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(out))); self.end_headers(); self.wfile.write(out)
    do_GET=_r; do_POST=_r
    def log_message(self,*a): pass
http.server.ThreadingHTTPServer(('127.0.0.1',18999),H).serve_forever()
