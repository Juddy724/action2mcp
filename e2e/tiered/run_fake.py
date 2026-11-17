#!/usr/bin/env python3
"""Run historical HTTP/stdio/optional SDK clients with disposable loopback peers.

python3 e2e/tiered/run_fake.py /absolute/a2m [--sdk-python /venv/bin/python]
The Redis peer implements only handshake/PING, not real Redis semantics.
"""
import argparse
import json
import os
from pathlib import Path
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = Path(__file__).resolve().parent

class Echo(BaseHTTPRequestHandler):
    def reply(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()
        raw = json.dumps({"path": self.path, "method": self.command, "body": body}, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)
    do_GET = reply
    do_POST = reply
    def log_message(self, *args):
        pass

class RedisPing(socketserver.StreamRequestHandler):
    def handle(self):
        while True:
            line = self.rfile.readline()
            if not line:
                return
            if not line.startswith(b"*"):
                return
            args = []
            for _ in range(int(line[1:])):
                size = self.rfile.readline()
                if not size.startswith(b"$"):
                    return
                args.append(self.rfile.read(int(size[1:])))
                self.rfile.read(2)
            command = args[0].upper() if args else b""
            if command == b"PING":
                response = b"+PONG\r\n"
            elif command == b"CLIENT":
                response = b"+OK\r\n"
            else:
                response = b"-ERR unknown command\r\n"
            self.wfile.write(response)
            self.wfile.flush()

class RedisServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary", type=lambda p: str(Path(p).resolve()))
    parser.add_argument("--sdk-python", help="Python with official MCP SDK installed")
    opts = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="a2m-tiered-") as data:
        echo = ThreadingHTTPServer(("127.0.0.1", 0), Echo)
        redis = RedisServer(("127.0.0.1", 0), RedisPing)
        for server in (echo, redis):
            threading.Thread(target=server.serve_forever, daemon=True).start()
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = str(s.getsockname()[1])
        env = dict(os.environ, A2M_DATA=data, A2M_PORT=port)
        base = "http://127.0.0.1:" + port
        with open(Path(data) / "serve.log", "w+") as log:
            proc = subprocess.Popen([opts.binary, "serve", "--no-open"], cwd=data, env=env, stdout=log, stderr=log)
            try:
                for _ in range(100):
                    try:
                        with urllib.request.urlopen(base + "/api/status", timeout=1) as response:
                            assert json.load(response)["data_dir"] == data
                        break
                    except OSError:
                        time.sleep(.05)
                else:
                    raise RuntimeError("server startup timeout")
                subprocess.run([sys.executable, str(HERE / "prepare_fake_fixture.py"), base,
                                "http://127.0.0.1:" + str(echo.server_port), str(redis.server_address[1])], check=True, timeout=30)
                subprocess.run([sys.executable, str(HERE / "raw_http.py"), port], check=True, timeout=60)
                stdio = subprocess.run([sys.executable, str(HERE / "stdio_console.py"), port, opts.binary, data], check=True, timeout=60, capture_output=True, text=True)
                print(stdio.stdout, end="")
                if ": False" in stdio.stdout:
                    raise AssertionError("stdio_console notification/initialize probe failed")
                if opts.sdk_python:
                    subprocess.run([opts.sdk_python, str(HERE / "sdk_client.py"), port, opts.binary, data], check=True, timeout=120)
                else:
                    print("NOT TESTED: Python MCP SDK (provide --sdk-python)")
                print("PASS isolated tiered HTTP + stdio" + (" + official SDK" if opts.sdk_python else ""))
            finally:
                try:
                    subprocess.run([opts.binary, "quit"], cwd=data, env=env, capture_output=True, timeout=10, check=True)
                    proc.wait(timeout=10)
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.wait()
                    echo.shutdown()
                    echo.server_close()
                    redis.shutdown()
                    redis.server_close()
                if proc.returncode:
                    log.seek(0)
                    print(log.read(), file=sys.stderr)

if __name__ == "__main__":
    main()
