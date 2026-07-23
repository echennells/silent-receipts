#!/usr/bin/env python3
"""Silent Receipts demo GUI server.

Serves the static page and bridges POST /verify to the `receipt` CLI as a
subprocess. All cryptography lives in the Rust binary; this is display glue.

    RECEIPT_BIN=target/release/receipt python3 web/serve.py
"""
import json
import os
import re
import subprocess
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8552"))
RECEIPT_BIN = os.environ.get("RECEIPT_BIN", "target/release/receipt")
BUNDLE_DIR = os.environ.get("BUNDLE_DIR", "data/bundles")
CACHE_DIR = os.environ.get("CACHE_DIR", "data/cache")
WEB_DIR = os.path.dirname(os.path.abspath(__file__))

SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            with open(os.path.join(WEB_DIR, "index.html"), "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        elif self.path == "/bundles":
            items = []
            if os.path.isdir(BUNDLE_DIR):
                for name in sorted(os.listdir(BUNDLE_DIR)):
                    if not name.endswith(".json"):
                        continue
                    try:
                        with open(os.path.join(BUNDLE_DIR, name)) as f:
                            b = json.load(f)
                        items.append({
                            "file": name,
                            "claim": b.get("claim", "?"),
                            "txid": b.get("txid", "?"),
                            "address": b.get("address", "?"),
                            "verifier": b.get("verifier", "?"),
                            "outputs": len(b.get("outputs", [])),
                        })
                    except (OSError, json.JSONDecodeError):
                        continue
            self._send(200, items)
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/verify":
            self._send(404, {"error": "not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            req = json.loads(self.rfile.read(length) or b"{}")
            name = req.get("bundle", "")
            if not SAFE_NAME.match(name) or ".." in name:
                self._send(400, {"error": "bad bundle name"})
                return
            path = os.path.join(BUNDLE_DIR, name)
            if not os.path.isfile(path):
                self._send(404, {"error": f"no such bundle: {name}"})
                return
            proc = subprocess.run(
                [RECEIPT_BIN, "verify", "--bundle", path, "--cache", CACHE_DIR],
                capture_output=True, text=True, timeout=30,
            )
            if proc.returncode != 0:
                self._send(500, {"error": proc.stderr.strip() or "verifier failed"})
                return
            self._send(200, json.loads(proc.stdout))
        except Exception as e:  # demo server: report, never crash
            self._send(500, {"error": str(e)})

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    print(f"Silent Receipts GUI: http://localhost:{PORT}  (verifier: {RECEIPT_BIN})")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
