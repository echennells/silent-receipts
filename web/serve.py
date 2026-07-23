#!/usr/bin/env python3
"""Silent Receipts demo GUI server.

Serves the static page and bridges POST /verify to the `receipt` CLI as a
subprocess. All cryptography lives in the Rust binary; this is display glue.

It also commits the most gratuitous possible use of OpenTimestamps:
every verification triggered through this server is written to disk and
timestamped — the act of checking a receipt is itself receipted.

    RECEIPT_BIN=target/release/receipt python3 web/serve.py
"""
import json
import os
import re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8552"))
RECEIPT_BIN = os.environ.get("RECEIPT_BIN", "target/release/receipt")
BUNDLE_DIR = os.environ.get("BUNDLE_DIR", "data/bundles")
CACHE_DIR = os.environ.get("CACHE_DIR", "data/cache")
OTS_DIR = os.environ.get("OTS_DIR", "data/ots")
WEB_DIR = os.path.dirname(os.path.abspath(__file__))

SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
MAX_WITNESSED = 500  # a two-day demo does not need more receipts of receipts


def find_ots():
    for c in (os.environ.get("OTS_BIN"), "/opt/ots/bin/ots",
              os.path.expanduser("~/.venvs/ots/bin/ots")):
        if c and os.path.isfile(c):
            return c
    return "ots"


OTS_BIN = find_ots()
_ots_cache = {}
_witness_lock = threading.Lock()


def ots_status(path):
    """pending | bitcoin | unknown — parsed from `ots info` (offline, cached by mtime)."""
    try:
        key = (path, os.path.getmtime(path))
        if key in _ots_cache:
            return _ots_cache[key]
        out = subprocess.run([OTS_BIN, "info", path], capture_output=True,
                             text=True, timeout=8).stdout
        if "Bitcoin" in out:
            st = "bitcoin"
        elif "Pending" in out or "calendar" in out:
            st = "pending"
        else:
            st = "unknown"
        _ots_cache[key] = st
        return st
    except Exception:
        return "unknown"


def witness_verification(verdict_json):
    """Write the verdict to disk and timestamp it. Yes, really."""
    try:
        vdir = os.path.join(OTS_DIR, "verifications")
        os.makedirs(vdir, exist_ok=True)
        with _witness_lock:
            n = len([f for f in os.listdir(vdir) if f.endswith(".json")]) + 1
            if n > MAX_WITNESSED:
                return
            path = os.path.join(vdir, f"verification-{n:04d}.json")
            with open(path, "w") as f:
                f.write(verdict_json)
        subprocess.run([OTS_BIN, "stamp", path], capture_output=True, timeout=30)
    except Exception:
        pass


def list_timestamps():
    items = []
    for sub in ("artifacts", "verifications"):
        d = os.path.join(OTS_DIR, sub)
        if not os.path.isdir(d):
            continue
        for name in os.listdir(d):
            if not name.endswith(".ots"):
                continue
            full = os.path.join(d, name)
            if name.endswith(".ots.ots"):
                kind = "proof of proof"
            elif sub == "verifications":
                kind = "verification"
            else:
                kind = "artifact"
            items.append({
                "name": name,
                "kind": kind,
                "status": ots_status(full),
                "mtime": os.path.getmtime(full),
            })
    items.sort(key=lambda t: t["mtime"], reverse=True)
    counts = {
        "total": len(items),
        "artifacts": sum(1 for t in items if t["kind"] == "artifact"),
        "proofs_of_proofs": sum(1 for t in items if t["kind"] == "proof of proof"),
        "verifications": sum(1 for t in items if t["kind"] == "verification"),
        "bitcoin": sum(1 for t in items if t["status"] == "bitcoin"),
        "pending": sum(1 for t in items if t["status"] == "pending"),
    }
    for t in items:
        del t["mtime"]
    return {"counts": counts, "items": items[:80]}


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
        elif self.path == "/timestamps":
            self._send(200, list_timestamps())
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
            threading.Thread(target=witness_verification, args=(proc.stdout,),
                             daemon=True).start()
            self._send(200, json.loads(proc.stdout))
        except Exception as e:  # demo server: report, never crash
            self._send(500, {"error": str(e)})

    def log_message(self, fmt, *args):
        pass


if __name__ == "__main__":
    print(f"Silent Receipts GUI: http://localhost:{PORT}  "
          f"(verifier: {RECEIPT_BIN}, ots: {OTS_BIN})")
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
