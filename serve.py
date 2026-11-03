#!/usr/bin/env python3
"""Veilgate data plane: the gateway in its own process.

The agent gets a URL and one credential. It never gets the real store, the approver
key, the shadow, or a reference to any object in this process. That is the whole
point of the file.

    python serve.py --port 8080 --operator-token s3cret --seed 7
    python serve.py --demo            # ephemeral port, prints a ready credential

Endpoints
    POST /v1/register   operator token   {"name": n, "principal": p} -> {"credential": c}
    GET  /v1/directory  agent credential -> {"action": "token", ...}
    POST /v1/call       agent credential {"route", "args", "approval"}
    GET  /healthz                        -> {"ok": true}

The data plane is the only reachable surface. Registration is the control plane's
job; it is mounted here on a separate token so the pilot has one process, and the
README says plainly that in a real deployment it belongs on another host, unreachable
from the agent's network.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import veilgate as ad

MAX_BODY = 64 * 1024
VERSION = "0.1.0"


class Handler(BaseHTTPRequestHandler):
    server_version = f"veilgate/{VERSION}"
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # --- plumbing ---
    def log_message(self, fmt, *args):          # silence by default: logs leak routes
        if self.server.verbose:
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, payload: dict) -> None:
        body = json.dumps(payload, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _auth(self) -> str:
        h = self.headers.get("Authorization", "")
        if not h.startswith("Bearer "):
            return ""
        return h[7:].strip()

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > MAX_BODY:
            return None
        try:
            doc = json.loads(self.rfile.read(n).decode())
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None
        return doc if isinstance(doc, dict) else None

    # --- routes ---
    def do_GET(self):
        if self.path == "/healthz":
            return self._send(200, {"ok": True, "version": VERSION})
        if self.path != "/v1/directory":
            return self._send(404, {"error": "not found"})
        cred = self._auth()
        gw = self.server.gateway
        if cred not in gw.agents:
            return self._send(401, {"error": "unauthorized"})
        return self._send(200, gw.directory(cred))

    def do_POST(self):
        if self.path == "/v1/register":
            if not self._operator_ok():
                return self._send(401, {"error": "unauthorized"})
            doc = self._body() or {}
            name = str(doc.get("name") or "agent")[:64]
            principal = str(doc.get("principal") or "default")[:64]
            cred = self.server.gateway.register(name, principal)
            return self._send(200, {"credential": cred})

        if self.path == "/v1/call":
            cred = self._auth()
            gw = self.server.gateway
            if cred not in gw.agents:
                return self._send(401, {"error": "unauthorized"})
            doc = self._body()
            if doc is None:
                return self._send(400, {"error": "bad request"})
            out = gw.call(cred, doc.get("route", ""), doc.get("args") or {}, doc.get("approval"))
            return self._send(200, out)

        return self._send(404, {"error": "not found"})

    def _operator_ok(self) -> bool:
        token = self._auth()
        want = self.server.operator_token
        return bool(want) and secrets.compare_digest(token, want)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, addr, gateway, operator_token, verbose=False):
        super().__init__(addr, Handler)
        self.gateway = gateway
        self.operator_token = operator_token
        self.verbose = verbose


def build(seed=None, bind="127.0.0.1", port=0, operator_token=None, verbose=False):
    gw = ad.Gateway(ad.Approver(), real=ad.real_store(seed),
                    log=lambda m: sys.stderr.write(m + "\n") if verbose else None)
    srv = Server((bind, port), gw, operator_token or secrets.token_urlsafe(24), verbose)
    return srv


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind", default="127.0.0.1",
                    help="loopback by default; put a real proxy in front for anything else")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--operator-token", default=os.environ.get("VEILGATE_OPERATOR_TOKEN"))
    ap.add_argument("--demo", action="store_true", help="start on an ephemeral port and print a credential")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    srv = build(a.seed, a.bind, a.port, a.operator_token, a.verbose)
    host, port = srv.server_address[:2]
    print(f"LISTENING {host}:{port}", flush=True)
    if a.demo:
        cred = srv.gateway.register("agent", "demo")
        print(f"CREDENTIAL {cred}", flush=True)
    else:
        print("operator token: set (not printed)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()


if __name__ == "__main__":
    main()
