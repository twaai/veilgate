"""Thin client for the Veilgate data plane.

An agent integration gets exactly this: a base URL and one credential. Everything
else - the real store, the approver key, the shadow builder - lives in the server
process. If you find yourself importing veilgate here, the boundary is already lost.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request


class Client:
    def __init__(self, base: str, credential: str, timeout: float = 30.0) -> None:
        self.base = base.rstrip("/")
        self._cred = credential
        self.timeout = timeout

    def _req(self, method: str, path: str, payload: dict | None = None) -> dict:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method,
                                     headers={"Authorization": f"Bearer {self._cred}",
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return {"http_status": e.code, **json.loads(e.read().decode() or "{}")}

    def directory(self) -> dict:
        return self._req("GET", "/v1/directory")

    def call(self, route: str, args: dict | None = None, approval: str | None = None) -> dict:
        return self._req("POST", "/v1/call",
                         {"route": route, "args": args or {}, "approval": approval})


def register(base: str, operator_token: str, name: str, principal: str = "default") -> str:
    req = urllib.request.Request(
        base.rstrip("/") + "/v1/register",
        data=json.dumps({"name": name, "principal": principal}).encode(), method="POST",
        headers={"Authorization": f"Bearer {operator_token}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read().decode())["credential"]
