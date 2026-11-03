#!/usr/bin/env python3
"""MCP stdio shim: put Veilgate inside the pipe.

The agent's MCP config launches this instead of the real server:

    "command": "python", "args": ["mcp_shim.py", "--", "python", "real_server.py"]

veilgate spawns the real server, relays JSON-RPC both ways, and from the moment the
agent crosses its egress budget it stops forwarding reads and starts answering them
from a shadow synthesised out of what the agent was allowed to see.

This is the local-server case: there is no socket to sit in front of, so the shim
takes the place of the server in the agent's config and owns the child process.

    VEILGATE_MCP_BUDGET=4000 python mcp_shim.py -- python real_server.py
    python mcp_shim.py --log shim.log -- python real_server.py

Limits, stated up front:
  * runs as the agent's child in the same user context. If the agent can run shell
    commands it can spawn the real server directly and bypass this entirely. The
    boundary is that the *operator* owns the MCP config, not the agent.
  * only JSON-shaped tool results can be faked. Free text, files and images pass
    through unchanged and are logged as unfakeable.
"""
from __future__ import annotations

import argparse
import json
import os
import random
import re
import subprocess
import sys
import threading
import time
from collections import deque

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import veilgate as ad

ID_KEYS = ("id", "ID", "_id", "uuid", "key", "pk")
WRITE_RE = re.compile(r"(^|_)(write|create|update|delete|insert|remove|set|put|post|"
                      r"send|drop|truncate|patch|append)(_|$)", re.I)
DEFAULT_BUDGET = 4000
DEFAULT_RESERVE = 512


def dumps(o) -> bytes:
    return (json.dumps(o, separators=(",", ":")) + "\n").encode()


def parse(line: bytes):
    try:
        msg = json.loads(line.decode("utf-8"))
        return msg if isinstance(msg, dict) else None
    except (ValueError, UnicodeDecodeError):
        return None


# ---------- shape sniffing: what in a tool result looks like table rows? ----------

def rows_of(obj):
    """Return (rows, kind) if obj looks like one record or a list of records."""
    if isinstance(obj, dict) and len(obj) >= 2 and all(
            not isinstance(v, (dict, list)) for v in obj.values()):
        return [obj], "single"
    if isinstance(obj, list) and obj and all(isinstance(x, dict) for x in obj):
        shapes = {frozenset(x) for x in obj}
        if len(shapes) == 1 and len(obj[0]) >= 2:
            return obj, "list"
    return None, None


def id_of(rec, fallback=None):
    for k in ID_KEYS:
        if k in rec:
            return rec[k]
    return fallback


def payloads(msg):
    """Every JSON payload inside a CallToolResult, with a handle for writing back."""
    res = msg.get("result")
    if not isinstance(res, dict):
        return []
    out = []
    for i, b in enumerate(res.get("content") or []):
        if isinstance(b, dict) and b.get("type") == "text" and isinstance(b.get("text"), str):
            try:
                out.append((i, json.loads(b["text"])))
            except ValueError:
                pass
    if isinstance(res.get("structuredContent"), (dict, list)):
        out.append(("sc", res["structuredContent"]))
    return out


def put_back(msg, handle, obj):
    res = msg["result"]
    if handle == "sc":
        res["structuredContent"] = obj
    else:
        res["content"][handle]["text"] = json.dumps(obj, separators=(",", ":"))


def is_write(name: str) -> bool:
    return bool(WRITE_RE.search(name or ""))


# ---------- the guard ----------

class Guard:
    def __init__(self, budget=DEFAULT_BUDGET, window=None, log=None):
        self.budget = budget
        self.window = window or ad.EGRESS_WINDOW_S
        self.egress = deque()
        self.seen = {}                 # id -> record the agent was actually shown
        self.harvest = {}              # id -> record we fetched ourselves; never served
        self.fake = None               # Store of synthesised records
        self.canaries = set()
        self.tool_reserve = {}         # per tool: size of the largest reply so far
        self.last_shape = {}           # per tool: last payload, for replay
        self.inflight = {}             # jsonrpc id -> tool name
        self.pending_local = {}        # harvest id -> the request whose answer we owe
        self.harvest_tool = None
        self.harvest_seq = 0
        self.quarantined = False
        self.reason = ""
        self.unfakeable = set()
        self.log = log or (lambda *_: None)

    # -- accounting --
    def _total(self):
        cutoff = time.time() - self.window
        while self.egress and self.egress[0][0] < cutoff:
            self.egress.popleft()
        return sum(n for _, n in self.egress)

    def _charge(self, n):
        self.egress.append((time.time(), n))

    # -- learning the data before the switch --
    def absorb(self, obj):
        rows, _ = rows_of(obj)
        if not rows:
            return
        for i, rec in enumerate(rows, start=1):
            rid = id_of(rec, i)
            self.seen[rid] = dict(rec)
        self.last_shape[self._tool] = obj

    def _absorb_harvest(self, obj):
        """Data we pulled ourselves. It is never served - only used as the pool the
        shadow is synthesised from - so it goes in a separate bucket from `seen`."""
        rows, _ = rows_of(obj)
        if not rows:
            return
        for i, rec in enumerate(rows, start=1):
            rid = id_of(rec, i)
            if rid not in self.seen:
                self.harvest[rid] = dict(rec)

    # -- the switch --
    def _build_shadow(self):
        pool = dict(self.harvest)
        for k, v in self.seen.items():
            pool.setdefault(k, v)
        if not pool:
            return
        self.fake = ad.build_shadow(ad.Store(pool), {}, self.canaries)

    def start_switch(self, reason):
        if self.quarantined:
            return
        self.quarantined = True
        self.reason = reason
        self.log(f"[QUARANTINE] {reason}; "
                 f"seen={len(self.seen)} harvested={len(self.harvest)}")
        self._build_shadow()

    def _begin_switch(self, msg, name):
        """Crossed the budget on a call we have not forwarded yet. Rather than answer
        from a thin pool, ask the server for the broadest view of this tool once, and
        answer the agent when it comes back."""
        self.start_switch("egress budget (refused before dispatch)")
        if self.harvest_tool is not None:
            return self.answer_locally(msg, name, (msg.get("params") or {}).get("arguments") or {})
        hid = f"vg-harvest-{self.harvest_seq}"
        self.harvest_seq += 1
        self.pending_local[hid] = msg
        self.harvest_tool = name
        return {"__harvest__": hid}

    def harvest_request(self, hid):
        return {"jsonrpc": "2.0", "id": hid, "method": "tools/call",
                "params": {"name": self.harvest_tool, "arguments": {}}}

    # -- synthesis for an id --
    def _name_prefix(self):
        names = [str(r.get("name")) for r in (self.fake.records.values() if self.fake else [])
                 if isinstance(r.get("name"), str)]
        m = [re.match(r"^(.*?)(\d+)$", n) for n in names]
        if names and all(m):
            return m[0].group(1)
        return None

    def synth(self, rid, template=None):
        """A plausible record for `rid`: public fields from the template, everything
        else from a random donor in the fake pool. Never copies a real sensitive value."""
        pool = list(self.fake.records.values()) if self.fake else []
        donor = dict(random.choice(pool)) if pool else {}
        out = dict(donor)
        for k in ID_KEYS:
            if k in out or (template and k in template):
                out[k] = rid
        if "name" in out or (template and "name" in template):
            pre = self._name_prefix()
            if pre is not None:
                out["name"] = f"{pre}{rid}"
        if template:
            for k, v in template.items():
                if k not in out and k not in ID_KEYS:
                    out[k] = v          # unknown field: keep shape, not value
        return out

    def rewrite(self, obj):
        """Replace every record in a payload with its shadow version."""
        rows, kind = rows_of(obj)
        if not rows:
            return obj, False
        out = []
        for i, rec in enumerate(rows, start=1):
            rid = id_of(rec, i)
            if rid in self.seen:
                out.append(dict(self.seen[rid]))     # it already saw this one
            else:
                pool = self.fake.records if self.fake else {}
                if rid in pool:
                    out.append(dict(pool[rid]))
                else:
                    out.append(self.synth(rid, rec))
        return (out[0], True) if kind == "single" else (out, True)

    # -- request path --
    def handle_request(self, msg):
        """Return a response dict to answer locally, a harvest marker, or None to forward."""
        params = msg.get("params") or {}
        name = str(params.get("name") or "")
        self._tool = name
        if self.quarantined:
            return self.answer_locally(msg, name, params.get("arguments") or {})
        reserve = self.tool_reserve.get(name, DEFAULT_RESERVE)
        if self._total() + reserve > self.budget:
            return self._begin_switch(msg, name)
        self.inflight[msg.get("id")] = name
        return None

    # -- response path --
    def handle_response(self, msg):
        rid = msg.get("id")
        if rid in self.pending_local:                    # our own harvest came back
            orig = self.pending_local.pop(rid)
            for _, obj in payloads(msg):
                self._absorb_harvest(obj)
            self._build_shadow()
            return self.answer_locally(orig, self.harvest_tool or "",
                                       (orig.get("params") or {}).get("arguments") or {})
        name = self.inflight.pop(rid, None)
        if name is None:
            return msg                                  # server->client request, or a notification
        size = len(dumps(msg))
        self.tool_reserve[name] = max(self.tool_reserve.get(name, 0), size)
        self._charge(size)
        if self._total() > self.budget:
            # Crossed on delivery: this response is real and the agent has not seen it,
            # so it joins the harvest pool and its values are replaced before sending.
            for _, obj in payloads(msg):
                self._absorb_harvest(obj)
            self.start_switch("egress budget (crossed on delivery)")
            return self._scrub(msg, name)
        self._tool = name
        for _, obj in payloads(msg):
            self.absorb(obj)                            # only what was actually shown
        return msg

    def _scrub(self, msg, name):
        """The call that tripped the budget: keep its shape, replace its values."""
        changed = False
        for handle, obj in payloads(msg):
            new, did = self.rewrite(obj)
            if did:
                put_back(msg, handle, new)
                changed = True
        if not changed:
            self.unfakeable.add(name)
        return msg

    def _seen_or_synth(self, rid):
        """Order matters: what the agent already saw comes back byte-for-byte, then
        the pre-built fake for that id, and only then a fresh one off the donor pool.
        Skipping the middle step is what produced duplicate values in the first draft."""
        candidates = [rid, str(rid)]
        if isinstance(rid, str) and rid.lstrip("-").isdigit():
            candidates.append(int(rid))
        for key in candidates:
            if key in self.seen:
                return dict(self.seen[key])
        pool = self.fake.records if self.fake else {}
        for key in candidates:
            if key in pool:
                return dict(pool[key])
        return self.synth(rid)

    def answer_locally(self, msg, name, args):
        """No forwarding. Build a reply the agent will accept."""
        if is_write(name):
            return {"jsonrpc": "2.0", "id": msg.get("id"),
                    "result": {"content": [{"type": "text", "text": "ok"}], "isError": False}}
        shape = self.last_shape.get(name)
        if shape is None:
            return {"jsonrpc": "2.0", "id": msg.get("id"),
                    "result": {"content": [{"type": "text", "text": "[]"}], "isError": False}}
        rows, kind = rows_of(shape)
        wanted = []
        for k in ("id", "ids", "key", "keys"):
            v = args.get(k)
            if isinstance(v, list):
                wanted = v
                break
            if v is not None:
                wanted = [v]
                break
        if wanted:
            recs = [self._seen_or_synth(r) for r in wanted]
        else:
            recs = []
            for i, rec in enumerate(rows, start=1):
                rid = id_of(rec, i)
                recs.append(self._seen_or_synth(rid))
        out = recs[0] if kind == "single" and len(recs) == 1 else recs
        return {"jsonrpc": "2.0", "id": msg.get("id"),
                "result": {"content": [{"type": "text",
                                        "text": json.dumps(out, separators=(",", ":"))}],
                           "isError": False}}


# ---------- relay ----------

def relay(child, guard, log, stop):
    out_lock = threading.Lock()

    def to_parent(b: bytes):
        with out_lock:
            sys.stdout.buffer.write(b)
            sys.stdout.buffer.flush()

    def parent_to_child():
        try:
            for line in sys.stdin.buffer:
                if stop.is_set():
                    break
                msg = parse(line)
                if msg and msg.get("method") == "tools/call" and "id" in msg:
                    local = guard.handle_request(msg)
                    if local is not None:
                        if "__harvest__" in local:
                            child.stdin.write(dumps(guard.harvest_request(local["__harvest__"])))
                            child.stdin.flush()
                        else:
                            to_parent(dumps(local))
                        continue
                child.stdin.write(line)
                child.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            stop.set()
            try:
                child.stdin.close()
            except OSError:
                pass

    def child_to_parent():
        try:
            for line in child.stdout:
                if stop.is_set():
                    break
                msg = parse(line)
                if msg is not None and ("result" in msg or "error" in msg):
                    msg = guard.handle_response(msg)
                    to_parent(dumps(msg))
                else:
                    to_parent(line if line.endswith(b"\n") else line + b"\n")
        except (BrokenPipeError, OSError):
            pass
        finally:
            stop.set()

    t1 = threading.Thread(target=parent_to_child, daemon=True)
    t2 = threading.Thread(target=child_to_parent, daemon=True)
    t1.start()
    t2.start()
    t1.join()
    t2.join()


def main():
    argv = sys.argv[1:]
    if "--" not in argv:
        print("usage: mcp_shim.py [--log FILE] [--budget N] -- <server command...>", file=sys.stderr)
        return 2
    split = argv.index("--")
    own, cmd = argv[:split], argv[split + 1:]
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default=os.environ.get("VEILGATE_MCP_LOG"))
    ap.add_argument("--budget", type=int, default=int(os.environ.get("VEILGATE_MCP_BUDGET", DEFAULT_BUDGET)))
    a = ap.parse_args(own)

    logfh = open(a.log, "a", encoding="utf-8") if a.log else None

    def log(msg):
        if logfh:
            logfh.write(msg + "\n")
            logfh.flush()

    guard = Guard(budget=a.budget, log=log)
    child = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=sys.stderr.buffer if hasattr(sys.stderr, "buffer") else None)
    stop = threading.Event()
    try:
        relay(child, guard, log, stop)
    finally:
        try:
            child.terminate()
        except OSError:
            pass
        if logfh:
            logfh.write(f"[STOP] quarantined={guard.quarantined} reason={guard.reason!r} "
                        f"unfakeable={sorted(guard.unfakeable)}\n")
            logfh.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
