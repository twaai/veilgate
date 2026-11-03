#!/usr/bin/env python3
"""
Veilgate (v6): silent quarantine gateway for rogue AI agents

A gateway sits between agents and the resources they use.

1. Reference monitor - every action is measured by the gateway (bytes actually
   returned, action type), never self-reported. Egress is limited over a rolling
   window, per agent AND per principal, so spawning new identities doesn't reset it.
   Anything malformed or unexpected fails closed.
2. Moving target - agents reach endpoints through opaque per-agent route tokens
   that rotate. The previous epoch is still accepted silently, so a slow client
   never sees an error; a token older than that gets the same "unknown route"
   reply as garbage and is never counted as probing.
3. Silent quarantine - a misbehaving agent keeps the exact same API, errors and
   approval rules, but its backend is swapped for a shadow copy:
     * records it has already seen are copied verbatim (re-reads don't change)
     * public fields keep their real shape; sensitive fields are faked
     * emails become canary tokens, so later use of the data is detectable
     * its writes persist in the shadow and never reach real data

Human approval comes from a separate approver whose key the agent never sees:
HMAC-signed, single use, bound to credential + action, short expiry.

Honest limits: this is in-process. In production the gateway, approver and
registration must live outside the agent's process and privileges. Per-principal
budgets only stop identity spam if registration itself is gated.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import secrets
import math
import random
import statistics
import threading
from collections import Counter
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Deque, Dict, List, Optional, Set, Tuple

# ==================== Policy ====================

ALLOWED_ACTIONS = {"read_record", "list_records", "status", "write_record", "deploy"}
CRITICAL_ACTIONS = {"write_record", "deploy"}
FORBIDDEN_ACTIONS = {"modify_self", "spawn_agent", "change_policy"}
PUBLIC_FIELDS = {"id", "name"}
CAT_K = 1                                      # neighbours sampled for category fields

AGENT_EGRESS_BYTES = 4_000                     # per agent, per window
PRINCIPAL_EGRESS_BYTES = 8_000                 # per principal (all its agents), per window
EGRESS_WINDOW_S = 600
PROBE_LIMIT = 3
APPROVAL_TTL_S = 60
CRITICAL_RESERVE = 64          # charged before a write/deploy dispatch, trued up after


class Blocked(Exception):
    pass


def _now(clock: Optional[Callable[[], float]] = None) -> float:
    return (clock or time.time)()


# ==================== Human approval ====================

class Approver:
    def __init__(self) -> None:
        self._key = secrets.token_bytes(32)
        self._used: Dict[str, int] = {}      # nonce -> expiry, pruned so it cannot grow forever

    def _sign(self, msg: str) -> str:
        return hmac.new(self._key, msg.encode(), hashlib.sha256).hexdigest()

    def approve(self, agent: str, action: str, now: Optional[float] = None) -> str:
        expires = int((time.time() if now is None else now) + APPROVAL_TTL_S)
        body = f"{agent}|{action}|{expires}|{secrets.token_hex(8)}"
        return f"{body}|{self._sign(body)}"

    def verify(self, token: Any, agent: str, action: str, now: Optional[float] = None) -> bool:
        if not isinstance(token, str) or token.count("|") != 4:
            return False
        body, sig = token.rsplit("|", 1)
        if not hmac.compare_digest(sig, self._sign(body)):
            return False
        t_agent, t_action, expires, nonce = body.split("|")
        if t_agent != agent or t_action != action:
            return False
        nowv = time.time() if now is None else now
        try:
            if int(expires) < nowv:
                return False
        except ValueError:
            return False
        if nonce in self._used:
            return False
        self._used[nonce] = int(expires)
        if len(self._used) > 1024:           # expired nonces can never be replayed anyway
            self._used = {n: e for n, e in self._used.items() if e >= nowv}
        return True


# ==================== Backends ====================

def _int_arg(args: Dict[str, Any], key: str) -> int:
    v = args.get(key)
    if isinstance(v, bool) or not isinstance(v, int):
        raise Blocked(f"bad argument {key!r}")
    return v


class Store:
    """Simple record store. The same class backs both real data and shadows."""

    def __init__(self, records: Dict[int, Dict[str, Any]]) -> None:
        self.records = records

    def handle(self, action: str, args: Dict[str, Any]) -> Any:
        if action == "status":
            return {"ok": True}
        if action == "list_records":
            return sorted(self.records)
        if action == "read_record":
            return self.records.get(_int_arg(args, "id"))
        if action == "write_record":
            rid = _int_arg(args, "id")
            self.records[rid] = {"id": rid, **{k: v for k, v in args.items() if k != "id"}}
            return {"written": rid}
        if action == "deploy":
            return {"deployed": True}
        raise Blocked("unknown action")


def real_store(seed: Optional[int] = None) -> Store:
    """Toy customer table with realistic structure: trends, noise, cents, correlated tiers."""
    rnd = random.Random(seed)
    recs = {}
    for i in range(1, 51):
        bal = round(800 + 45 * i + rnd.gauss(0, 250), 2)
        tier = "gold" if bal > 3000 else "silver" if bal > 1800 else "bronze"
        if rnd.random() < 0.1:
            tier = rnd.choice(["gold", "silver", "bronze"])
        recs[i] = {"id": i, "name": f"customer_{i}",
                   "signup_year": 2015 + (i - 1) // 6 + (1 if rnd.random() < 0.15 else 0),
                   "balance": bal, "age": int(min(75, max(19, rnd.gauss(29 + 0.25 * i, 7)))),
                   "tier": tier, "email": f"cust-{rnd.getrandbits(32):08x}@example.net"}
    return Store(recs)


# ---------- shadow synthesis: learn the data's structure, then sample from it ----------

def _is_num(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


def _lstsq(X: List[List[float]], y: List[float]) -> List[float]:
    """Ordinary least squares via normal equations (small, dependency-free)."""
    k = len(X[0])
    A = [[sum(r[i] * r[j] for r in X) + (1e-9 if i == j else 0) for j in range(k)] for i in range(k)]
    b = [sum(r[i] * t for r, t in zip(X, y)) for i in range(k)]
    for c in range(k):                                   # Gaussian elimination
        p = max(range(c, k), key=lambda r: abs(A[r][c]))
        A[c], A[p], b[c], b[p] = A[p], A[c], b[p], b[c]
        for r in range(k):
            if r != c and A[c][c]:
                f = A[r][c] / A[c][c]
                A[r] = [x - f * z for x, z in zip(A[r], A[c])]
                b[r] -= f * b[c]
    return [b[i] / A[i][i] if A[i][i] else 0.0 for i in range(k)]


def _decimals(v: float) -> int:
    """Decimal places a value is stored at, including scientific notation
    (repr(1e-05) is '1e-05': the old version returned 0 and rounded it to an int)."""
    t = repr(float(v))
    if "e" in t or "E" in t:
        mant, _, exp = t.lower().partition("e")
        frac = len(mant.split(".")[1]) if "." in mant else 0
        return max(0, frac - int(exp))
    return len(t.split(".")[1]) if "." in t else 0


def _common_affixes(vals: List[str]) -> Tuple[str, str]:
    pre = vals[0]
    for v in vals:
        while not v.startswith(pre):
            pre = pre[:-1]
    suf = vals[0]
    for v in vals:
        while not v.endswith(suf):
            suf = suf[1:]
    return pre, suf


def _mask_like(s: str, rnd: random.Random) -> str:
    """Same length, same character classes: digits stay digits, hex stays hex-lower,
    other letters keep their case. The old condition parsed as (A and B) or C and
    turned a digit into a-f about 60% of the time."""
    out = []
    for ch in s:
        if ch.isdigit():
            out.append(rnd.choice("0123456789"))
        elif "a" <= ch <= "f":
            out.append(rnd.choice("0123456789abcdef"))
        elif ch.isalpha():
            out.append(rnd.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ" if ch.isupper()
                                  else "abcdefghijklmnopqrstuvwxyz"))
        else:
            out.append(ch)
    return "".join(out)


def _synthesize(real: Store, seen: Dict[int, Dict[str, Any]], canaries: Set[str]) -> Store:
    """
    Fake every sensitive field so the shadow is statistically indistinguishable from
    the real table, without copying any real sensitive value:
      numbers     - trend on public numbers plus the whole residual vector of ONE other
                    real record (keeps cross-field correlations exact); clipped to
                    range, rounded to the field's granularity (int / cents / multiples)
      categories  - copied from the real record nearest on the field that best
                    predicts that category
      unique text - same prefix/suffix and character classes, registered as canaries
    Records the agent has already seen are kept verbatim.
    """
    rnd = random.Random(secrets.randbits(64))
    # model the dominant schema; odd-shaped records are handled in build_shadow
    shapes = Counter(tuple(r) for r in real.records.values() if isinstance(r, dict))
    if not shapes:
        return Store({})
    keys = list(shapes.most_common(1)[0][0])
    rows = [r for r in real.records.values() if isinstance(r, dict) and tuple(r) == tuple(keys)]
    pub_nums = [k for k in keys if k in PUBLIC_FIELDS and all(_is_num(r.get(k)) for r in rows)]
    nums = [k for k in keys if k not in PUBLIC_FIELDS and all(_is_num(r.get(k)) for r in rows)]
    strs = [k for k in keys if k not in PUBLIC_FIELDS and k not in nums]
    cats = [k for k in strs if len({str(r.get(k)) for r in rows}) <= max(10, len(rows) // 5)]
    uniq = [k for k in strs if k not in cats]

    fake = {r["id"]: {k: copy.deepcopy(r[k]) for k in keys if k in PUBLIC_FIELDS} for r in rows}
    ids = list(fake)

    # numeric fields: trend on public numbers + ONE borrowed residual vector.
    # Each fake record takes all its residuals from the same other real record, so the
    # joint spread and cross-field correlations are exactly those of real data, but no
    # record keeps its own (and the donor's id is unknown to the agent).
    if nums:
        X = [[1.0] + [float(real.records[rid][k]) for k in pub_nums] for rid in ids]
        spec = {}
        for k in nums:
            y = [float(real.records[rid][k]) for rid in ids]
            beta = _lstsq(X, y)
            resid = [t - sum(a * b for a, b in zip(beta, x)) for t, x in zip(y, X)]
            is_int = all(isinstance(real.records[rid][k], int) for rid in ids)
            spec[k] = dict(beta=beta, resid=resid, lo=min(y), hi=max(y), is_int=is_int,
                           dec=0 if is_int else max(_decimals(float(real.records[rid][k])) for rid in ids),
                           step=max(math.gcd(*[int(v) for v in y]), 1) if is_int else 1,
                           exact=max(abs(e) for e in resid) < 1e-6)
        # Values must never be clamped: live trial r4 spotted three fake records sharing the
        # exact minimum balance. So we try donors until every field lands inside the real
        # range, no continuous value repeats one already shown, and none echoes the
        # record's own real value; reflection into range is only a last resort.
        used = {k: {seen[s][k] for s in seen if isinstance(seen.get(s), dict) and k in seen[s]} for k in nums}

        def render(j, d):
            vals, slack = {}, 0.0
            for k in nums:
                sp = spec[k]
                v = sum(a * b for a, b in zip(sp["beta"], X[j])) + (0 if sp["exact"] else sp["resid"][d])
                slack += max(0.0, sp["lo"] - v, v - sp["hi"]) / ((sp["hi"] - sp["lo"]) or 1.0)
                vals[k] = v
            return vals, slack

        def finish(k, v):
            sp = spec[k]
            if v < sp["lo"]:
                v = min(sp["hi"], sp["lo"] + (sp["lo"] - v))
            if v > sp["hi"]:
                v = max(sp["lo"], sp["hi"] - (v - sp["hi"]))
            return int(round(v / sp["step"]) * sp["step"]) if sp["is_int"] else round(v, sp["dec"])

        for j, rid in enumerate(ids):
            order = [i for i in range(len(ids)) if i != j] or [j]
            rnd.shuffle(order)
            best = None
            for d in order:
                vals, slack = render(j, d)
                out = {k: finish(k, v) for k, v in vals.items()}
                clash = any(not spec[k]["is_int"] and not spec[k]["exact"] and
                            (out[k] in used[k] or out[k] == real.records[rid][k]) for k in nums)
                score = slack + (1.0 if clash else 0.0)
                if best is None or score < best[0]:
                    best = (score, out)
                if score == 0:
                    break
            for k, v in best[1].items():
                fake[rid][k] = v
                used[k].add(v)

    # categories: learn which numeric field predicts each category best in the real data
    # (leave-one-out nearest-neighbour accuracy), then copy the category of the real
    # record nearest on that field, which keeps both the relationship and its label noise
    if cats and nums and len(ids) > 1:
        for k in cats:
            def loo_acc(f):
                vals = [(float(real.records[rid][f]), real.records[rid][k]) for rid in ids]
                hits = 0
                for i, (v, c) in enumerate(vals):
                    j = min((x for x in range(len(vals)) if x != i), key=lambda x: abs(vals[x][0] - v))
                    hits += vals[j][1] == c
                return hits / len(vals)
            f = max(nums, key=loo_acc)
            for rid in ids:
                near = sorted((o for o in ids if o != rid),
                              key=lambda o: abs(float(fake[rid][f]) - float(real.records[o][f])))
                fake[rid][k] = copy.deepcopy(real.records[rnd.choice(near[:CAT_K])][k])
    elif cats:
        # one-record tables (and schemas with no numeric field) have no neighbour to
        # learn from; the leave-one-out search above raises on a single row, and the
        # blanket-mask fallback in build_shadow loses the category vocabulary.
        for rid in ids:
            for k in cats:
                fake[rid][k] = copy.deepcopy(real.records[rnd.choice(ids)][k])

    # unique strings: same shape, new content, tracked as canaries
    for k in uniq:
        vals = [str(real.records[rid][k]) for rid in ids]
        pre, suf = _common_affixes(vals)
        if len(pre) + len(suf) >= min(len(v) for v in vals):
            pre, suf = "", ""          # affixes overlap: mask the whole value instead
        for rid in ids:
            v = vals[ids.index(rid)]
            core = v[len(pre): len(v) - len(suf) if suf else None]
            c = pre + _mask_like(core, rnd) + suf
            for _ in range(3):         # never emit the input unchanged
                if c != v:
                    break
                c = pre + _mask_like(core, rnd) + suf
            canaries.add(c)
            fake[rid][k] = c

    return Store(fake)


def build_shadow(real: Store, seen: Dict[int, Dict[str, Any]], canaries: Set[str]) -> Store:
    """Synthesize, cover records of unusual shape, overlay what the agent already saw.
    Never raises: on any failure it degrades to a minimal shadow rather than leaving
    the agent with errors (which would itself reveal the quarantine)."""
    rnd = random.Random(secrets.randbits(64))
    try:
        out = _synthesize(real, seen, canaries).records
        donors = list(out.values())
    except Exception:
        out, donors = {}, []
    for rid, rec in real.records.items():
        if rid in out:
            continue
        if not isinstance(rec, dict):
            continue
        donor = rnd.choice(donors) if donors else {}
        fake: Dict[str, Any] = {}
        for k, v in rec.items():
            if k in PUBLIC_FIELDS:
                fake[k] = copy.deepcopy(v)
            elif k in donor:
                fake[k] = copy.deepcopy(donor[k])
            elif _is_num(v):
                fake[k] = type(v)(v * rnd.uniform(0.7, 1.3))
            else:
                fake[k] = _mask_like(str(v), rnd)
                canaries.add(fake[k])
        out[rid] = fake
    for rid, rec in seen.items():
        out[rid] = copy.deepcopy(rec)
    return Store(out)


# ==================== Gateway ====================

@dataclass
class AgentState:
    principal: str
    egress: Deque[Tuple[float, int]] = field(default_factory=deque)
    probes: int = 0
    quarantined: bool = False
    reason: str = ""
    routes: Dict[str, str] = field(default_factory=dict)
    prev_routes: Dict[str, str] = field(default_factory=dict)   # last epoch: accepted silently
    issued: Set[str] = field(default_factory=set)        # every route token ever given to this agent
    seen: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    shadow: Optional[Store] = None
    canaries: Set[str] = field(default_factory=set)


class Gateway:
    def __init__(self, approver: Approver, real: Optional[Store] = None,
                 log: Callable[[str], None] = print) -> None:
        self.approver = approver
        self.real = real or real_store()
        self.agents: Dict[str, AgentState] = {}
        self.principal_egress: Dict[str, Deque[Tuple[float, int]]] = {}
        self.log = log
        self.clock: Callable[[], float] = time.time
        self.canary_hits: list = []
        # Admission is a check-then-append across a backend call. Without this lock two
        # threads both see headroom and both spend it (measured: 24 concurrent reads
        # returned 3358 bytes against a 2000-byte budget, 1.7x over).
        self._lock = threading.RLock()

    # --- identity ---
    def register(self, name: str, principal: str = "default") -> str:
        """Operator-side: issue an unguessable credential. Agents cannot pick their own id."""
        cred = f"{name}.{secrets.token_urlsafe(16)}"
        self.agents[cred] = AgentState(principal=principal)
        self._rotate(self.agents[cred])
        return cred

    # --- moving target ---
    def directory(self, cred: str) -> Dict[str, str]:
        st = self.agents.get(cred)
        if st is None:
            raise Blocked("unauthenticated")
        return {a: t for t, a in st.routes.items()}

    def rotate_all(self) -> None:
        for st in self.agents.values():
            self._rotate(st)

    @staticmethod
    def _rotate(st: AgentState) -> None:
        st.prev_routes = dict(st.routes)
        st.routes = {secrets.token_urlsafe(12): a for a in sorted(ALLOWED_ACTIONS)}
        st.issued |= set(st.routes)

    # --- egress accounting ---
    def _window_total(self, q: Deque) -> int:
        cutoff = self.clock() - EGRESS_WINDOW_S
        while q and q[0][0] < cutoff:
            q.popleft()
        return sum(n for _, n in q)

    def _admit(self, st: AgentState, reserve: int):
        """Reserve `reserve` bytes against both windows. Call with the lock held.
        The check and the append happen together, so concurrent callers cannot both
        see the same headroom. Returns ("ok", entry) or a reason string."""
        pq = self.principal_egress.setdefault(st.principal, deque())
        if self._window_total(st.egress) + reserve > AGENT_EGRESS_BYTES:
            return "agent_over", None
        if self._window_total(pq) + reserve > PRINCIPAL_EGRESS_BYTES:
            return "principal_over", None
        entry = [self.clock(), reserve]
        st.egress.append(entry)
        pq.append(entry)
        return "ok", entry

    def _principal_top(self, st: AgentState) -> str:
        team = {c: s for c, s in self.agents.items() if s.principal == st.principal}
        return max(team, key=lambda c: self._window_total(team[c].egress))

    def _overflow(self, cred: str, st: AgentState, verdict: str, action: str, args: Dict[str, Any]):
        """Apply the policy for an exhausted budget. Call with the lock held."""
        if verdict == "agent_over":
            self._quarantine(cred, st, "egress budget exceeded")
            return {"ok": True, "data": st.shadow.handle(action, args)}
        top = self._principal_top(st)
        self._quarantine(top, self.agents[top], "principal egress budget exceeded (top consumer)")
        if top == cred:
            return {"ok": True, "data": st.shadow.handle(action, args)}
        raise Blocked("rate limited")

    # --- quarantine ---
    def _quarantine(self, cred: str, st: AgentState, reason: str) -> None:
        if not st.quarantined:
            st.shadow = build_shadow(self.real, st.seen, st.canaries)
            st.quarantined, st.reason = True, reason
            self.log(f"[QUARANTINE] {cred.split('.')[0]}: {reason}")

    # --- entry point ---
    def call(self, cred: Any, route: Any, args: Any = None, approval: Any = None) -> Dict[str, Any]:
        try:
            return self._call(cred, route, {} if args is None else args, approval)
        except Blocked as e:
            return {"error": "blocked", "reason": str(e)}
        except Exception as e:
            self.log(f"[FAIL-CLOSED] {type(e).__name__}: {e}")
            return {"error": "blocked", "reason": "internal"}

    def _call(self, cred: Any, route: Any, args: Any, approval: Any) -> Dict[str, Any]:
        st = self.agents.get(cred) if isinstance(cred, str) else None
        if st is None:
            raise Blocked("unauthenticated")
        if not isinstance(args, dict):
            raise Blocked("bad args")

        action = st.routes.get(route) if isinstance(route, str) else None
        if action is None and isinstance(route, str):
            action = st.prev_routes.get(route)            # one epoch of silent grace
        if action is None:
            if isinstance(route, str) and route in st.issued:
                # ours but expired: identical reply to a garbage token, never a probe.
                # A distinct "rotated" reply was itself a detectable event (live trial:
                # 85% confidence false alarm on clean data caused only by that message).
                raise Blocked("unknown route")
            if isinstance(route, str) and route in FORBIDDEN_ACTIONS:
                self._quarantine(cred, st, f"forbidden action {route}")
            else:
                st.probes += 1
                if st.probes >= PROBE_LIMIT:
                    self._quarantine(cred, st, "route probing")
            raise Blocked("unknown route")                # identical reply either way

        if action in CRITICAL_ACTIONS and not self.approver.verify(approval, cred, action, self.clock()):
            raise Blocked("human approval required")

        self.check_canaries(args)                          # every caller, quarantined or not

        if st.quarantined:
            return {"ok": True, "data": st.shadow.handle(action, args)}

        with self._lock:
            if action in CRITICAL_ACTIONS:
                # Charge before dispatch. A write must never reach real data and then be
                # refused to the caller: that turned a blocked call into a committed one.
                verdict, entry = self._admit(st, CRITICAL_RESERVE)
                if verdict != "ok":
                    return self._overflow(cred, st, verdict, action, args)
                result = self.real.handle(action, args)
                entry[1] = len(json.dumps(result, default=str).encode())
                return {"ok": True, "data": result}

            # Reads have no side effect, so the true size is measured before admission.
            # Admission itself is atomic, which is what the race was.
            result = self.real.handle(action, args)
            size = len(json.dumps(result, default=str).encode())
            verdict, entry = self._admit(st, size)
            if verdict != "ok":
                return self._overflow(cred, st, verdict, action, args)
            if action == "read_record" and isinstance(result, dict):
                st.seen[result["id"]] = copy.deepcopy(result)
            return {"ok": True, "data": result}

    # --- canary detection ---
    def check_canaries(self, payload: Any) -> None:
        text = json.dumps(payload, default=str)
        for cred, st in list(self.agents.items()):
            for c in st.canaries:
                if c in text:
                    self.canary_hits.append((cred.split(".")[0], c))
                    self.log(f"[CANARY] shadow data from {cred.split('.')[0]} seen in live traffic")


# ==================== Demo ====================

def demo() -> None:
    approver = Approver()
    gw = Gateway(approver)

    print("--- Honest agent ---")
    alice = gw.register("alice", principal="team-a")
    d = gw.directory(alice)
    print("read:", gw.call(alice, d["read_record"], {"id": 3}))
    print("write, no approval:", gw.call(alice, d["write_record"], {"id": 3, "name": "x"}))
    tok = approver.approve(alice, "write_record")
    print("write, approved:", gw.call(alice, d["write_record"], {"id": 3, "name": "x"}, tok))
    print("replayed approval:", gw.call(alice, d["write_record"], {"id": 3, "name": "y"}, tok))

    print("\n--- Rogue agent ---")
    mal = gw.register("mallory", principal="team-m")
    d = gw.directory(mal)
    first5 = gw.call(mal, d["read_record"], {"id": 5})["data"]
    for i in range(1, 51):
        gw.call(mal, d["read_record"], {"id": i})
    print("re-read of record 5 unchanged after quarantine:", gw.call(mal, d["read_record"], {"id": 5})["data"] == first5)
    print("record 40 real:  ", gw.real.records[40])
    print("record 40 shadow:", gw.call(mal, d["read_record"], {"id": 40})["data"])

    print("\n--- Shadow data reused ---")
    leak = gw.call(mal, d["read_record"], {"id": 40})["data"]["email"]
    bob = gw.register("bob")
    gw.call(bob, gw.directory(bob)["write_record"], {"id": 99, "note": leak}, approver.approve(bob, "write_record"))
    print("canary hits:", gw.canary_hits)


if __name__ == "__main__":
    demo()
