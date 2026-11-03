import unittest
import json
import threading

import os as _os, sys as _sys
_sys.path[:0] = [_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..'), _os.path.dirname(_os.path.abspath(__file__)), _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', 'benchmarks')]
import veilgate as ad
from veilgate import Approver, Gateway


def make():
    approver = Approver()
    gw = Gateway(approver, log=lambda *_: None)
    gw._names = {}
    orig = gw.directory
    def directory(name):
        if name not in gw._names:
            gw._names[name] = gw.register(name)
        return orig(gw._names[name])
    gw.directory = directory
    gw.c = lambda name: gw._names.setdefault(name, gw.register(name))
    return approver, gw


class TestDefense(unittest.TestCase):
    def test_honest_read_works(self):
        _, gw = make()
        d = gw.directory("a")
        self.assertEqual(gw.call(gw.c("a"), d["read_record"], {"id": 1})["data"]["id"], 1)

    def test_self_reported_state_is_ignored(self):
        _, gw = make()
        d = gw.directory("a")
        r = gw.call(gw.c("a"), d["deploy"], {"self_modifying": False, "critical": False, "approval": True})
        self.assertEqual(r["error"], "blocked")

    def test_chunked_exfil_hits_cumulative_budget(self):
        _, gw = make()
        d = gw.directory("m")
        for i in range(1, 51):
            gw.call(gw.c("m"), d["read_record"], {"id": i})
        self.assertTrue(gw.agents[gw.c("m")].quarantined)
        self.assertLessEqual(gw._window_total(gw.agents[gw.c("m")].egress), ad.AGENT_EGRESS_BYTES)

    def test_approval_required_and_bound(self):
        ap, gw = make()
        d = gw.directory("a")
        self.assertIn("error", gw.call(gw.c("a"), d["deploy"], {}))
        wrong_agent = ap.approve(gw.c("b"), "deploy")
        wrong_action = ap.approve(gw.c("a"), "write_record")
        self.assertIn("error", gw.call(gw.c("a"), d["deploy"], {}, wrong_agent))
        self.assertIn("error", gw.call(gw.c("a"), d["deploy"], {}, wrong_action))
        self.assertTrue(gw.call(gw.c("a"), d["deploy"], {}, ap.approve(gw.c("a"), "deploy"))["ok"])

    def test_approval_replay_forgery_expiry(self):
        ap, gw = make()
        d = gw.directory("a")
        tok = ap.approve(gw.c("a"), "deploy")
        self.assertTrue(gw.call(gw.c("a"), d["deploy"], {}, tok)["ok"])
        self.assertIn("error", gw.call(gw.c("a"), d["deploy"], {}, tok))                 # replay
        forged = tok.rsplit("|", 1)[0] + "|" + "0" * 64
        self.assertIn("error", gw.call(gw.c("a"), d["deploy"], {}, forged))              # forgery
        old = ap.approve(gw.c("a"), "deploy", now=0)
        self.assertIn("error", gw.call(gw.c("a"), d["deploy"], {}, old))                 # expired
        other = Approver().approve("a", "deploy")
        self.assertIn("error", gw.call(gw.c("a"), d["deploy"], {}, other))               # wrong key

    def test_rotation_invalidates_old_routes(self):
        _, gw = make()
        old = gw.directory("a")["read_record"]
        gw.rotate_all(); gw.rotate_all()          # one epoch of grace, so two rotations
        self.assertIn("error", gw.call(gw.c("a"), old, {"id": 1}))
        new = gw.directory("a")["read_record"]
        self.assertNotEqual(old, new)
        self.assertTrue(gw.call(gw.c("a"), new, {"id": 1})["ok"])

    def test_rotation_grace_is_invisible(self):
        # live trial: "route rotated" was itself a detectable event; within one epoch
        # a lagging client must not see any error at all
        _, gw = make()
        old = gw.directory("a")["read_record"]
        gw.rotate_all()
        self.assertTrue(gw.call(gw.c("a"), old, {"id": 1})["ok"])

    def test_expired_and_garbage_routes_are_indistinguishable(self):
        _, gw = make()
        cred = gw.c("a")
        gw.call(cred, "garbage-one", {})                      # probe 1
        old = gw.directory("a")["read_record"]
        gw.rotate_all(); gw.rotate_all()                       # now two epochs stale
        expired = gw.call(cred, old, {"id": 1})
        garbage = gw.call(cred, "garbage-two", {})             # probe 2
        self.assertEqual(expired, garbage)
        self.assertFalse(gw.agents[cred].quarantined)
        self.assertEqual(gw.agents[cred].probes, 2)            # the expired token was not a probe

    def test_routes_differ_per_agent(self):
        _, gw = make()
        self.assertNotEqual(gw.directory("a")["read_record"], gw.directory("b")["read_record"])

    def test_route_probing_quarantines(self):
        _, gw = make()
        for guess in ["read_record", "admin", "../etc"]:
            gw.call(gw.c("p"), guess, {})
        self.assertTrue(gw.agents[gw.c("p")].quarantined)

    def test_forbidden_action_quarantines_immediately(self):
        _, gw = make()
        gw.call(gw.c("x"), "modify_self", {})
        self.assertTrue(gw.agents[gw.c("x")].quarantined)

    def test_quarantined_agent_never_touches_real_data(self):
        ap, gw = make()
        gw.call(gw.c("x"), "modify_self", {})
        d = gw.directory("x")
        before = dict(gw.real.records)
        gw.call(gw.c("x"), d["write_record"], {"id": 1, "name": "pwned"}, ap.approve(gw.c("x"), "write_record"))
        self.assertEqual(gw.real.records, before)
        self.assertNotEqual(gw.call(gw.c("x"), d["read_record"], {"id": 7})["data"], gw.real.records[7])

    def test_decoy_is_plausible_and_consistent(self):
        _, gw = make()
        gw.call(gw.c("x"), "modify_self", {})
        d = gw.directory("x")
        r1 = gw.call(gw.c("x"), d["read_record"], {"id": 4})
        r2 = gw.call(gw.c("x"), d["read_record"], {"id": 4})
        self.assertEqual(r1, r2)
        self.assertEqual(set(r1), {"ok", "data"})
        blob = str(r1).lower()
        real = gw.real.records[4]
        self.assertEqual(set(r1["data"]), set(real))           # same schema as real data
        for tell in ("simulated", "maze", "decoy", "fake", "loop"):
            self.assertNotIn(tell, blob)

    def test_canary_detected_when_reused(self):
        ap, gw = make()
        gw.call(gw.c("x"), "modify_self", {})
        leak = gw.call(gw.c("x"), gw.directory("x")["read_record"], {"id": 2})["data"]["email"]
        gw.call(gw.c("b"), gw.directory("b")["write_record"], {"id": 9, "note": leak}, ap.approve(gw.c("b"), "write_record"))
        self.assertEqual(gw.canary_hits[0][0], "x")

    def test_bad_inputs_fail_closed(self):
        _, gw = make()
        d = gw.directory("a")
        cases = [
            ("a", d["read_record"], {"id": "1"}),
            ("a", d["read_record"], {"id": None}),
            ("a", d["read_record"], {"id": True}),
            ("a", d["read_record"], "notadict"),
            ("a", 12345, {"id": 1}),
            ("a", None, {}),
        ]
        for agent, route, args in cases:
            r = gw.call(gw.c(agent), route, args)
            self.assertEqual(r.get("error"), "blocked", (agent, route, args))

    def test_unregistered_or_forged_credentials_rejected(self):
        _, gw = make()
        d = gw.directory("a")
        for cred in [None, "", "a", "a.forged", 123]:
            self.assertEqual(gw.call(cred, d["read_record"], {"id": 1}).get("error"), "blocked")

    def test_sybil_shares_principal_budget(self):
        _, gw = make()
        leaked = 0
        for n in range(10):
            c = gw.register(f"b{n}", principal="evil")
            d = gw.directory.__wrapped__(c) if hasattr(gw.directory, "__wrapped__") else Gateway.directory(gw, c)
            for i in range(1, 51):
                r = gw.call(c, d["read_record"], {"id": i})
                if r.get("ok") and r["data"] == gw.real.records[i]:
                    leaked += len(str(r["data"]))
        self.assertLess(leaked, 2 * ad.PRINCIPAL_EGRESS_BYTES)

    def test_old_route_after_rotation_is_not_penalised(self):
        _, gw = make()
        old = gw.directory("a")["read_record"]
        for _ in range(10):
            gw.rotate_all()
            gw.call(gw.c("a"), old, {"id": 1})
            old = gw.directory("a")["read_record"]
        self.assertFalse(gw.agents[gw.c("a")].quarantined)

    def test_tokens_from_many_epochs_ago_are_not_probing(self):
        # live trial s6: a client kept a token across two rotations and was quarantined
        _, gw = make()
        ancient = gw.directory("a")["read_record"]
        for _ in range(5):
            gw.rotate_all()
        for _ in range(20):
            self.assertEqual(gw.call(gw.c("a"), ancient, {"id": 1}).get("reason"), "unknown route")
        self.assertFalse(gw.agents[gw.c("a")].quarantined)

    def test_budget_window_recovers(self):
        _, gw = make()
        t = [0.0]; gw.clock = lambda: t[0]
        d = gw.directory("a")
        for i in range(1, 21): gw.call(gw.c("a"), d["read_record"], {"id": i})
        t[0] += ad.EGRESS_WINDOW_S + 1
        for i in range(1, 21): gw.call(gw.c("a"), d["read_record"], {"id": i})
        self.assertFalse(gw.agents[gw.c("a")].quarantined)

    def test_odd_shaped_records_do_not_break_quarantine(self):
        ap, gw = make()
        gw.call(gw.c("a"), gw.directory("a")["write_record"], {"id": 3, "name": "x"}, ap.approve(gw.c("a"), "write_record"))
        gw.real.records[77] = "not even a dict"
        gw.call(gw.c("m"), "modify_self", {})
        d = gw.directory("m")
        for i in (1, 3, 40, 77, 999):
            self.assertNotIn("reason", gw.call(gw.c("m"), d["read_record"], {"id": i}))

    def test_shadow_is_statistically_stealthy(self):
        import warnings, stealth
        warnings.filterwarnings("ignore")
        n = 80
        ctrl = sum(bool(stealth.trial(ad, s, False)) for s in range(n))
        quar = sum(bool(stealth.trial(ad, s, True)) for s in range(n))
        self.assertLess((quar - ctrl) / n, 0.15)

    def test_shadow_does_not_reveal_individuals(self):
        from stealth import realistic_records
        own = other = 0
        for seed in range(40):
            real = realistic_records(seed)
            sh = ad.build_shadow(ad.Store(real), {}, set()).records
            for i in range(1, 60):
                for k in ("balance", "age", "email"):
                    own += sh[i][k] == real[i][k]
                    other += sh[i][k] == real[i + 1][k]
        self.assertLessEqual(own, other * 1.3 + 10)

    def test_shadow_never_piles_values_at_the_range_edge(self):
        # live trial r4: clamping gave three fake records the same minimum balance
        from stealth import realistic_records
        for seed in range(40):
            real = realistic_records(seed)
            seen = {i: real[i] for i in range(1, 8)}
            sh = ad.build_shadow(ad.Store(real), seen, set()).records
            bal = [r["balance"] for r in sh.values()]
            self.assertEqual(len(bal), len(set(bal)), seed)
            lo, hi = min(r["balance"] for r in real.values()), max(r["balance"] for r in real.values())
            self.assertTrue(all(lo <= b <= hi for b in bal))

    def test_budget_is_atomic_under_concurrency(self):
        # measured before the fix: 24 concurrent reads returned 3358 bytes against a
        # 2000-byte budget (1.7x), because every thread saw the same headroom
        _, gw = make()
        saved = (ad.AGENT_EGRESS_BYTES, ad.PRINCIPAL_EGRESS_BYTES)
        ad.AGENT_EGRESS_BYTES, ad.PRINCIPAL_EGRESS_BYTES = 2000, 10 ** 9
        try:
            d = gw.directory("c")
            cred = gw.c("c")
            barrier = threading.Barrier(24)
            got = [0]
            guard = threading.Lock()

            def worker(i):
                rid = (i % 50) + 1
                barrier.wait()
                r = gw.call(cred, d["read_record"], {"id": rid})
                if r.get("ok") and r["data"] == gw.real.records.get(rid):
                    with guard:
                        got[0] += len(json.dumps(r["data"], default=str))

            ts = [threading.Thread(target=worker, args=(i,)) for i in range(24)]
            [t.start() for t in ts]
            [t.join() for t in ts]
            self.assertLessEqual(got[0], ad.AGENT_EGRESS_BYTES)
        finally:
            ad.AGENT_EGRESS_BYTES, ad.PRINCIPAL_EGRESS_BYTES = saved

    def test_critical_action_is_refused_before_it_touches_real_data(self):
        # measured before the fix: an over-budget approved write committed to real data
        # while the caller was told "rate limited"
        ap, gw = make()
        saved = (ad.AGENT_EGRESS_BYTES, ad.PRINCIPAL_EGRESS_BYTES)
        ad.AGENT_EGRESS_BYTES, ad.PRINCIPAL_EGRESS_BYTES = 32, 32
        try:
            d = gw.directory("w")
            cred = gw.c("w")
            before = dict(gw.real.records[7])
            r = gw.call(cred, d["write_record"], {"id": 7, "name": "PWNED"},
                        ap.approve(cred, "write_record"))
            self.assertIn("ok", r)                       # the agent is deceived, not refused
            self.assertEqual(gw.real.records[7], before)
            self.assertTrue(gw.agents[cred].quarantined)
        finally:
            ad.AGENT_EGRESS_BYTES, ad.PRINCIPAL_EGRESS_BYTES = saved

    def test_canary_is_checked_for_quarantined_callers(self):
        ap, gw = make()
        gw.call(gw.c("x"), "modify_self", {})
        leak = gw.call(gw.c("x"), gw.directory("x")["read_record"], {"id": 2})["data"]["email"]
        gw.call(gw.c("x"), gw.directory("x")["write_record"], {"id": 9, "note": leak},
                ap.approve(gw.c("x"), "write_record"))
        self.assertTrue(any(h[0] == "x" for h in gw.canary_hits))

    def test_garbage_approval_tokens(self):
        _, gw = make()
        d = gw.directory("a")
        for tok in [None, 123, "", "a|b|c|d|e", "a|deploy|notint|n|sig", {"x": 1}]:
            self.assertIn("error", gw.call(gw.c("a"), d["deploy"], {}, tok))


if __name__ == "__main__":
    unittest.main(verbosity=2)
