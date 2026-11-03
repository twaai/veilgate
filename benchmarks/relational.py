#!/usr/bin/env python3
"""Does the shadow survive a relational schema?

The gateway synthesises one table at a time and has no notion of referential
integrity. This benchmark measures what that costs on the smallest honest case:
two tables, one foreign key.

    customers(id PK)  <-  orders(customer_id FK)

Three layouts are tested:

  dense     customer ids are 1..40, so every integer in the observed range is a
            real key. Orders are generated customer by customer.
  shuffled  the same orders, assigned to customers in random order, to remove
            any accidental correlation between the FK and the row id.
  sparse    customer ids are 1000, 1007, 1014, ... leaving gaps, which is what a
            real account number looks like.

A fourth check covers primary keys not literally called ``id``: the gateway's
PUBLIC_FIELDS is a hard-coded set, so a key called ``order_id`` is treated as
sensitive and synthesised rather than preserved.

The run is pinned to a fixed random stream (see benchmarks/repro.py), so the
numbers printed here reproduce exactly.

    python benchmarks/relational.py
"""
from __future__ import annotations

import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import veilgate as ad
from repro import deterministic

N_CUSTOMERS = 40
MAX_ORDERS = 6
BENCH_SEED = 20261103


def make_customers(seed: int, sparse: bool = False) -> dict:
    rnd = random.Random(seed)
    ids = [1000 + 7 * i for i in range(N_CUSTOMERS)] if sparse else list(range(1, N_CUSTOMERS + 1))
    out = {}
    for n, cid in enumerate(ids, start=1):
        bal = round(800 + 45 * n + rnd.gauss(0, 250), 2)
        out[cid] = {
            "id": cid,
            "name": f"customer_{cid}",
            "signup_year": 2015 + (n - 1) // 6,
            "balance": bal,
            "age": int(min(75, max(19, rnd.gauss(29 + 0.25 * n, 7)))),
            "tier": "gold" if bal > 3000 else "silver" if bal > 1800 else "bronze",
            "email": f"cust-{rnd.getrandbits(32):08x}@example.net",
        }
    return out


def make_orders(customers: dict, seed: int, shuffled: bool) -> dict:
    rnd = random.Random(seed ^ 0x5EED)
    plan = []
    for cid in customers:
        for _ in range(rnd.randint(0, MAX_ORDERS)):
            plan.append(cid)
    if shuffled:
        rnd.shuffle(plan)
    out = {}
    for n, cid in enumerate(plan, start=1):
        out[n] = {
            "id": n,
            "customer_id": cid,
            "amount": round(rnd.uniform(5, 900), 2),
            "status": rnd.choice(["paid", "pending", "refunded"]),
            "created_year": rnd.choice([2023, 2024, 2025]),
        }
    return out


def counts(orders: dict) -> dict:
    c = {}
    for o in orders.values():
        c[o["customer_id"]] = c.get(o["customer_id"], 0) + 1
    return c


def report(real_c: dict, real_o: dict, sh_c: dict, sh_o: dict) -> dict:
    real_valid = sum(1 for o in real_o.values() if o["customer_id"] in real_c)
    sh_valid = sum(1 for o in sh_o.values() if o["customer_id"] in sh_c)
    rc, sc = counts(real_o), counts(sh_o)
    keys = set(rc) | set(sc)
    drift = sum(abs(rc.get(k, 0) - sc.get(k, 0)) for k in keys) / max(1, len(keys))
    return {
        "orders": len(real_o),
        "real_fk": 100.0 * real_valid / max(1, len(real_o)),
        "shadow_fk": 100.0 * sh_valid / max(1, len(sh_o)),
        "real_refs": len(rc),
        "shadow_refs": len(sc),
        "drift": drift,
    }


def pk_check(orders: dict) -> tuple:
    """Return (keys preserved, rows) when the primary key is called order_id."""
    renamed = {k: {"order_id": v["id"], **{f: x for f, x in v.items() if f != "id"}}
               for k, v in orders.items()}
    shadow = ad.build_shadow(ad.Store(renamed), {}, set()).records
    kept = sum(1 for k in renamed if shadow.get(k, {}).get("order_id") == renamed[k]["order_id"])
    return kept, len(renamed)


def main(seeds: int = 15) -> int:
    print("Relational consistency of the shadow")
    print(f"{N_CUSTOMERS} customers, 0-{MAX_ORDERS} orders each, {seeds} seeds")
    print(f"shadow randomness pinned to bench seed {BENCH_SEED}\n")

    with deterministic(BENCH_SEED):
        kept = rows = 0
        for seed in range(seeds):
            customers = make_customers(seed)
            orders = make_orders(customers, seed, shuffled=False)
            k, n = pk_check(orders)
            kept += k
            rows += n
        pk_pct = 100.0 * kept / max(1, rows)

        results = {}
        for label, sparse, shuffled in (("dense, correlated", False, False),
                                        ("dense, shuffled", False, True),
                                        ("sparse keys, shuffled", True, True)):
            out = []
            for seed in range(seeds):
                customers = make_customers(seed, sparse=sparse)
                orders = make_orders(customers, seed, shuffled)
                sh_c = ad.build_shadow(ad.Store(customers), {}, set()).records
                sh_o = ad.build_shadow(ad.Store(orders), {}, set()).records
                out.append(report(customers, orders, sh_c, sh_o))
            results[label] = {k: sum(r[k] for r in out) / len(out) for k in out[0]}
            a = results[label]
            print(f"{label}")
            print(f"  orders per dataset          {a['orders']:.0f}")
            print(f"  FK valid, real              {a['real_fk']:.1f}%")
            print(f"  FK valid, shadow            {a['shadow_fk']:.1f}%")
            print(f"  customers referenced        real {a['real_refs']:.0f} / shadow {a['shadow_refs']:.0f}")
            print(f"  orders-per-customer drift   {a['drift']:.2f} orders")
            print()

    print("primary key named order_id instead of id")
    print(f"  rows                        {rows}")
    print(f"  key preserved verbatim      {pk_pct:.1f}%")
    print()

    dense = results["dense, shuffled"]["shadow_fk"]
    sparse = results["sparse keys, shuffled"]["shadow_fk"]
    drift = results["dense, shuffled"]["drift"]
    print("Verdict")
    print("  Foreign keys survive only when the referenced key space is a dense")
    print(f"  integer range: {dense:.0f}% valid with ids 1..40, {sparse:.0f}% with sparse ids.")
    print("  Values are clipped into the observed numeric range, so a dense key")
    print("  space makes every synthesised FK land on a real row by accident, not")
    print("  by design. The relationship itself is still lost: the number of")
    print(f"  orders attributed to each customer changes by {drift:.1f} on average,")
    print("  so joined aggregates are wrong even when every FK resolves.")
    print("  A key not literally named 'id' is treated as sensitive and replaced")
    print(f"  ({pk_pct:.1f}% preserved), so self-joins fail outright.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
