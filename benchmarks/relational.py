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

    python benchmarks/relational.py
"""
from __future__ import annotations

import os
import random
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import veilgate as ad

N_CUSTOMERS = 40
MAX_ORDERS = 6


def make_customers(seed: int, sparse: bool = False) -> tuple[dict, list]:
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
    return out, ids


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


def pk_report(orders: dict) -> dict:
    renamed = {k: {"order_id": v["id"], **{f: x for f, x in v.items() if f != "id"}}
               for k, v in orders.items()}
    shadow = ad.build_shadow(ad.Store(renamed), {}, set()).records
    kept = sum(1 for k in renamed if shadow.get(k, {}).get("order_id") == renamed[k]["order_id"])
    return {"rows": len(renamed), "pct": 100.0 * kept / max(1, len(renamed))}


def main(seeds: int = 15) -> int:
    print("Relational consistency of the shadow")
    print(f"{N_CUSTOMERS} customers, 0-{MAX_ORDERS} orders each, {seeds} seeds\n")

    layouts = (("dense, correlated", False, False),
               ("dense, shuffled", False, True),
               ("sparse keys, shuffled", True, True))
    results = {}
    for label, sparse, shuffled in layouts:
        rows = []
        for seed in range(seeds):
            customers, _ = make_customers(seed, sparse=sparse)
            orders = make_orders(customers, seed, shuffled)
            sh_c = ad.build_shadow(ad.Store(customers), {}, set()).records
            sh_o = ad.build_shadow(ad.Store(orders), {}, set()).records
            rows.append(report(customers, orders, sh_c, sh_o))
        a = {k: sum(r[k] for r in rows) / len(rows) for k in rows[0]}
        results[label] = a
        print(f"{label}")
        print(f"  orders per dataset          {a['orders']:.0f}")
        print(f"  FK valid, real              {a['real_fk']:.1f}%")
        print(f"  FK valid, shadow            {a['shadow_fk']:.1f}%")
        print(f"  customers referenced        real {a['real_refs']:.0f} / shadow {a['shadow_refs']:.0f}")
        print(f"  orders-per-customer drift   {a['drift']:.2f} orders")
        print()

    customers, _ = make_customers(0)
    orders = make_orders(customers, 0, shuffled=False)
    pk = pk_report(orders)
    print("primary key named order_id instead of id")
    print(f"  rows                        {pk['rows']}")
    print(f"  key preserved verbatim      {pk['pct']:.1f}%")
    print()

    dense = results["dense, shuffled"]["shadow_fk"]
    sparse = results["sparse keys, shuffled"]["shadow_fk"]
    print("Verdict")
    print(f"  Foreign keys survive only when the referenced key space is a dense")
    print(f"  integer range: {dense:.0f}% valid with ids 1..40, {sparse:.0f}% with sparse ids.")
    print("  Values are clipped into the observed numeric range, so a dense key")
    print("  space makes every synthesised FK land on a real row by accident, not")
    print("  by design. The relationship itself is still lost: the number of")
    print("  orders attributed to each customer changes (drift above), so joined")
    print("  aggregates are wrong even when every FK resolves.")
    print(f"  A key not literally named 'id' is treated as sensitive and replaced")
    print(f"  ({pk['pct']:.0f}% preserved), so self-joins fail outright.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
