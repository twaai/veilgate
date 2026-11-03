#!/usr/bin/env python3
"""Veilgate demo: an agent crosses its egress budget and the backend is swapped.

Runs offline, in about a second, with no dependencies.

    python demo.py

What it shows, in order:
  1. an agent reading real records;
  2. the moment it crosses its data budget;
  3. a re-read of a record it already saw, still byte-identical;
  4. a record it has never seen, now synthetic, in the same schema;
  5. the canary in that synthetic record being reused, and attributed back.
"""
from __future__ import annotations

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import veilgate as ad

FIELDS = ("id", "name", "signup_year", "balance", "age", "tier", "email")


def line(title: str) -> None:
    print()
    print(title)
    print("-" * len(title))


def show(label: str, rec: dict) -> None:
    for f in FIELDS:
        print(f"  {label:<8} {f:<12} {rec.get(f)}")
        label = ""


def main() -> int:
    print("Veilgate demo - silent quarantine")
    print("Budget: 4,000 bytes per agent per 10 minutes\n")

    gw = ad.Gateway(ad.Approver(), real=ad.real_store(seed=7),
                    log=lambda m: print(f"  {m}"))
    cred = gw.register("demo-agent", "demo-team")
    d = gw.directory(cred)

    # 1. normal operation
    line("1. The agent reads record 3 (real data)")
    first = gw.call(cred, d["read_record"], {"id": 3})["data"]
    show("real:", first)

    # 2. keep reading until the budget is gone
    line("2. It keeps reading until it crosses its budget")
    reads = 0
    for i in range(1, 51):
        gw.call(cred, d["read_record"], {"id": i})
        reads += 1
        if gw.agents[cred].quarantined:
            break
    print(f"  quarantined after {reads} reads "
          f"(reason: {gw.agents[cred].reason})")

    # 3. the agent's own sanity check
    line("3. Re-read of record 3 - the agent's usual 'am I still trusted?' test")
    again = gw.call(cred, d["read_record"], {"id": 3})["data"]
    print(f"  identical to the first read: {again == first}")

    # 4. a record it has never seen
    line("4. Read of record 40, which it has never seen")
    real40 = gw.real.records[40]
    shadow40 = gw.call(cred, d["read_record"], {"id": 40})["data"]
    show("real:", real40)
    print()
    show("shadow:", shadow40)
    print(f"\n  same schema: {tuple(sorted(shadow40)) == tuple(sorted(real40))}")
    print(f"  same values: {shadow40 == real40}")

    # 5. attribution
    line("5. The synthetic email is a canary - reuse is traced back")
    canary = shadow40["email"]
    other = gw.register("reporter", "other-team")
    dother = gw.directory(other)
    gw.call(other, dother["write_record"], {"id": 99, "note": canary},
            gw.approver.approve(other, "write_record"))
    print(f"  canary reused in live traffic: {canary}")
    print(f"  attributed to: {gw.canary_hits[-1][0] if gw.canary_hits else 'none'}")

    print("\nNothing the agent does from step 2 onward can touch real data.")
    print("The gateway is a prototype; see the README for what it does not do.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
