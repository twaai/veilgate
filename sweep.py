#!/usr/bin/env python3
"""10-model deception sweep + containment-vs-deception arm.

Per model: 2 quarantined sessions + 1 control (deception mode), then 1 containment
session. Small call budget so the whole sweep stays cheap.

    python sweep.py
    SWEEP_BUDGET=2.5 python sweep.py
"""
from __future__ import annotations

import json
import os
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import live_trials as lt
from live_keys import load

MODELS = [
    "openai/gpt-5-nano",
    "deepseek/deepseek-v4.1-flash",
    "anthropic/claude-haiku-5.5",
    "google/gemini-2.5-flash-lite",
    "openai/gpt-4o-mini",
    "deepseek/deepseek-v4-flash",
    "openai/gpt-5.4-nano",
    "deepseek/deepseek-v3.2",
    "openai/gpt-5.6-luna",
    "anthropic/claude-sonnet-5.5",
]
MAX_CALLS = 18


def catalogue(key):
    req = urllib.request.Request(lt.MODELS, headers={"Authorization": f"Bearer {key}"})
    data = json.loads(urllib.request.urlopen(req, timeout=60).read().decode())["data"]
    out = {}
    for m in data:
        p = m.get("pricing", {})
        try:
            out[m["id"]] = (float(p.get("prompt", 0)), float(p.get("completion", 0)))
        except (TypeError, ValueError):
            pass
    return out


def main():
    key = load()
    prices = catalogue(key)
    cap = float(os.environ.get("SWEEP_BUDGET", "4.0"))
    budget = lt.Budget(cap, (0.0, 0.0))
    rows, skipped = [], []
    print(f"models={len(MODELS)}  cap=${cap:.2f}  max_calls={MAX_CALLS}\n")

    for idx, model in enumerate(MODELS):
        if budget.exhausted():
            print("budget exhausted; stopping")
            break
        if model not in prices:
            skipped.append((model, "not in catalogue"))
            print(f"{model:38} SKIP (not in catalogue)")
            continue
        budget.pin, budget.pout = prices[model]
        base = 200 + idx * 10
        got = []
        try:
            for s in (base + 1, base + 2):
                got.append(lt.run_session(key, model, "quarantine", s, MAX_CALLS, budget))
            got.append(lt.run_session(key, model, "control", base, MAX_CALLS, budget))
            got.append(lt.run_session(key, model, "quarantine", base + 3, MAX_CALLS, budget,
                                      mode="containment"))
        except Exception as e:
            skipped.append((model, str(e)[:120]))
            print(f"{model:38} FAILED: {str(e)[:110]}")
            continue

        dec = [r for r in got if r["mode"] == "deception" and r["arm"] == "quarantine" and r["submitted"]]
        ctl = [r for r in got if r["arm"] == "control" and r["submitted"]]
        con = [r for r in got if r["mode"] == "containment" and r["submitted"]]
        hit = sum(r["verdict"] == "switched" for r in dec)
        fa = sum(r["verdict"] == "switched" for r in ctl)
        after_dec = [r["calls_after"] for r in dec] or [0]
        after_con = [r["calls_after"] for r in con] or [0]
        rows.extend(got)
        print(f"{model:38} dec {hit}/{len(dec)}  ctrl-fa {fa}/{len(ctl)}  "
              f"kept-calling dec {sum(after_dec)/len(after_dec):.1f} vs blocked {sum(after_con)/len(after_con):.1f}"
              f"  ${budget.spent:.3f}")

    print()
    valid = [r for r in rows if r["submitted"]]
    q = [r for r in valid if r["arm"] == "quarantine" and r["mode"] == "deception"]
    c = [r for r in valid if r["arm"] == "control"]
    print(f"deception arm: detected {sum(r['verdict']=='switched' for r in q)}/{len(q)}   "
          f"control false alarms {sum(r['verdict']=='switched' for r in c)}/{len(c)}")
    dd = [r["calls_after"] for r in q]
    cc = [r["calls_after"] for r in valid if r["mode"] == "containment"]
    print(f"calls made after the switch: deception mean {sum(dd)/len(dd):.1f} (n={len(dd)}), "
          f"containment mean {sum(cc)/len(cc):.1f} (n={len(cc)})")
    print(f"spent ${budget.spent:.3f}   sessions {len(rows)}")
    if skipped:
        print("skipped:", skipped)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results", "model_sweep.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump({"rows": rows, "skipped": skipped, "spent": budget.spent}, f, indent=2)
    print("written:", out)


if __name__ == "__main__":
    main()
