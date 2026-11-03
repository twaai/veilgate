"""OpenRouter credential loader for the optional live trials.

Only the live-trial scripts (``live_trials.py``, ``sweep.py``, ``screen.py``) need
this. The gateway, the tests, the demo and both integrations run with no network
access and no credentials at all.

Set the key in the environment:

    export OPENROUTER_API_KEY=...        # macOS / Linux
    $env:OPENROUTER_API_KEY = "..."      # PowerShell

Then:

    from live_keys import load
    key = load()          # raises RuntimeError if the variable is unset

CLI:  python live_keys.py --ping       # shows status and remaining credit only
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

ENV = "OPENROUTER_API_KEY"


def load() -> str:
    key = (os.environ.get(ENV) or "").strip()
    if not key:
        raise RuntimeError(
            f"{ENV} is not set. The live trials need an OpenRouter key; "
            "everything else in this repository runs offline."
        )
    return key


def key_info(key: str) -> dict:
    req = urllib.request.Request("https://openrouter.ai/api/v1/key",
                                 headers={"Authorization": f"Bearer {key}"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return {"status": r.status, **json.loads(r.read().decode()).get("data", {})}
    except urllib.error.HTTPError as e:
        return {"status": e.code, "body": e.read().decode()}


if __name__ == "__main__":
    k = load()
    print("source:", ENV)
    print("key   :", k[:8] + "..." + k[-4:], f"(len {len(k)})")
    if "--ping" in sys.argv:
        info = key_info(k)
        print("ping  :", info.get("status"), {x: info.get(x) for x in
              ("label", "limit", "usage", "limit_remaining", "is_free_tier")})
