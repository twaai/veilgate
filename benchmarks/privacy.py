"""
Does the shadow reveal a real person's sensitive values?

For each field we count how often a shadow value equals that SAME person's real
value, and compare against the correct null: the average over every OTHER real
record.  The old neighbour baseline (i+1) was wrong for this data - signup_year and
tier are smooth functions of id, so the neighbour shares the value and the null was
inflated to roughly the size of the effect, hiding a 2-6x leak.

We also report whether the shadow value is a better guess at the real value than
the trend line alone, and a membership-inference ratio (own / chance).
"""
import os as _os, sys as _sys
_sys.path[:0] = [_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..'), _os.path.dirname(_os.path.abspath(__file__)), _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), '..', 'benchmarks')]
import warnings

import numpy as np

import veilgate as ad
from stealth import realistic_records

warnings.filterwarnings("ignore")

FIELDS = ("balance", "age", "signup_year", "tier", "email")


def main(seeds=200):
    own = {k: 0 for k in FIELDS}
    chance = {k: 0.0 for k in FIELDS}
    mae_shadow, mae_trend = [], []
    for seed in range(seeds):
        real = realistic_records(seed)
        canaries = set()
        sh = ad.build_shadow(ad.Store(real), {}, canaries).records
        ids = sorted(real)
        for i in ids:
            others = [o for o in ids if o != i]
            for k in FIELDS:
                own[k] += sh[i][k] == real[i][k]
                chance[k] += sum(sh[i][k] == real[o][k] for o in others) / len(others)
            assert sh[i]["email"] in canaries
        x = np.array(ids, float)
        rb = np.array([real[i]["balance"] for i in ids])
        sb = np.array([sh[i]["balance"] for i in ids])
        mae_shadow.append(np.abs(sb - rb).mean())
        mae_trend.append(np.abs(np.polyval(np.polyfit(x, sb, 1), x) - rb).mean())
    n = seeds * len(ids)
    print(f"{'field':12} {'= own real':>10} {'= chance':>10} {'ratio':>7}")
    for k in FIELDS:
        o, c = own[k] / n, chance[k] / n
        ratio = (o / c) if c else float("inf")
        print(f"{k:12} {o:>9.1%} {c:>10.1%} {ratio:>6.1f}x")
    print(f"\nerror guessing real balance: from shadow value {np.mean(mae_shadow):.0f}, "
          f"from trend line alone {np.mean(mae_trend):.0f}  (shadow should be no better)")
    print("ratio ~1.0 means the shadow carries no per-person information for that field.")
    return own, chance, np.mean(mae_shadow), np.mean(mae_trend)


if __name__ == "__main__":
    main()
