"""Pin the randomness that ``build_shadow`` draws from.

``build_shadow`` seeds itself with ``secrets.randbits``, so any benchmark that
calls it produces different numbers on every run. That is fine for a one-off
measurement and bad for a published figure: two people running the same command
get different results.

``deterministic(seed)`` swaps that source for a fixed stream and restores it
afterwards, so a benchmark's output reproduces exactly. It patches the whole
``secrets`` module for the duration of the block, so keep the block single
threaded and do not use it in code that needs real randomness.
"""
from __future__ import annotations

import contextlib
import random

import veilgate as ad


@contextlib.contextmanager
def deterministic(seed: int):
    rnd = random.Random(seed)
    original = ad.secrets.randbits
    ad.secrets.randbits = lambda k: rnd.getrandbits(k)
    try:
        yield
    finally:
        ad.secrets.randbits = original
