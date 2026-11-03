# Contributing

Veilgate is a research prototype. The most valuable contribution is not a feature — it is
a **test that catches something**.

## The loop this project runs on

```
build  ->  attack it (scripted, statistical, live model)  ->  turn every tell into a
permanent test  ->  fix  ->  re-measure
```

Every genuine tell found by a live attacker so far became a regression test before it was
fixed. If you find a way to detect the switch, the PR we want is: a failing test that
demonstrates it, plus the smallest change that makes it pass without removing the
behaviour other tests depend on.

## Getting set up

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python demo.py                     # sanity check, no dependencies beyond the stdlib
python tests/test_veilgate.py
python tests/test_server.py
python tests/test_mcp_shim.py
```

All three suites must pass before a PR is considered. Please paste the actual output
(including the count and the time) rather than saying "tests pass".

## What a good PR looks like

- **One change, one reason.** If a fix needs a new test, include it.
- **No new dependencies for the core.** `veilgate.py`, `serve.py`, `client.py`,
  `mcp_shim.py` and `demo.py` are standard library only. `numpy` and `scipy` are allowed
  in `benchmarks/` and in statistical tests.
- **Do not weaken a test to make it pass.** If a test is wrong, say why in the PR and
  change the assertion with an explanation.
- **Numbers need a source.** Any claim in the README or in code comments about detection
  rate, false alarms or privacy must come from a run recorded in `results/`, with the
  command that produced it.
- **No marketing language.** Claims of perfect or absolute detection resistance are not
  used in this repository, because they are not true.

## Style

- Python 3.9+, no type stubs needed, `from __future__ import annotations` in newer modules.
- Comments explain *why*, not *what*. A comment that restates the code should be deleted.
- Keep the gateway dependency-free. If you think it needs a library, open an issue first.

## Reporting a problem

- **Bug in the code:** open an issue with the command, the output, and the Python version.
- **Security-relevant problem:** follow [SECURITY.md](SECURITY.md), not a public issue.
- **A tell you found in the shadow:** this is the most useful kind of report. Include the
  session seed, the records you compared and the statistical test you ran if you have one.

## What will be rejected

- Changes that add an admin endpoint, dashboard or metrics surface reachable from the
  agent's network. The security model depends on there being exactly one observable
  surface; a second one is a vulnerability, not a feature.
- A model call in the request path. It adds latency variance and non-determinism, both of
  which are observable.
- Sharing shadow data or canaries across agents or tenants.

## License

By contributing you agree that your contribution is licensed under the Apache License 2.0,
the same license as the project.

## Conduct

Be precise, be kind, and assume the other person is trying to make the thing correct.
