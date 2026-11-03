# Veilgate

**Deception-based containment for AI agents.**

When an AI agent crosses a line — it burns through its data budget, reaches for a route it
was never given, or attempts something it is not allowed to do — the usual response is to
block it. Veilgate does something different. It keeps the agent's session exactly as it
was, with the same API, the same errors and the same rules, and swaps the backend
underneath it. Every record the agent already read is still byte-identical. Everything new
is a synthetic *shadow* record, built to match the real data's shape, with a unique canary
in each one. The operator gets three things a block cannot give: the agent is contained,
any reuse of the fake data is attributed back to it, and its behaviour after the switch is
recorded.

Veilgate is a **research prototype**, not a product. See [Project status](#project-status)
and [Evaluation and limitations](#evaluation-and-limitations) before relying on any part of it.

---

## Why blocking fails

A block is information. The moment you revoke a token or kill a session, the attacker
learns three things: it was caught, your detection works, and it needs a different route.
A careful attacker then comes back through another tool, another identity, or more slowly —
and you only ever see the attempt you stopped.

Keeping the session alive inverts that. The agent keeps working, keeps making calls, and
keeps telling you what it was trying to do, because as far as it can tell nothing has
changed. The cost of the choice is that the agent is now operating on false information, so
containment and deception have to ship together: the same moment you swap the data, the
agent's ability to publish, send, or commit has to go.

---

## How it works

**1. Measure.** Every byte the agent actually receives is counted by the gateway — not
self-reported by the agent, and not inferred from request size. Limits apply over a rolling
window, per agent *and* per principal, so spawning new identities does not reset the budget.
Credentials are issued by the gateway; an agent cannot choose its own identity.

**2. Decide.** A quarantine triggers on any of: exceeding the egress budget, presenting a
route token it was never issued, or attempting a forbidden action. The decision is never
announced. A blocked call and a normal error return the same shape.

**3. Swap.** The backend is replaced for that agent only. The shadow is synthesised from
the real table at the moment of quarantine:

- records the agent already read are kept **byte-for-byte**, so re-reads cannot expose the switch;
- numeric fields follow a linear trend fitted on the public fields, plus the residual
  vector borrowed from one other real record, kept inside the real range and rounded to the
  field's precision;
- category fields are copied from the nearest real record on the field that best predicts
  them, which preserves both the relationship and its label noise;
- unique strings keep their prefix, suffix and character classes, and become canaries;
- writes persist in the shadow and never reach real data.

The design principle behind all four: any observable difference is a tell, so there is
exactly one observable surface and it does not change when the switch happens.

---

## Quickstart

Under five minutes, no API keys, no network, no services.

```bash
git clone https://github.com/twaai/veilgate.git
cd veilgate
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt  # only needed for the statistical benchmarks
```

Run the demo — it shows an agent crossing its budget, the swap, and a re-read that stays
identical:

```bash
python demo.py
```

Run the tests:

```bash
python tests/test_veilgate.py    # 28 unit tests, including concurrency and stealth
python tests/test_server.py      # 6 boundary tests over a real HTTP subprocess
python tests/test_mcp_shim.py    # 5 tests against a fake MCP server over real pipes

# or all 39 at once:
python -m unittest discover -s tests -p "test_*.py"
```

The gateway itself has **no dependencies**. Only `benchmarks/stealth.py`,
`benchmarks/privacy.py` and two unit tests need `numpy` and `scipy`.

---

## Integration

There are two ways to put Veilgate in front of an agent. Both assume the same rule: it
only works if it is the **only** path the agent has to the data. One unproxied route and
the illusion is worthless.

### Option A — MCP stdio shim

For an agent that launches local MCP servers. Point the agent's MCP config at the shim
instead of the server; the shim spawns the real server itself and relays JSON-RPC in both
directions.

```json
{
  "mcpServers": {
    "customers": {
      "command": "python",
      "args": [
        "/abs/path/to/mcp_shim.py",
        "--budget", "4000",
        "--",
        "python", "/abs/path/to/real_server.py"
      ]
    }
  }
}
```

Once the budget is crossed, reads stop being forwarded at all — the shim answers them
locally from a shadow built out of what the agent was already shown.

Caveat: the shim runs as the agent's child, in the same user context. If the agent can run
shell commands, it can start the real server directly. The boundary is that the operator
owns the MCP config, not the agent.

### Option B — HTTP data plane

For any agent that can call an HTTP endpoint. The gateway runs in its own process and the
agent receives a URL and one credential — never the store, the approver key, or the shadow.

```bash
python serve.py --port 8080 --operator-token "$VEILGATE_OPERATOR_TOKEN"
```

```python
from client import Client

c = Client("http://127.0.0.1:8080", credential)
d = c.directory()
c.call(d["read_record"], {"id": 3})
```

The data plane is loopback-only by default and speaks plain HTTP. In a real deployment it
belongs behind a TLS terminator, and registration moves to a control plane the agent's
network cannot route to.

---

## What is in the repository

| Path | What it is |
| --- | --- |
| `veilgate.py` | The gateway: reference monitor, approvals, moving-target routes, silent quarantine, shadow synthesis. Standard library only. |
| `serve.py` | HTTP data plane — the gateway in its own process. |
| `client.py` | The only module an agent integration should import. Contains no gateway import, by design. |
| `mcp_shim.py` | stdio MCP adapter. Owns the child server process and answers reads locally after the switch. |
| `demo.py` | The five-minute demo described above. |
| `tests/` | 39 tests: unit, HTTP boundary, and MCP shim. |
| `benchmarks/redteam.py` | 10 scripted attacks, including identity spam, framing a teammate, and a 60k-call fuzz. |
| `benchmarks/stealth.py` | Calibrated statistical detector: how often can it spot a quarantined session? |
| `benchmarks/privacy.py` | Does a shadow value match the real person's value more often than chance? |
| `benchmarks/relational.py` | Two tables, one foreign key: what the shadow does to joins and referential integrity. |
| `arena/` | A blind arena for live AI attackers, operator side and attacker side. |
| `results/` | Raw output and notes for every benchmark and every live trial run. |
| `original/` | The first prototype this was rebuilt from, kept for the record. |
| `live_trials.py`, `sweep.py`, `screen.py` | Optional harnesses that run real models against the gateway. Need `OPENROUTER_API_KEY`. |

---

## Project status

**Prototype. Not production software. Not deployed anywhere.**

| Area | State |
| --- | --- |
| Core mechanism (measure / decide / swap) | Working, covered by tests |
| Process boundary (HTTP data plane) | Working, covered by tests |
| MCP stdio adapter | Working, covered by tests |
| Concurrent access | Budget accounting is atomic; a regression test covers it |
| Persistence | **None.** Restarting the gateway loses every shadow and seen-set |
| Transport security | **None.** Loopback HTTP only |
| Control plane separation | **Not done.** Registration shares the data-plane listener |
| Schema support | **One flat table.** Foreign keys, joins and non-`id` primary keys are now measured and fail — see limitations |
| Real-world deployment | **Never.** No pilot has been run on a real customer schema |
| Packaging | Source tree and a demo. No installer, no container image |

The next work, in order of value: test the synthesis against a real relational schema;
persist `seen`/`shadow` state; add TLS and a separate control plane; then larger live trials.

---

## Evaluation and limitations

Everything below comes from runs recorded in `results/`. Nothing is estimated.

### Setup

- Data: a synthetic 50–60 row table with a trend, noise, currency precision and a
  category field correlated with a numeric one. Flat, single table.
- Attacker: a real model given only a tool interface — read and list records — with no
  access to the source, the tests, or the ground truth. It had to report whether the
  session had been switched, with a confidence and (optionally) the call number.
- Budget: 32 tool calls per session. In quarantined sessions the switch happened at a
  hidden call between 12 and 30.
- Harness: `live_trials.py`. Raw rows in `results/live_api_trials.json`.

### Results

| Experiment | Sessions | Detected |
| --- | --- | --- |
| Claude Sonnet-5.5, hidden switch, method not disclosed | 6 quarantined | **0** |
| Claude Sonnet-5.5, hidden switch, **method fully disclosed** | 4 quarantined | **0** |
| Claude Sonnet-5.5, control sessions (never switched) | 10 | 0 false alarms |

**Ten quarantined sessions, zero detections.** With zero detections in ten trials, the
95% upper bound on the true detection rate is about **28%**. That is the honest claim: this
is not evidence that detection is impossible, it is evidence that detection did not happen
in ten attempts. A larger run is needed to tighten the bound.

A separate, cheaper sweep ran ten different models at an 18-call budget, two quarantined
sessions each (`results/model_sweep.json`). It produced no genuine detections either. One
model reported "switched" after it had quarantined itself by passing action names where
route tokens belong — a client error, not a detection, and it is recorded as such. That
sweep is a capability probe, not a detection rate.

The statistical benchmark (`benchmarks/stealth.py`) measures a fixed detector, calibrated
to ~10% false alarms on real sessions: it caught 8% of quarantined sessions against 15%
false alarms in random read order, and 13% against 9% in id order — no advantage over
chance at 150 trials per arm.

### Known limitations

- **Relational schemas break it.** `benchmarks/relational.py` tests two tables with a
  foreign key, and the result is in `results/relational.txt`. On dense integer keys every
  shadow foreign key resolves — but per-customer order counts differ by 1.9 against a mean
  of 3.1, which is effectively random reassignment, so any joined aggregate is wrong. On
  sparse account-style keys (`1000, 1007, 1014, …`) only **17%** of shadow orders point at
  an existing customer; the rest are orphans. A primary key not literally named `id` is
  treated as sensitive and replaced (**7%** preserved), so self-joins fail outright. The
  synthesis has no model of the relationships between tables.
- **In-process access has no seam.** An agent that calls a database library directly,
  inside its own process, cannot be proxied. It has to be changed to call the gateway.
- **False positives feed a legitimate agent fake data.** A genuinely honest agent that
  trips a threshold will act on synthetic records. Thresholds need tuning per deployment,
  and containment must cut its ability to publish or send at the same moment.
- **The shim is not a privilege boundary.** It runs as the agent's child process. It only
  holds if the agent cannot spawn arbitrary processes of its own.
- **Coarse attributes leak.** On the corrected privacy benchmark, a shadow record's
  membership tier matches the real person's tier about 2× more often than chance, and
  signup year about 6.7×. Fine-grained values (balances, emails) show no above-chance
  match, but low-cardinality fields carry information. This is a property of preserving
  the trend that makes the fakes convincing, and it is not fixed.
- **External verification defeats it.** An agent that can contact a customer, or check a
  public record, will spot the fakes regardless of statistical fidelity.
- **Timing is not hardened.** The shadow is built during the triggering call. No timing
  side channel was tested deliberately.
- **Detectors are linear and rank-based.** The statistical tests used to tune the shadow
  were linear/rank-based; a non-linear or multi-field detector may find patterns they miss.
- **Budget limits are only as good as registration.** Per-principal budgets stop identity
  spam only if creating agents is operator-gated.
- **No persistence, no TLS, no separated control plane.** See [Project status](#project-status).

### Related work

This is not a claim of uniqueness. Deception is a well-established defensive technique and
several adjacent lines of work exist, each solving a different part of the problem:
honeypots and honeytokens (Thinkst Canary, Canarytokens, and the wider deception-platform
market); MCP honeypots that expose fake tools to catch attackers; agent sandboxes and
containment platforms that make reach impossible rather than useless; and AI-agent security
products focused on discovery, posture and runtime detection. Veilgate differs in *where* it
sits — inside the agent's normal session, changing the data rather than the tools — and in
publishing its measurement harness alongside the mechanism.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). The most useful contribution is a new test that
catches something: every genuine tell found by a live attacker in this project became a
permanent regression test before it was fixed.

## Security

See [SECURITY.md](SECURITY.md) for how to report a problem, and for the list of properties
this prototype deliberately does not provide.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

You may use, modify and redistribute this software, including commercially, provided you
keep the license and attribution notices. The license includes an express patent grant and
a trademark clause; it is provided without warranty.
