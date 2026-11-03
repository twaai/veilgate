# Security policy

## Reporting a vulnerability

Please **do not open a public issue** for anything security-relevant.

Use GitHub's private reporting instead: on this repository, open the **Security** tab and
choose **Report a vulnerability**. That creates a private advisory visible only to the
maintainers.

Please include:

- what you did, in enough detail to reproduce it;
- what you observed versus what the README says should happen;
- the commit you tested and your Python version.

You will get an acknowledgement when the report is read. There is no bug bounty.

## What counts as a vulnerability here

Veilgate makes one specific promise: **a quarantined agent cannot tell the backend was
swapped, and cannot reach real data afterwards.** A vulnerability is anything that breaks
either half. Examples that qualify:

- a difference between the real and shadow path that is observable by the agent —
  response shape, error text, status code, ordering, or timing;
- a way for a quarantined agent to reach real data, or to write to the real store;
- a way to detect quarantine from the protocol itself rather than from the data;
- a budget accounting flaw that lets an agent receive more real data than its limit;
- an authentication or routing flaw that lets one credential act as another;
- a cross-agent or cross-tenant leak — one agent's shadow, canaries or `seen` set
  influencing another's responses.

## What does not count

These are documented limitations, not vulnerabilities. Reports about them are welcome as
issues, but they are not security fixes. See the README's
[Evaluation and limitations](README.md#evaluation-and-limitations) section.

- **No TLS and no authentication on the transport.** The data plane is loopback HTTP by
  design in this prototype.
- **The MCP shim is not a privilege boundary.** It runs as the agent's child. An agent
  that can spawn processes can bypass it. The security boundary is the operator owning the
  agent's MCP configuration.
- **No persistence.** Restarting the gateway loses all quarantine state.
- **Coarse attribute leakage.** Low-cardinality fields such as membership tier correlate
  with the real value above chance. This is measured and documented.
- **External verification.** An agent that can check the data against the outside world
  will detect the fakes.
- **False positives.** A legitimate agent that trips a threshold will be served synthetic
  data. This is why containment must ship alongside deception.

## Supported versions

None yet. This is a pre-release prototype: there are no versioned releases and no
back-ported security fixes. Test against the tip of the default branch.

## For deployers

Before using any part of this in front of real data, at minimum:

1. put the data plane behind TLS and move registration to a control plane the agent's
   network cannot reach;
2. run the gateway, the approver and the agent in separate processes with separate
   credentials;
3. make the gateway the **only** path the agent has to the data — one unproxied route
   removes the guarantee;
4. tune the budget thresholds for the deployment, and decide in advance what happens when
   a legitimate agent trips one;
5. cut the agent's ability to publish, send or commit at the same moment the data is
   swapped.
