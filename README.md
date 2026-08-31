# PivotCheck

Passive network discovery and pivot-path validation for authorized security assessments.

[![CI](https://github.com/Debajyoti0-0/pivotcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Debajyoti0-0/pivotcheck/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](pyproject.toml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

<p align="center">
<img src="Image.png" alt="PivotCheck logo">
</p>

After landing on a host during an assessment, you run `ip route`, `arp -a`,
`ss -tunap`, and `cat /etc/resolv.conf` — then reason about the output by
hand. PivotCheck does that reasoning for you: it normalizes the host's
network state into one model, classifies each reachable network by
confidence, correlates transit evidence, and tells you what to investigate
next. It does not scan, and it does not claim reachability without evidence.

## Why PivotCheck?

- **What's visible from this vantage point?** Interfaces, routes, neighbors,
  DNS, and sockets are collected passively — no host sweeps, no ICMP, no
  traceroute.
- **What supports a pivot?** Route, neighbor, and connection evidence is
  correlated into an explicit transit assessment, each conclusion traceable
  back to the observations behind it.
- **What's missing or contradictory?** Gap analysis separates what was
  observed, what was not observed, and what was never collected.
- **What should I investigate next?** One evidence-backed candidate,
  selected deterministically — or nothing, if the evidence doesn't
  support one.
- **What actually works?** Only the explicit target and port you choose
  get validated: one TCP connect or one SOCKS5 CONNECT, per command.

## Features

- Passive discovery of interfaces, routes, neighbors, DNS, and sockets
- Confidence-classified networks (HIGH / MEDIUM / LOW)
- Pivot-path candidate identification with transit-evidence correlation
- Evidence-gap analysis with a six-state evidence model
- Candidate explanation: full evidence → inference → priority chain
- Baseline snapshots and deterministic comparison
- Explicit TCP and SOCKS5 CONNECT validation, one target at a time
- Remote collection over SSH using your existing agent and keys
- Stable, deterministic JSON output on every command

## Installation

```bash
pip install pivotcheck
```

Verify:

```bash
pivotcheck --version
```

Requires Python 3.10+. No runtime dependencies beyond the standard library.

## Quick Start

```bash
pivotcheck discover            # full passive discovery of this host
pivotcheck map --show-pivots   # topology view with inferred pivot context
pivotcheck next                # highest-priority investigation candidate
pivotcheck explain 10.50.0.0/16   # evidence chain for one network
pivotcheck gaps 10.50.0.0/16      # what evidence is missing?
pivotcheck check 10.10.20.25 --port 445      # explicit TCP validation
pivotcheck proxy-check --proxy socks5://127.0.0.1:1080 10.10.20.25 --port 445
```

A typical workflow: `discover` → `next` → `explain` the candidate →
`check` one explicit target → `baseline create` → compare later after
network changes.

## Commands

| Command | Purpose |
| ------- | ------- |
| `pivotcheck discover` | Passive discovery of interfaces, routes, neighbors, DNS, and sockets |
| `pivotcheck map` | Topology-focused view of the same data with confidence levels |
| `pivotcheck next` | Select the single highest-priority investigation candidate |
| `pivotcheck gaps NETWORK` | Classify what evidence exists and what is missing for a network |
| `pivotcheck explain NETWORK` | Full evidence → inference → priority chain for a network |
| `pivotcheck check TARGET --port P` | Explicit TCP validation of one target, classified precisely |
| `pivotcheck proxy-check --proxy URL TARGET --port P` | SOCKS5 CONNECT validation through one operator-supplied proxy |
| `pivotcheck baseline` | Save and manage discovery snapshots |
| `pivotcheck compare BASELINE` | Diff current state against a saved baseline, with recommendations |

Every command accepts `--json`. `discover`, `map`, `gaps`, and `explain`
also accept SSH options to collect from a remote vantage point.

## Evidence Model

PivotCheck keeps four levels strictly separate:

```text
observed evidence → inference → priority → explicit validation
```

No output presents an inference as an observed fact, and no passive output
claims reachability. Gap analysis classifies evidence as `OBSERVED`,
`NOT_OBSERVED`, `NOT_COLLECTED`, `NEGATIVE_EVIDENCE`, or `NOT_APPLICABLE` —
absence of evidence is never quietly promoted to negative evidence.
A `TIMEOUT` from `check` is reported as ambiguous, never as proof a host
is down.

## Validation Scope

Four validation capabilities, all strictly operator-directed:

- **TCP** (`check`) — explicit target, explicit ports, one attempt per
  address:port. Port ranges are rejected; at most 16 explicit ports.
- **SSH** (`check --protocol ssh`) — one public-key authentication attempt
  against one target:port, credential supplied via `--ssh-key-env`. Strict
  host-key verification by default; server-identity verification is
  reported separately from authentication success.
- **SMB** (`check --protocol smb`) — one NTLM session-setup attempt against
  one target:port (default 445), password credential supplied via
  `--credential-env`. Requires the optional `smb` extra
  (`pip install "pivotcheck[smb]"`). No share enumeration, no fallback
  chains, no execution — authentication only.
- **SOCKS5 CONNECT** (`proxy-check`) — one proxy, one destination, one
  port, one attempt. Hostnames are resolved by the proxy, never locally.
- **OPSEC intelligence** (`opsec --action ACTION --platform PLATFORM`) —
  predictive analysis of the telemetry a validation action is reasonably
  expected to produce on a platform (Windows/Linux). Predictive only: it
  never observes target telemetry, never guarantees events, and provides
  no evasion guidance.

UDP is deliberately not supported: no response is not evidence of
unreachability, and PivotCheck does not make claims it cannot support.
Application-layer validation beyond authentication (SMB share access,
remote execution, SSH command execution, HTTP) is out of scope — an
accepted credential does not mean the service "works" beyond accepting it.

## Output

Human output is evidence-first with color on TTYs (`--no-color` to
disable). `--json` produces stable, deterministic, ANSI-free output with
schema and provenance fields:

```json
{
  "schema_version": "1.1",
  "tool": "pivotcheck",
  "version": "1.0.0",
  "command": "next",
  "candidate": null,
  "message": "NO INVESTIGATION CANDIDATES"
}
```

## Scope and Safety

PivotCheck is for **authorized** security assessments only. Passive
commands perform zero network I/O; validation happens only on an explicit
operator command, against one explicit target. Credentials for SOCKS5
proxies are held in memory only and redacted in all output. SSH
collection verifies host keys strictly by default.

## Limitations

- Discovery requires Linux tooling (`ip`, `ss`, `/etc/resolv.conf`);
  validation and baselines work cross-platform.
- Passive analysis shows what the evidence supports — it does not prove
  end-to-end reachability.
- A routed network is classified MEDIUM confidence, never presented as
  reachable.
- `check` TIMEOUT is ambiguous by nature; it is never reported as proof
  either way.
- Baselines are stored unencrypted and contain reconnaissance detail —
  protect them accordingly.

## Documentation

Deeper, focused documentation lives in [`docs/`](docs/):

- [Baseline workflow](docs/baseline-workflow.md)
- [Comparison semantics](docs/comparison-semantics.md)
- [Operator intelligence](docs/operator-intelligence.md)
- [Perspective map](docs/perspective-map.md)
- [SSH session providers](docs/session-providers.md)

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for
development setup and pull-request guidelines.

## Security

Report vulnerabilities privately per [SECURITY.md](SECURITY.md); please
do not open public issues for security reports.

## License

[GNU General Public License v3.0](LICENSE) — GPL-3.0-only.
