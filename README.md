# PivotCheck

[![CI](https://github.com/Debajyoti0-0/pivotcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/Debajyoti0-0/pivotcheck/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue)](pyproject.toml)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

<p align="center">
<img src="Image.png" alt="PivotCheck logo">
</p>

**PivotCheck** is a passive network discovery and pivot-path validation
engine for authorized security assessments. It normalizes a host's observed
network state — interfaces, routes, neighbors, DNS configuration, and
listening sockets — into a single deterministic model, classifies each
reachable network by evidence confidence, correlates transit evidence into
explicit pivot assessments, and performs strictly bounded,
operator-directed validation of exactly one target at a time.

PivotCheck performs no scanning. Discovery is passive (zero network I/O);
validation occurs only on an explicit operator command against one explicit
target. No output presents an inference as an observed fact, and no passive
result is ever reported as reachability.

## Design Principles

The following invariants are architectural and non-negotiable:

1. **Passive by default.** Discovery reads local operating-system state
   only: no host sweeps, no ICMP probes, no traceroute, no port scans.
2. **Strict layer separation.** Output maintains four distinct levels:
   `observed evidence → inference → priority → explicit validation`. An
   inference is never rendered as an observed fact.
3. **One target, one port, one attempt.** Every validation action is bound
   to a single explicit destination. Port ranges and CIDR expansion are
   rejected at argument parsing; there are no retries, no fallback chains,
   and no parallel attempts.
4. **Timeout is ambiguous.** A `TIMEOUT` result is never reported as proof
   of a host being down (or up). Absence of a response is not negative
   evidence.
5. **Authentication is not authorization.** A successful authentication
   handshake never implies execution capability, lateral-movement
   capability, or application health.
6. **Absence of evidence is never negative evidence.** Gap analysis
   preserves the distinction between what was observed, what was not
   observed, what could not be collected, and what was never attempted.
7. **Deterministic output.** `--json` output is stable, ordered, and
   ANSI-free, with schema and provenance fields on every command.

## Architecture

```text
pivotcheck/
├── discovery/    OS-level collectors: interfaces, routes, neighbors,
│                 DNS, sockets (Linux, Windows, macOS; SSH remotes)
├── models/       Frozen dataclasses: baseline, network, check, credentials
├── analysis/     Confidence classification, correlation, gap analysis,
│                 next-step selection, explanation, what-if engine
├── checks/       Validation providers: tcp, http, ssh, smb, winrm,
│                 rdp, proxy, resolver
├── output/       Terminal (TTY, color-aware) and JSON renderers
├── storage/      Baseline persistence (plaintext or Fernet+scrypt at rest)
├── utils/        Credential loading, redaction, validation, system info
└── cli.py        Argparse wiring, argument validation, exit-code contract
```

Discovery collectors degrade to warnings when a tool is unavailable — never
to failures. All credential material is supplied via environment variables
(never the command line), held in memory only, and redacted in every output
path.

## Installation

```bash
pip install pivotcheck
```

Requires Python 3.10+. The core has **zero runtime dependencies** beyond the
standard library; protocol backends are opt-in extras:

| Extra | Enables | Dependencies |
|---|---|---|
| `socks` | SOCKS5 CONNECT validation (`proxy-check`) | PySocks ≥ 1.7.1 |
| `smb` | SMB / NTLM pass-the-hash validation (`check --protocol smb`) | smbprotocol ≥ 1.15 |
| `winrm` | WinRM WS-Man authentication validation | pywinrm ≥ 0.5.0 |
| `kerberos` | Kerberos-backed WinRM (non-Windows hosts) | gssapi, krb5 |
| `encrypt` | Encrypted-at-rest baseline storage | cryptography ≥ 42.0 |
| `dev` | Lint and type-check toolchain (ruff, mypy) | — |

Install with extras:

```bash
pip install "pivotcheck[smb,winrm,encrypt]"
```

Verify:

```bash
pivotcheck --version        # pivotcheck 1.0.0
```

## Quick Start

```bash
pivotcheck discover                        # full passive discovery of this host
pivotcheck map --show-pivots               # topology view with inferred pivot context
pivotcheck next                            # highest-priority investigation candidate
pivotcheck explain 10.50.0.0/16            # evidence chain for one network
pivotcheck gaps 10.50.0.0/16               # what evidence is missing?
pivotcheck check 10.10.20.25 --port 445    # explicit single-target TCP validation
pivotcheck proxy-check --proxy socks5://127.0.0.1:1080 10.10.20.25 --port 445
```

Canonical workflow: `discover` → `next` → `explain` the candidate → `check`
one explicit target → `baseline create` → `compare` after network changes.

## Command Reference

| Command | Purpose |
|---|---|
| `pivotcheck discover` | Passive discovery of interfaces, routes, neighbors, DNS, and sockets |
| `pivotcheck map` | Topology-focused view of the same data with confidence classification |
| `pivotcheck next` | Select the single highest-priority investigation candidate, deterministically |
| `pivotcheck gaps NETWORK` | Classify which evidence exists, is missing, or was never collected |
| `pivotcheck explain NETWORK` | Full evidence → inference → priority chain for one network |
| `pivotcheck check TARGET --port P` | Explicit single-target validation (TCP, HTTP, SSH, SMB, WinRM, RDP) |
| `pivotcheck proxy-check --proxy URL TARGET --port P` | SOCKS5 CONNECT validation through one operator-supplied proxy |
| `pivotcheck baseline` | Create, list, show, and delete discovery snapshots (`create --encrypt --password-env VAR` for encryption at rest) |
| `pivotcheck compare BASELINE` | Diff current state against a saved baseline, with recommendations |
| `pivotcheck compare A B` | Diff two saved baselines offline (no discovery performed) |
| `pivotcheck opsec --action A --platform P` | Predictive observability analysis for a validation action |
| `pivotcheck what-if --network CIDR --gateway IP --interface NAME` | Hypothetical evaluation of assumed routing changes |

Global options: `--json` (stable machine output), `--data-dir DIR`
(baseline storage location), `-v` (verbosity), `--no-color`.
`discover`, `map`, `gaps`, and `explain` also accept SSH options to collect
from a remote vantage point using your existing agent and keys.

## Evidence Model

PivotCheck keeps four levels strictly separate:

```text
observed evidence → inference → priority → explicit validation
```

Every evidence type carries exactly one of six explicit statuses
(`pivotcheck.analysis.evidence_gaps.EvidenceStatus`):

| Status | Meaning |
|---|---|
| `OBSERVED` | Collector ran and found evidence |
| `NOT_OBSERVED` | Collector ran but found no evidence for this network |
| `NOT_COLLECTED` | Collector was unavailable or degraded |
| `NEGATIVE_EVIDENCE` | Collector explicitly found absence (e.g., a neighbor entry in `FAILED` state) |
| `NOT_APPLICABLE` | The evidence type does not apply to this context |
| `NOT_PERFORMED` | The corresponding action was not performed |

Absence of evidence is never quietly promoted to negative evidence. A
`TIMEOUT` from `check` is reported as ambiguous, never as proof either way.
Networks are classified `HIGH`, `MEDIUM`, or `LOW` confidence; a routed
network is `MEDIUM` — inferred from routing evidence, never presented as
reachable. The exact confidence rules are specified in
[docs/confidence-model.md](docs/confidence-model.md).

## Validation Reference

All validation is strictly operator-directed: one explicit target, one
explicit port, one attempt, per command.

**TCP** — `check TARGET --port P` (up to 16 explicit ports; ranges rejected).
One connect attempt per address:port. Result classes distinguish connection
established, refused, filtered, and timeout (ambiguous by definition).

**HTTP** — `check TARGET --port P --protocol http`. One `HEAD` request to
one target:port. Add `--http-tls` for HTTPS with certificate verification
(TLS failures are reported and never bypassed). No crawling, no redirects,
no enumeration. An HTTP response is an observation, never proof of
authorization or application health.

**SSH** — `check TARGET --port P --protocol ssh --ssh-key-env VAR`. One
public-key authentication attempt using the key named by the environment
variable. Strict host-key verification by default; server-identity
verification is reported separately from authentication success. No command
execution.

**SMB / Pass-the-Hash** — `check TARGET --port 445 --protocol smb
--credential-env VAR --smb-user USER` (requires the `smb` extra). Without
`--smb-hash`, `VAR` holds the account password. With `--smb-hash`, `VAR`
holds an NTLM hash (32 hex chars, or `LM:NT`) and the backend authenticates
via a typed hash credential — the hash is never converted to a password and
never surfaces in diagnostics. `--smb-user` is required for pass-the-hash
(a hash authenticates an account; it does not identify one). One NTLM
session-setup attempt; no share enumeration, no fallback chains.

**WinRM** — `check TARGET --port 5985 --protocol winrm` (requires the
`winrm` extra). Read-only WS-Man authentication probe: password
(`--credential-env`), NTLM hash (`--winrm-hash`), or Kerberos ticket
(`--winrm-ticket-env`; mutually exclusive). No shells, no commands, no
session establishment.

**RDP observation** — `check TARGET --port 3389 --protocol rdp`. One bounded
TPKT/X.224 pre-authentication exchange. Zero credentials, zero
authentication, zero session establishment. `RDP_RESPONSE_OBSERVED` plus the
server-selected security protocol (PROTOCOL_RDP / SSL / HYBRID / HYBRID_EX)
is an observation only; malformed and non-RDP responses fail closed.

**SOCKS5 CONNECT** — `proxy-check --proxy socks5://HOST:PORT TARGET --port P`
(requires the `socks` extra). One proxy, one destination, one port, one
attempt. Hostnames are resolved by the proxy, never locally. Proxy
credentials via `--proxy-auth-env` or the proxy URL; redacted everywhere.

UDP is deliberately unsupported: no response is not evidence of
unreachability, and PivotCheck does not make claims it cannot support.

## OPSEC Intelligence

```bash
pivotcheck opsec --action smb-auth --platform windows
```

Predictive analysis of the telemetry a validation action is reasonably
expected to produce on a named platform (`windows`, `linux`, `macos`;
actions: `ssh-auth`, `smb-auth`, `winrm-auth`, `tcp-connect`,
`socks5-connect`, `http-request`). Strictly predictive: PivotCheck never
observes target-side telemetry, never guarantees event generation, and
provides no evasion guidance. HTTPS is a distinct visibility profile
(`http-request` documents how TLS changes which bytes are observable on the
path) — visibility-changing, not stealthy.

## What-If Analysis

```bash
pivotcheck what-if \
  --network 10.50.0.0/16 --gateway 10.40.1.254 --interface eth1 \
  --network 10.60.0.0/16 --gateway 10.40.1.254 --interface eth1
```

Evaluates **hypothetical** routing changes (repeatable
`--network`/`--gateway`/`--interface` triplets) against observed evidence.
Every result is explicitly marked hypothetical: contradictions with observed
evidence are preserved and reported, unknowns are named, and nothing is
claimed as reachable, validated, or executable. Uses passive local discovery
only — no active validation is performed by `what-if`.

## Output Contract

Human output is evidence-first, with color on TTYs (`--no-color` disables).
Every command accepts `--json`, producing stable, deterministic, ANSI-free
output with schema and provenance fields:

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

## Exit Codes

| Code | Constant | Meaning |
|---|---|---|
| 0 | `EXIT_OK` | Success |
| 1 | `EXIT_FATAL` | Unrecoverable runtime failure |
| 2 | `EXIT_USAGE` | Invalid arguments or failed argument validation |
| 3 | `EXIT_RESOLVE` / `EXIT_BASELINE_NOT_FOUND` | Target network not present in the current model; baseline not found |
| 4 | `EXIT_BASELINE_SCHEMA` | Baseline file failed schema validation |

## Platform Support

| Platform | Collectors |
|---|---|
| Linux | `ip`, `ss`, `/etc/resolv.conf` |
| Windows | `ipconfig`, `route print`, `arp`, `netstat` (English-locale output required) |
| macOS | `ifconfig`, `netstat`, `arp`, `ndp`, `scutil --dns` |

macOS IPv6 neighbors are read from the local `ndp` neighbor table — observed
L2 presence only, never reachability. Remote collection over SSH expects
Linux-style tooling on the remote vantage point. Collectors that cannot run
degrade to warnings, never failures.

## Limitations

- Passive analysis shows what the evidence supports; it does not prove
  end-to-end reachability.
- A routed network is classified `MEDIUM` confidence, never presented as
  reachable.
- `check` `TIMEOUT` is ambiguous by nature and is never reported as proof
  either way.
- Baselines contain reconnaissance detail and are stored unencrypted by
  default — protect them accordingly. Encrypted-at-rest storage is available
  via the `encrypt` extra: `baseline create --encrypt --password-env VAR`
  (password supplied from the named environment variable, never the command
  line; Fernet + scrypt; wrong passwords and tampered files fail closed; a
  lost password means the baseline cannot be recovered). Reading or listing
  encrypted baselines requires the same `--password-env` flag. Encryption
  protects stored contents at rest only — it does not protect a compromised
  host, process, or password.
- Application-layer interaction beyond a single HTTP `HEAD` observation,
  SMB share access, remote execution, and SSH command execution are out of
  scope by design.

## Documentation

Focused documentation lives in [`docs/`](docs/):

- [Confidence model](docs/confidence-model.md)
- [Baseline workflow](docs/baseline-workflow.md)
- [Comparison semantics](docs/comparison-semantics.md)
- [Operator intelligence](docs/operator-intelligence.md)
- [Operator findings](docs/operator-findings.md)
- [Perspective map](docs/perspective-map.md)
- [SSH session providers](docs/session-providers.md)

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for
development setup and pull-request guidelines.

## Security

Report vulnerabilities privately per [SECURITY.md](SECURITY.md). Do not
open public issues for security reports.

## Feedback

Found a bug, usability issue, compatibility problem, or have a feature
request? Use the structured channels:

- [Report a Bug](https://github.com/Debajyoti0-0/pivotcheck/issues/new?template=bug_report.yml) — reproducible defects
- [Request a Feature](https://github.com/Debajyoti0-0/pivotcheck/issues/new?template=feature_request.yml) — new capability requests (evidence-gated)
- [Share Feedback](https://github.com/Debajyoti0-0/pivotcheck/issues/new?template=feedback.yml) — usability, documentation, compatibility, false positives/negatives

Never include passwords, private keys, NTLM hashes, Kerberos tickets, API
keys, or sensitive network data in any report. Redact before submitting.

## License

[GNU General Public License v3.0](LICENSE) — GPL-3.0-only.
