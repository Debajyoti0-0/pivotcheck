# PivotCheck

**Passive network discovery and pivot path validation for authorized security assessments.**

PivotCheck answers the question a foothold does *not*: **"what can I actually reach from here, what changed since I last looked, and what evidence-backed investigation should I perform next?"** It normalizes heterogeneous host network state (`ip`, `route`, `arp`/`neigh`, `ss`, `resolv.conf`) into one coherent model, classifies each reachable network with an explicit confidence level, correlates transit evidence, and explains every conclusion — instead of leaving you to stitch that picture together by hand.

> ⚠️ **Authorized use only.** PivotCheck is built for defensive review and sanctioned penetration testing. Only run it against systems and networks you are explicitly authorized to assess.

- **Repository:** <https://github.com/Debajyoti0-0/pivotcheck>
- **License:** GPL-3.0-only
- **Status:** v1.0.0 — stable release
- **Primary platform:** Linux for discovery; checks and baseline management are cross-platform

---

## Overview

PivotCheck is **not** a network scanner, exploitation framework, or automatic pivot engine. It is a decision-support tool that reduces the manual reasoning gap between observing a host's network state and deciding what explicit pivot-path validation to perform next.

The central epistemic rule, enforced throughout the architecture, tests, and output language:

```text
OBSERVED EVIDENCE ≠ INFERRED CONTEXT ≠ PRIORITY ≠ ACTIVE VALIDATION
```

No presentation layer invents evidence, no recommendation becomes validation, and no inferred conclusion is presented as directly observed fact.

## Why PivotCheck Exists

After gaining a foothold (or during a defensive review of one), an operator traditionally runs `ip route`, `arp -a`, `ss -tunap`, and `cat /etc/resolv.conf` manually and reasons about the results by hand. That reasoning is error-prone and, worse, tends to blur evidence ("a route exists") with conclusions ("therefore the network is reachable").

PivotCheck exists to make that reasoning explicit, deterministic, and honest:

1. **Collect** — normalize heterogeneous system state into one evidence model.
2. **Infer** — deterministic topology and transit analysis, clearly labeled as inference.
3. **Compare** — diff the current perspective against saved baselines.
4. **Prioritize** — rank investigation candidates by supporting evidence, deterministically.
5. **Validate** — only on explicit operator command, against one explicit target at a time.

Every conclusion is traceable backward: recommendation → analysis rule → inference → observed evidence.

## Core Capabilities

- **Passive discovery** (`discover`, `map`) — interfaces, routes, neighbors, DNS, and sockets from `ip`, `ss`, and `resolv.conf`; no host sweeps, no ICMP, no traceroute.
- **Confidence-classified networks** — `HIGH` (directly connected + interface up), `MEDIUM` (explicit route via gateway), `LOW` (inferred — never presented as fact).
- **Evidence gap analysis** (`gaps`) — six-state classification of what evidence exists and what is missing.
- **Candidate explanation** (`explain`) — the full evidence → inference → priority chain for one network.
- **Investigation ranking** (`next`) — one evidence-backed candidate, deterministically selected.
- **Baselines and comparison** (`baseline`, `compare`) — versioned persistence and diff analysis with operator intelligence views.
- **Explicit validation** (`check`, `proxy-check`) — single-target TCP and SOCKS5 CONNECT with precise result taxonomies.
- **Remote vantage points** — discovery over SSH using your existing agent/keys, with strict host-key verification.
- **Stable JSON** on every command, deterministic ordering, zero required runtime dependencies (Python standard library only).

## Safety and Scope

| Invariant | Enforcement |
|---|---|
| Passive commands perform zero network I/O | `discover`, `map`, `gaps`, `explain`, `compare`, `next`, `baseline` — verified by adversarial tests |
| No scanning of any kind | No CIDR expansion, no port ranges (max 16 explicit ports on `check`), no automatic target generation, no retries |
| Validation only on explicit operator action | `check` and `proxy-check` require explicit target + port per invocation |
| Credential safety | Memory-only, redacted in all output (`socks5://user:***@host`), `--proxy-auth-env` for environment-based passwords |
| Graceful degradation | An unreadable table becomes a warning, never a crash |
| Provenance ≠ authenticity | Timestamps identify generation time only; no cryptographic attestation |

## Installation

Requires Python **3.10+**.

```bash
pip install pivotcheck            # once published to PyPI, or:
pip install .                      # from a source checkout
```

For development (tests, linting, type-checking):

```bash
pip install -e ".[dev]"
```

This installs a `pivotcheck` console script. `python -m pivotcheck` is equivalent. The optional `[socks]` extra (PySocks) is kept for future protocol work; `proxy-check` itself ships a stdlib-only SOCKS5 client.

## Quick Start

```bash
# 1. Discover the current network perspective
pivotcheck discover

# 2. Topology-focused view with inferred pivot context
pivotcheck map --show-pivots

# 3. Identify the highest-priority investigation candidate
pivotcheck next

# 4. Explain that candidate's evidence chain
pivotcheck explain 10.50.0.0/16

# 5. Check what evidence is missing before validation
pivotcheck gaps 10.50.0.0/16

# 6. Explicitly validate one target (your choice, one attempt)
pivotcheck check 10.50.1.10 --port 443

# 7. Save a baseline, then compare later
pivotcheck baseline create --name pre-pivot
pivotcheck compare pre-pivot --recommend
```

## Commands

### discover

Full passive discovery: enumerate interfaces, routes, neighbors, DNS, and sockets, then classify reachable networks and potential pivot paths.

```bash
pivotcheck discover [--summary] [--interface IFACE] [--family ipv4|ipv6|all]
                    [--format text|json | --json]
pivotcheck discover --ssh jump-host          # collect from a remote vantage point
```

### map

The same discovery data as an interface/network topology view with confidence levels. `--show-pivots` shows **only** inferred pivot context (routing evidence — never confirmed reachability).

```bash
pivotcheck map [--focus NETWORK] [--changes-only] [--show-pivots]
               [--interface IFACE] [--family ...] [--baseline NAME] [--json]
```

### next

Selects the single highest-priority investigation candidate from current evidence, optionally enriched with baseline comparison context. Ranking is deterministic: priority (`HIGH > MEDIUM > LOW`), then evidence strength, then a stable network tie-break. No random behavior, no network activity.

```bash
pivotcheck next [--baseline NAME] [--json]
```

If no candidate can be derived, it reports `NO INVESTIGATION CANDIDATES` and exits `0` — that is a successful result, not a failure. `next` may say "investigate this network first"; it never says "a target in this network is reachable".

### gaps

Evidence gap analysis for one network. Classifies each evidence category into exactly one of six states: `OBSERVED`, `NOT_OBSERVED`, `NOT_COLLECTED`, `NEGATIVE_EVIDENCE`, `NOT_APPLICABLE`, `NOT_PERFORMED`. Passive only — no network I/O. Answers: "what evidence is missing before I validate this candidate?"

```bash
pivotcheck gaps 10.50.0.0/16 [--json]
```

### explain

Standalone explanation of why a network is a candidate, without requiring a baseline: the complete evidence → inference → priority chain (route, neighbor, connection, and transit evidence) with explicit limitations. `--baseline` adds comparison context.

```bash
pivotcheck explain 10.50.0.0/16 [--baseline NAME] [--json]
```

### check

Attempt a controlled TCP connection to one operator-selected host and classify the result precisely. **This is not a scanner:** ports must be listed explicitly, ranges are rejected, and at most 16 ports are accepted.

```bash
pivotcheck check 10.10.20.25 --port 445
pivotcheck check host.internal --port 445,3389 --timeout 3 --json
pivotcheck check 10.10.20.25 --port 445 --baseline pre-pivot   # add comparison context
```

Result statuses: `SUCCESS`, `REFUSED`, `TIMEOUT`, `NO_ROUTE`, `UNREACHABLE`, `DNS_ERROR`, `INVALID_TARGET`, `LOCAL_ERROR`. (`--timeout` accepts 0.1–30s, default 3.) A `TIMEOUT` is explicitly **ambiguous** and never treated as proof a host is offline.

### proxy-check

SOCKS5 proxy-path validation (RFC 1928 + RFC 1929). One operator-supplied proxy, one operator-supplied destination, one port, one attempt. Hostnames are resolved by the **proxy** (ATYP 0x03), never locally. Credentials are redacted in all output (`user:***@`).

```bash
pivotcheck proxy-check --proxy socks5://127.0.0.1:1080 10.10.20.25 --port 445
pivotcheck proxy-check --proxy socks5://user:pass@proxy.internal:1080 target.internal --port 443 --json
```

The result is staged — proxy TCP → SOCKS5 negotiation → destination CONNECT — and reports exactly which stage failed. The verdict is `VALIDATED` only when all three stages succeeded. Validation success means only that the proxy accepted the CONNECT request at test time — not general reachability or pivot capability. `--baseline` is deliberately not offered: passive topology evidence cannot be meaningfully compared to an active SOCKS5 transaction.

### baseline

Save and manage perspectives. Names are 1–63 lowercase letters, digits, or hyphens.

```bash
pivotcheck baseline create --name pre-pivot   # discover + save
pivotcheck baseline list
pivotcheck baseline show pre-pivot
pivotcheck baseline delete pre-pivot --yes
```

Baselines are stored as versioned JSON with atomic writes. The directory resolves as: `--data-dir PATH` (highest), then `PIVOTCHECK_DATA_DIR`, then the platform default (`%LOCALAPPDATA%\pivotcheck` on Windows, `$XDG_DATA_HOME/pivotcheck` or `~/.local/share/pivotcheck` elsewhere). Baselines contain sensitive reconnaissance evidence and are not encrypted — store them accordingly. See [`docs/baseline-workflow.md`](docs/baseline-workflow.md).

### compare

Diff the current perspective against a saved baseline.

```bash
pivotcheck compare pre-pivot                       # full change detail
pivotcheck compare pre-pivot --summary             # concise change summary
pivotcheck compare pre-pivot --evidence            # evidence behind each change
pivotcheck compare pre-pivot --recommend           # rule-based next steps
pivotcheck compare pre-pivot --explain 10.10.20.0/24
pivotcheck compare pre-pivot --json --output result.json --force
```

The view flags (`--summary`, `--evidence`, `--recommend`, `--explain`) are mutually exclusive; filters (`--interface`, `--family`, `--changes-only`, `--minimum-confidence`) compose with any view. `--output` requires JSON format. See [`docs/comparison-semantics.md`](docs/comparison-semantics.md) and [`docs/operator-intelligence.md`](docs/operator-intelligence.md).

## Remote collection (SSH)

`discover`, `map`, and `baseline create` accept a remote vantage point. Authentication uses your existing SSH agent/keys/config; host keys are verified **strictly** by default.

```bash
pivotcheck discover --ssh jump-host
pivotcheck discover --ssh-user operator@10.0.0.5 --ssh-port 2222
pivotcheck baseline create --name from-jump --ssh jump-host --ssh-accept-new-hostkeys
```

`--ssh-accept-new-hostkeys` enables trust-on-first-use only; changed keys are still rejected. `--ssh-timeout` accepts up to 60s (default 10). Only the fixed collector command set is ever sent remotely — there is no generic remote-execution API. Details: [`docs/session-providers.md`](docs/session-providers.md).

## Architecture

### Design Principles

1. Observed facts remain distinguishable from inference; inference from prioritization; prioritization from validation.
2. No automatic target expansion without explicit operator intent.
3. Analysis is deterministic and side-effect free.
4. Output layers do not invent evidence.
5. Every documented semantic state is model-valid and derivation-reachable.
6. The CLI is orchestration, not business logic.

### Dependency Direction

```text
MODELS → DISCOVERY / NORMALIZATION → ANALYSIS → OUTPUT → CLI
```

Lower layers never depend on higher presentation or orchestration layers (`models ──X──> cli`, `analysis ──X──> cli`, `output ──X──> discovery`, `models ──X──> output`). Persistence and validation interact with models and analysis but never create circular dependencies.

### Core Components

```text
┌──────────────────────────────────────────────────────────────┐
│                           CLI                                │
│  discover | map | next | gaps | explain | check |            │
│  proxy-check | baseline | compare                            │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                 DISCOVERY / COLLECTION                       │
│     local providers | remote SSH providers | parsers         │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│              NORMALIZED MODELS                               │
│  Interface | Address | Route | Neighbor | Connection |       │
│  DNS | Network | PivotPath | DiscoverySnapshot               │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│              PURE ANALYSIS LAYER                             │
│  topology | comparison | recommendation | gateway |          │
│  transit priority | next-step selection                      │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│              OPERATOR INTELLIGENCE                           │
│  DiffReport | Recommendation | TransitEvidence |             │
│  ComparisonContext | NextStepCandidate                       │
└──────────────────────────────┬───────────────────────────────┘
                               ▼
┌──────────────────────────────────────────────────────────────┐
│              OUTPUT / SERIALIZATION                          │
│  text renderers | JSON renderers | deterministic ordering    │
└──────────────────────────────────────────────────────────────┘
```

### Discovery

Discovery collects facts without deciding whether something is an interesting pivot. Raw command output flows through parsers into normalized domain models, assembled into a `DiscoverySnapshot` — the boundary between collection and analysis. For example, the raw route `10.50.0.0/16 via 10.10.20.254 dev eth1 metric 50` becomes a normalized `Route` model; the conclusion "this is a viable pivot" belongs to the higher analysis layer, never the parser.

Collection is provider-based: a `LocalProvider` runs local subprocesses; an `SSHProvider` delegates to the system OpenSSH client against the same fixed collector commands. Everything downstream is provider-agnostic.

### Analysis

Analysis is a set of pure, deterministic functions:

- **Topology** — networks inferred from interfaces and routes, with confidence levels.
- **Transit evidence** — a composition layer correlating route + neighbor + connection evidence into states such as `MULTIPLE_SUPPORTING_SIGNALS`, `ROUTING_ONLY`, `ROUTING_PLUS_L2_EVIDENCE`, `CONTRADICTORY_EVIDENCE`, and `INSUFFICIENT_EVIDENCE`. Every declared state is documented, model-valid, and reachable from the derivation function — the three sets are equal by construction and by test.
- **Comparison** — a pure relationship analysis between two snapshots producing `NEW`, `EXPANDED`, `REDUCED`, `MORE_SPECIFIC`, `CONTEXT_CHANGED`, `UNCHANGED`. Comparison answers "what changed?", never "what is reachable?".
- **Recommendation** — deterministic rules over comparison findings: priority, reason, network, supporting context. Decision support, not proof.
- **Next-step selection** — candidate construction and ranking: priority → evidence strength → deterministic network tie-break. No random behavior, no network activity.

### Output

All output modules consume already-derived domain/report objects. Renderers never perform discovery, infer topology, assign priority, alter evidence, or validate anything.

### CLI

The CLI is the composition root. Each command handler follows the same shape: validate arguments → collect/load input → call pure domain/analysis functions → render result → return an explicit exit code. Selection, comparison, and ranking logic are never duplicated in handlers.

## Evidence Model and Semantics

### Evidence vs Inference

The evidence hierarchy is never collapsed:

```text
LEVEL 1 — OBSERVED            directly collected facts
          (route, neighbor, connection, interface)
              ↓ deterministic analysis
LEVEL 2 — INFERRED            network classification, pivot path,
          transit assessment, topology relationship
              ↓ deterministic prioritization
LEVEL 3 — PRIORITIZED         HIGH / MEDIUM / LOW / NONE
              ↓ explicit operator action
LEVEL 4 — ACTIVE VALIDATION   TCP result, SOCKS5 verdict
```

### Evidence States

`gaps` classifies every evidence category into one of six states: `OBSERVED`, `NOT_OBSERVED`, `NOT_COLLECTED`, `NEGATIVE_EVIDENCE`, `NOT_APPLICABLE`, `NOT_PERFORMED`. `NOT_OBSERVED` and `NEGATIVE_EVIDENCE` are distinct: absence of evidence is never silently treated as negative evidence, and vice versa.

### Confidence and Priority

Network confidence (`HIGH`/`MEDIUM`/`LOW`) describes how directly the *observation* supports the classification. Priority (`HIGH`/`MEDIUM`/`LOW`/`NONE`) describes how strongly the evidence argues for *operator attention*. The two are independent axes and are never conflated.

### Limitations

Every analytical output states what the evidence does not prove. Passive outputs never say: "target reachable", "pivot confirmed", "network accessible", or "boundary bypassed". Active validation outputs are scoped to the explicit target and port checked.

Warnings and limitations are distinct concepts: **warnings** describe what may have affected collection completeness (e.g., "neighbor collection unavailable"); **limitations** describe what the evidence fundamentally does not prove (e.g., "route evidence does not prove active reachability").

### Perspective

All evidence belongs to exactly one vantage point — local or a single SSH host — identified in the output (`provider`, source, timestamp). No multi-host correlation occurs within one invocation.

## Output Contracts

### Human Output

Human output is evidence-first, operationally concise, and consistent across commands: observed evidence, inferred context, priority, and validation results are visually separated. Color is auto-enabled on a TTY and changes presentation only — the semantic content is identical with `--no-color`.

### JSON Output

Every command supports `--json` (alias for `--format json`). JSON output carries no ANSI codes, is safe to pipe, and follows a stable per-command schema (e.g., `CheckReport.to_dict()`, `NextStepReport.to_dict()`, `ProxyCheckReport.to_dict()`). Verbose diagnostics (`-v`) always go to stderr and never contaminate JSON stdout.

### Schema Versioning

JSON payloads carry `tool`, `version` (the package version), `command`, `timestamp`, and a `schema_version`. Additive changes evolve the minor schema version; breaking structural changes require a major version. Automation consumers are never silently broken.

### Evidence Provenance

Payloads identify their source: provider (`local`/`ssh`), vantage point, and generation timestamp. Provenance is identification, not attestation — timestamps are not cryptographic proof of anything.

### Determinism

Same input → same normalized result → same ordering → same semantic output. Ordering is priority, then confidence, then canonical network ordering, with stable lexical tie-breaks. JSON never depends on dictionary insertion accidents or collection timing.

### Exit codes

**`discover` / `map`**

| Code | Meaning |
|------|---------|
| 0 | Discovery completed (partial collector degradation is reported, not failed) |
| 1 | Fatal execution failure (discovery engine could not run) |
| 2 | Invalid CLI usage |

**`check`**

| Code | Meaning |
|------|---------|
| 0 | Check executed normally (SUCCESS / REFUSED / TIMEOUT are data, not failures) |
| 1 | Fatal internal/local failure |
| 2 | Invalid CLI usage |
| 3 | Target could not be resolved, or requested `--baseline` not found |
| 4 | Requested `--baseline` is invalid/unsupported |

**`proxy-check`**

| Code | Meaning |
|------|---------|
| 0 | Validation executed (VALIDATED / REFUSED / TIMEOUT / AUTH_FAILED / CONNECT reply codes are data, not failures) |
| 1 | Fatal internal/local failure |
| 2 | Invalid CLI usage (proxy URL, target, port, timeout) |
| 3 | The **proxy** endpoint name could not be resolved (DNS_ERROR); the destination is never resolved locally |

## Protocol Scope

PivotCheck implements **two validation protocols**, both at the transport layer:

| Protocol | Command | Scope |
|---|---|---|
| **TCP** | `check` | Explicit target + explicit ports, single connection attempt per address:port |
| **SOCKS5 CONNECT** | `proxy-check` | Explicit proxy + explicit destination + explicit port, one three-stage transaction |

### Explicitly deferred: UDP

Connectionless semantics make UDP epistemically hazardous: no response ≠ unreachable, and a `TIMEOUT` would be even more ambiguous than TCP's. Doing this honestly would require distinct evidence states (`UDP_RESPONSE_OBSERVED`, `ICMP_*_OBSERVED`) and a strict ban on claiming "port open" from silence alone. It is deferred indefinitely — TCP + SOCKS5 CONNECT cover the pivot-validation need, and `nmap -sU` / `nc -u` exist for UDP.

### Explicitly out of scope: application protocol validation

`check` validates the network path and transport acceptance only. TCP 22 reachable ≠ SSH session; TCP 445 reachable ≠ SMB share access; TCP 3389 reachable ≠ RDP session. SSH, Telnet, HTTP CONNECT, SOCKS4/4a, UDP ASSOCIATE, BIND, SMB, WinRM, LDAP, RDP, and DNS are all deliberately rejected — application-layer protocols have fundamentally different evidence models and are better served by specialized tooling (`nmap -sV`, `impacket`, dedicated clients). PivotCheck answers *"Is the network path open and does the transport layer accept the connection?"* — never *"Does the service work correctly?"*

There is deliberately no generic `ValidationTransport` plugin framework: each protocol adds a parser, state machine, and error taxonomy, and "just add one more protocol" is a scope-creep vector. `checks/tcp.py` and `checks/proxy.py` are two independent, focused engines whose semantics are intentionally different (direct vs. relayed).

### Future protocol admission criteria

A new protocol would be considered only if **all** of the following hold:

1. Real operator workflow gap that TCP/SOCKS5 cannot answer.
2. Transport-layer focus (network path + transport acceptance, not application logic).
3. Deterministic, finite, documented status taxonomy.
4. Explicit target only — no scanning, no ranges.
5. Single transaction, bounded timeout, no retries.
6. No credential persistence.
7. Existing tooling insufficient for the need.

No protocol currently meets all criteria.

## Baselines and Comparison

Comparison analyzes **coverage** separately from the evidence describing that coverage. For CIDR blocks in one address family, overlap always means equality or containment, so the coverage view collapses adjacent subnets (`ipaddress.collapse_addresses()`): two baseline `/25`s covered by a current `/24` is *not* new reachability, and a current `/24` beneath a baseline `/16` is a more-specific topology observation, not new coverage. IPv4 and IPv6 are independent. An exact CIDR with a different interface, gateway, route type, or confidence is a route-context change, not a new network.

Deeper detail: [`docs/comparison-semantics.md`](docs/comparison-semantics.md), [`docs/perspective-map.md`](docs/perspective-map.md).

## Operator Intelligence

The comparison views and `next` form an operator workflow:

```text
discover → map → baseline create → compare → compare --recommend
        → next --baseline NAME → explicit check TARGET --port PORT
```

Recommendations are deterministic: new high-confidence connected evidence is `HIGH`; new or expanded routed evidence is `MEDIUM`; inferred pivot paths are `LOW`. Every recommendation carries its reason, supporting evidence lines, a suggested action template, and the explicit limitation. Filtering (`--interface`, `--family`, `--focus`, `--changes-only`, `--minimum-confidence`) is presentation/query logic that never changes discovery or comparison semantics. `compare --output PATH` writes the exact stdout payload atomically and refuses to overwrite without `--force`.

Deeper detail: [`docs/operator-intelligence.md`](docs/operator-intelligence.md).

## Security and Safety Guarantees

- **Zero network I/O in passive analysis** — verified by an adversarial test suite covering sockets, subprocesses, filesystem, and environment side effects.
- **No hidden scanning** — no CIDR expansion, no port ranges, no automatic targets, no implicit retries.
- **Credential safety** — no persistence, structural exclusion from serialization, redaction in text and JSON, environment-variable support via `--proxy-auth-env`.
- **SSH safety** — strict host-key verification by default, fixed argv remote commands, no shell interpolation, bounded timeouts.
- **Deterministic behavior** — identical inputs produce identical outputs; ranking has no random component.

Violations of these invariants are security bugs — see [Security Reporting](#security-reporting).

## Development and Testing

```bash
pip install -e ".[dev]"
pytest                       # unit tests (integration-marked tests deselected by default)
pytest -m integration        # integration tests (live OS/network resources)
ruff check .
mypy pivotcheck
python -m build              # wheel + sdist
```

The test suite (650+ tests: unit and integration, including extensive regression coverage) covers determinism and input-order independence, network safety (zero passive I/O), side-effect safety, CLI contracts (exit codes, JSON, help), JSON schema stability, and an epistemic language audit. Tests use OS-command fixtures (`tests/fixtures/`) so parsers are exercised without touching live network state. If your default system temp directory is unwritable (e.g., a OneDrive-synced Windows profile), `conftest.py` transparently redirects pytest's temporary files to a project-local `.pytest_tmp/`; healthy environments are unaffected.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow, architectural invariants, and contribution standards. In short: preserve the evidence hierarchy, the dependency direction, and the network-safety invariants; add tests for every change; no new protocols, scanning features, or credential persistence.

## Security Reporting

See [SECURITY.md](SECURITY.md). Report vulnerabilities privately via GitHub security advisories at <https://github.com/Debajyoti0-0/pivotcheck/security/advisories> — **do not** open public issues for security vulnerabilities.

## License

PivotCheck is licensed under the [GNU General Public License v3.0](LICENSE) (GPL-3.0-only). Copyright (c) 2026 PivotCheck contributors.
