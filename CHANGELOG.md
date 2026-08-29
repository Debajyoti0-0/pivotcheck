# PivotCheck — Release Notes v0.1.0

**Release Date:** 2026-08-29  
**Status:** Initial public release candidate

---

## Overview

PivotCheck is a passive network discovery and pivot path validation tool for authorized security assessments. It answers the practical question: **"From my current network vantage point, what networks, routes, topology relationships, and transit opportunities can I observe—and what should I investigate next?"**

PivotCheck is **not** a network scanner, exploitation framework, or automatic pivot engine. It is a decision-support tool that reduces the manual reasoning gap between observing a compromised host's network state and deciding what explicit pivot-path validation should be performed next.

---

## Core Capabilities

### Passive Discovery (`discover`, `map`)
- **Interfaces, routes, neighbors, DNS, sockets** — Normalized from `ip`, `ss`, `resolv.conf` (Linux)
- **Confidence-classified networks** — HIGH (directly connected), MEDIUM (explicit route), LOW (inferred)
- **Graceful degradation** — Unreadable tables become warnings, never crashes
- **SSH remote vantage** — `--ssh host` for remote collection using existing agent/keys
- **Stable JSON output** — `--json` on every command, deterministic ordering

### Baseline & Comparison (`baseline`, `compare`)
- **Versioned persistence** — Atomic writes, schema validation, forward-compatibility rejection
- **Diff analysis** — NEW, EXPANDED, REDUCED, MORE_SPECIFIC, CONTEXT_CHANGED, UNCHANGED
- **Evidence-preserving views** — `--summary`, `--evidence`, `--recommend`, `--explain NETWORK`
- **Filtering** — `--interface`, `--family`, `--changes-only`, `--minimum-confidence`

### Deterministic Prioritization (`next`)
- **Evidence-driven ranking** — Transit evidence correlation (routes + neighbors + connections)
- **Priority levels** — HIGH > MEDIUM > LOW > NONE (deterministic tie-breaking)
- **Operator decision support** — Explicit limitation text, suggested action template
- **Baseline-aware** — `--baseline` adds comparison context to candidate

### Evidence Gap Analysis (`gaps`) — **NEW in v0.1.0**
- **Six-state classification** — OBSERVED, NOT_OBSERVED, NOT_COLLECTED, NEGATIVE_EVIDENCE, NOT_APPLICABLE, NOT_PERFORMED
- **Passive only** — No network I/O, pure analysis
- **Answers** — "What evidence is missing before I validate this candidate?"

### Candidate Explanation (`explain`) — **NEW in v0.1.0**
- **Standalone explanation** — `explain NETWORK` without baseline required
- **Evidence→Inference→Priority chain** — Route + Neighbor + Connection + Transit evidence
- **Comparison context** — Optional `--baseline` for change context
- **Explicit limitations** — Every output states what the evidence does not prove

### Explicit Validation (`check`, `proxy-check`)
- **`check`** — Single-target TCP with precise status taxonomy (SUCCESS, REFUSED, TIMEOUT, NO_ROUTE, UNREACHABLE, DNS_ERROR, INVALID_TARGET, LOCAL_ERROR)
- **`proxy-check`** — SOCKS5 CONNECT validation (RFC 1928 + RFC 1929), 3-stage: proxy TCP → negotiation → CONNECT
- **Credential safety** — `--proxy-auth-env` for environment-based passwords, redaction in all output
- **Single transaction invariant** — One proxy, one destination, one port, one attempt

---

## Architecture

### Evidence Hierarchy (Never Collapsed)
```
RAW SYSTEM OBSERVATION
       ↓
NORMALIZED DISCOVERY EVIDENCE
       ↓
DETERMINISTIC INFERENCE
       ├── Network topology
       ├── Pivot context
       └── Transit assessment
       ↓
OPERATOR PRIORITIZATION
       ↓
EXPLICIT OPERATOR VALIDATION
```

### Layered Architecture
```
Models
   ↓
Discovery
   ↓
Analysis
   ↓
Output
   ↓
CLI
```

### Safety Invariants
- **Zero network I/O in passive analysis** — Verified by adversarial test suite
- **No CIDR expansion, no port ranges, no automatic scanning** — Enforced at CLI layer
- **No automatic validation** — Operator must explicitly choose target + port
- **Credential redaction** — All output paths redact `socks5://user:pass@host` → `socks5://user:***@host`
- **Provenance ≠ Authenticity** — Timestamps identify generation time; no cryptographic attestation

---

## Protocol Scope

| Protocol | Status | Rationale |
|----------|--------|-----------|
| **TCP** | ✅ Implemented | Core validation primitive |
| **SOCKS5 CONNECT** | ✅ Implemented | Pivot validation primitive |
| **UDP** | ❌ Deferred | Connectionless semantics require careful epistemic design |
| **SSH / Telnet / HTTP CONNECT / SMB / WinRM / LDAP / RDP** | ❌ Rejected | Application layer — use specialized tooling |

---

## Platform Support

| Platform | Discovery | Validation | Baseline/Compare |
|----------|-----------|------------|------------------|
| Linux | ✅ Full | ✅ | ✅ |
| Windows | ❌ | ✅ | ✅ |
| macOS | ❌ | ✅ | ✅ |

*Discovery requires Linux `ip`, `ss`, `resolv.conf`. Validation and baselines are cross-platform.*

---

## Requirements

- **Python** ≥ 3.10 (verified on 3.14; CI tests 3.10–3.14)
- **Runtime dependencies:** ZERO (stdlib only)
- **Optional extra:** `pip install "pivotcheck[socks]"` — PySocks (unused by current implementation)

---

## Installation

```bash
pip install pivotcheck
# or from source:
pip install -e ".[dev]"  # development with tests, linting, type-checking
```

---

## Quick Start

```bash
# 1. Discover current network perspective
pivotcheck discover

# 2. Topology-focused view
pivotcheck map --show-pivots

# 3. Identify highest-priority investigation candidate
pivotcheck next

# 4. Explain a candidate in detail
pivotcheck explain 10.50.0.0/16

# 5. Check what evidence is missing
pivotcheck gaps 10.50.0.0/16

# 6. Explicitly validate a target
pivotcheck check 10.50.1.10 --port 443

# 7. Save baseline for later comparison
pivotcheck baseline create --name pre-pivot

# 8. Later: compare against baseline
pivotcheck compare pre-pivot --recommend
```

---

## Evidence Semantics

PivotCheck never collapses these distinctions:

| Stage | Example Language |
|-------|-----------------|
| **Observed** | "Route to 10.50.0.0/16 via 10.10.20.1 observed" |
| **Inferred** | "Transit candidate with MEDIUM confidence" |
| **Prioritized** | "HIGH priority: multiple supporting signals" |
| **Validated** | "TCP check: SUCCESS on 10.50.1.10:443" |

**Never** says: "Target reachable", "Pivot confirmed", "Network accessible", "Boundary bypassed" based on passive evidence alone.

---

## Limitations (Explicitly Documented)

1. **Linux-only discovery** — Requires `ip`, `ss`, `resolv.conf`
2. **No UDP validation** — Epistemic constraints documented
3. **No application-protocol validation** — SSH, SMB, WinRM, LDAP, RDP, HTTP CONNECT out of scope
4. **No batch/scanning** — Explicit per-target only
5. **Provenance ≠ Authenticity** — Timestamps identify generation time; no cryptographic attestation
6. **Single vantage point** — No multi-host correlation in one invocation
7. **Passive baselines only** — Cannot compare active validation to passive topology

---

## Testing

```bash
# Development setup
pip install -e ".[dev]"

# Run all tests
pytest

# Unit tests only
pytest -m "not integration"

# Integration tests (require live OS/network)
pytest -m integration

# Linting
ruff check .

# Type checking
mypy pivotcheck
```

**Test suite:** 733 tests (549 unit + 4 integration + 184 regression) covering:
- Determinism & input-order independence
- Network safety (zero passive I/O)
- Side-effect safety (FS, env, sockets, processes)
- CLI contract (exit codes, JSON, help)
- JSON schema stability
- Epistemic language audit

---

## License

MIT License — see [LICENSE](LICENSE)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for architecture invariants, development workflow, and contribution standards.

## Security

See [SECURITY.md](SECURITY.md) for responsible disclosure policy and security invariants.

---

## Related Documentation

- [PROJECT_ARCHITECTURE.md](PROJECT_ARCHITECTURE.md) — System architecture
- [PROJECT_OUTPUT.md](PROJECT_OUTPUT.md) — Output contracts
- [PROTOCOL_SCOPE.md](PROTOCOL_SCOPE.md) — Protocol decisions
- [SECURITY.md](SECURITY.md) — Security policy
- [STAGE_E_RELEASE_CHECKLIST.md](STAGE_E_RELEASE_CHECKLIST.md) — Release tracking