# Changelog

All notable changes to PivotCheck are documented in this file.

## [1.0.0] — 2026-08-30

Initial stable public release.

PivotCheck is a passive network discovery and pivot path validation tool for authorized security assessments. It answers the practical question: **"From my current network vantage point, what networks, routes, topology relationships, and transit opportunities can I observe — and what should I investigate next?"**

PivotCheck is **not** a network scanner, exploitation framework, or automatic pivot engine. It is a decision-support tool that reduces the manual reasoning gap between observing a host's network state and deciding what explicit pivot-path validation to perform next.

### Added

- **Passive discovery** (`discover`, `map`) — interfaces, routes, neighbors, DNS, and sockets normalized from `ip`, `ss`, and `resolv.conf`; confidence-classified networks (`HIGH`/`MEDIUM`/`LOW`); graceful degradation (unreadable tables become warnings, never crashes); SSH remote vantage points with strict host-key verification.
- **Evidence correlation and explanation** (`next`, `explain`) — deterministic transit-evidence correlation across routes, neighbors, and connections; evidence → inference → priority chain; deterministic ranking with stable tie-breaking; explicit limitation text on every output; optional baseline comparison context.
- **Evidence gap analysis** (`gaps`) — six-state classification (`OBSERVED`, `NOT_OBSERVED`, `NOT_COLLECTED`, `NEGATIVE_EVIDENCE`, `NOT_APPLICABLE`, `NOT_PERFORMED`); passive only, zero network I/O.
- **Baseline management and comparison** (`baseline`, `compare`) — versioned JSON persistence with atomic writes and schema validation; diff analysis (`NEW`, `EXPANDED`, `REDUCED`, `MORE_SPECIFIC`, `CONTEXT_CHANGED`, `UNCHANGED`); evidence-preserving views (`--summary`, `--evidence`, `--recommend`, `--explain`); composable filters; atomic JSON artifact output.
- **Explicit validation** (`check`) — single-target TCP with a precise status taxonomy (`SUCCESS`, `REFUSED`, `TIMEOUT`, `NO_ROUTE`, `UNREACHABLE`, `DNS_ERROR`, `INVALID_TARGET`, `LOCAL_ERROR`); at most 16 explicit ports; ambiguous `TIMEOUT` never treated as proof a host is offline.
- **Explicit validation** (`proxy-check`) — SOCKS5 CONNECT (RFC 1928 + RFC 1929) in three stages: proxy TCP → negotiation → destination CONNECT; staged result reporting; `VALIDATED` only when every stage succeeded; proxy-side DNS resolution (ATYP 0x03); single-transaction invariant (one proxy, one destination, one port, one attempt).
- **Operator intelligence** — deterministic recommendation rules; mutually exclusive comparison views; deterministic candidate ranking with network tie-breaks; suggested action templates.
- **Output contracts** — stable, deterministic, ANSI-free JSON with `tool`/`version`/`schema_version` provenance on every command; documented exit codes; credential redaction in all output paths.

### Network safety invariants

- Zero network I/O in passive analysis — verified by an adversarial test suite.
- No CIDR expansion, no port ranges, no automatic target generation, no retries.
- No automatic validation of analysis candidates — the operator explicitly chooses every target and port.
- Credential memory-only handling with redaction in all output.
- Provenance identifies generation time and source vantage point; it is not cryptographic attestation.

### Platform support

| Platform | Discovery | Validation | Baseline/Compare |
|----------|-----------|------------|------------------|
| Linux    | ✅ Full   | ✅         | ✅               |
| Windows  | ❌        | ✅         | ✅               |
| macOS    | ❌        | ✅         | ✅               |

Discovery requires Linux `ip`, `ss`, and `resolv.conf`. Validation and baselines are cross-platform.

### Requirements

- Python ≥ 3.10 (CI tests 3.10–3.14)
- Zero required runtime dependencies (standard library only)
- Optional extra: `pip install "pivotcheck[socks]"` (PySocks; unused by the current implementation)

### License

GPL-3.0-only — see [LICENSE](LICENSE).
