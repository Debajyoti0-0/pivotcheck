# Changelog

All notable changes to PivotCheck are documented in this file.

## [Unreleased]

### Added — 2.0 development line (Steps 1–7)

- **Credential abstraction** — typed credential model (password, NTLM
  hash, SSH private key, Kerberos ticket) with secret-safe
  representation (`secret=[REDACTED]` in every string form; `secret_present`
  instead of material in JSON) and an explicit environment loader that
  reads exactly one named variable, never enumerates the environment,
  and never persists values.
- **SSH validation** — one public-key authentication attempt against one
  operator-specified target:port via the system OpenSSH client; strict
  host-key verification; server-identity verification reported separately
  from authentication success.
- **SMB validation** — one NTLM session-setup attempt against one
  operator-specified target:port via the optional `smb` extra
  (smbprotocol); guest fallback refused by construction; no share
  enumeration or execution. NTLM hash pass-the-hash is honestly
  unsupported by the current backend.
- **WinRM validation** — one WS-Man authentication attempt (read-only
  Get on the service configuration resource — no shell, no command)
  against one operator-specified target:port via the optional `winrm`
  extra (pywinrm); HTTPS certificate verification always on.
- **Credential/host correlation** — pure analysis ranking credential/host
  validation candidates from evidence, with explicit negative and
  contradictory-evidence handling.
- **Multi-hop graph intelligence** — evidence-bounded directed graph over
  normalized discovery evidence with bounded simple-path discovery;
  path status describes evidence composition (never capability).
- **OPSEC intelligence** (`opsec --action ACTION --platform PLATFORM`) —
  predictive analysis of the telemetry a validation action is reasonably
  expected to produce on Windows/Linux. Predictive only: PivotCheck does
  not observe target telemetry and provides no evasion, suppression, or
  security-control bypass guidance.

All validation capabilities enforce one target, one port, one credential,
one attempt — no scanning, retries, fallback chains, or execution.
Optional extras keep the runtime core dependency-free.

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
