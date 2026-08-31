# Changelog

All notable changes to PivotCheck are documented in this file.

## [2.0.2] — 2026-08-31

### Fixed

- `gaps` and `explain` no longer crash with a raw Python traceback when the
  network argument is not a valid CIDR or IP address (for example
  `gaps 999.999.1.0/24` or `explain not-a-cidr`). Invalid input now fails
  through the standard CLI error contract: a clean `[-]` message on stderr,
  exit code 2, an empty stdout (JSON output emits no partial artifact), and
  no discovery or other side effects. Valid CIDR, bare-IP, host-bit, and
  IPv6 behavior is unchanged. Found during Stage 9 release-consumer
  validation against the public 2.0.0 artifact; still present in the
  published 2.0.1, which shipped before this fix existed.

## [2.0.1] — 2026-08-31

### Fixed

- `explain` no longer classifies a network that is absent from the current
  discovery snapshot as `CURRENT_EVIDENCE`. Absent networks are now
  classified `NOT_OBSERVED` ("Network not found in current discovery
  evidence."), matching the limitations the same output already carried.
  Found during Stage 9 operator-workflow validation: explaining a
  mistyped/unobserved network produced a contradictory claim of
  observation. Classification for genuinely observed networks is
  unchanged, including comparison modes (`NEW_REACHABILITY`, etc.).

## [2.0.0] — 2026-08-31

The 2.0 release turns PivotCheck into a cross-platform, evidence-driven
credential/path validation platform — while preserving every v1.0.0
invariant: passive analysis does no network I/O, active validation stays
one target / one port / one credential / one attempt, and possession of a
credential never implies that it works.

### Added

- **Credential abstraction** — typed credential model (password, NTLM
  hash, SSH private key, Kerberos ticket) with secret-safe representation
  (`secret=[REDACTED]` in every string form; `secret_present` instead of
  material in JSON) and an explicit environment loader that reads exactly
  one named variable, never enumerates the environment, and never
  persists values.
- **SSH validation** (`check --protocol ssh`) — one public-key
  authentication attempt against one operator-specified target:port via
  the system OpenSSH client; strict host-key verification (accept-new is
  an explicit opt-in); server-identity verification reported separately
  from authentication success.
- **SMB validation** (`check --protocol smb`) — one NTLM session-setup
  attempt against one operator-specified target:port via the optional
  `smb` extra (smbprotocol); guest fallback refused by construction; no
  share enumeration or execution. NTLM hash pass-the-hash is honestly
  unsupported by the current backend and returns
  `UNSUPPORTED_CREDENTIAL`.
- **WinRM validation** (`check --protocol winrm`) — one WS-Man
  authentication attempt (a read-only Get on the service configuration
  resource — no shell, no command) against one operator-specified
  target:port via the optional `winrm` extra (pywinrm); HTTPS
  certificate verification always on; TLS failures are distinct from
  authentication failures.
- **Credential/host correlation** — pure analysis ranking credential/host
  validation candidates from evidence, with explicit negative and
  contradictory-evidence handling and deterministic ordering.
- **Multi-hop graph intelligence** — evidence-bounded directed graph over
  normalized discovery evidence with bounded simple-path discovery;
  path status describes evidence composition (never capability).
- **OPSEC intelligence** (`opsec --action ACTION --platform PLATFORM`) —
  predictive analysis of the telemetry a validation action is reasonably
  expected to produce on Windows/Linux. Predictive only: PivotCheck does
  not observe target telemetry and provides no evasion, suppression, or
  security-control bypass guidance.
- **Windows/macOS discovery collectors** — the passive discovery engine
  now works on Windows (`ipconfig`, `route print`, `arp`, `netstat`,
  `tasklist`) and macOS (`ifconfig`, `netstat`, `arp`, `scutil`), sharing
  the same normalized evidence contract as Linux.

### Changed

- `check --protocol` now accepts `tcp` (default), `ssh`, `smb`, and
  `winrm`; credential material is supplied only via environment
  variables (`--ssh-key-env`, `--credential-env`) — never command-line
  arguments. The default TCP path is unchanged.
- Check JSON envelopes gain an additive `protocol` field (schema 1.1).
- Optional extras `smb` (smbprotocol) and `winrm` (pywinrm) were added;
  the runtime core remains dependency-free.

### Security

- All validation capabilities enforce one target, one port, one
  credential, one attempt — no scanning, retries, fallback chains, share
  enumeration, or command execution.
- Credential material is structurally excluded from every string and
  serialized representation and stripped defensively from third-party
  error text.
- Guest-session fallback is refused by construction for SMB.
- OPSEC intelligence is predictive analysis only and provides no evasion,
  suppression, or security-control bypass guidance.

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
