# PivotCheck — Final Operator Gap Analysis

**Status:** Authoritative gap assessment derived from live code inspection, architecture documents, and red-team workflow review.

**Date:** 2026-08-29

---

## 1. Red-Team Workflow Coverage Assessment

| Workflow Stage | PivotCheck Capability | Current Implementation | Residual Operator Burden |
|---|---|---|---|
| **Foothold → Local Visibility** | `discover` (interfaces, routes, neighbors, DNS, sockets; SSH vantage) | Full — normalized `DiscoverySnapshot`, graceful degradation | None significant |
| **Route/Topology Understanding** | `map` (confidence-graded, interface-aware, pivot context) | Full — CONNECTED/ROUTED/INFERRED classification | Minor: multi-interface ambiguity prose in output |
| **Transit Identification** | Passive correlation (`PivotPath`, `TransitEvidence`, `assess_transit_evidence`) | Full — 11 assessment states, deterministic | None significant |
| **Change Detection** | `baseline` create/list/show/delete + `compare` (`--summary`, `--evidence`, `--recommend`, `--explain`, `--changes-only`, `--minimum-confidence`) | Full — atomic storage, schema versioning, deterministic diff | None significant |
| **Prioritization** | `next` (deterministic ranking: priority > evidence strength > canonical network) | Full — `NextStepReport` with limitation text | None significant |
| **Direct Validation** | `check` (explicit target + explicit ports, 8-status taxonomy, `--baseline` context) | Full — `CheckReport`, `ValidationContext`, precise statuses | Evidence provenance (G2) |
| **SOCKS Relay Validation** | `proxy-check` (3-stage RFC 1928/1929, stdlib-only, one-transaction invariant) | Full — `ProxyCheckReport`, staged output, credential redaction | Credential input safety (G1), provenance (G2) |
| **Evidence Capture** | `--json` on every command | Full — stable schemas with `tool`, `version`, `timestamp` | G2, G3 (schema version field missing from some commands) |
| **Evidence Gap Analysis** | **NOT IMPLEMENTED** | — | **Operator must manually cross-reference** what evidence exists vs. what is missing |
| **Candidate Explanation** | `compare --explain NETWORK` (partial) | Partial — only available during comparison, not standalone | No standalone `explain` for `next` candidates |
| **Validation Evidence Provenance** | **PARTIAL** | `check`/`proxy-check` JSON lack `timestamp` and `command` fields | Automation must correlate results by hand |
| **Batch Validation** | **NOT IMPLEMENTED** (deliberate) | Rejected in architecture — scanner territory | Manual per-target validation |
| **UDP Validation** | **NOT IMPLEMENTED** | — | Manual `nc -u` / `nmap -sU` |
| **Protocol-Aware Validation** (SSH, HTTP CONNECT, etc.) | **NOT IMPLEMENTED** | Rejected — application layer out of scope | Manual tooling |

---

## 2. Gap Classification Matrix

| Gap ID | Gap Description | Operator Pain | Security Value | Implementation Cost | Architecture Risk | Recommendation |
|---|---|---|---|---|---|---|
| **G1** | Credential exposure via `argv` (`--proxy socks5://user:pass@host`) | HIGH — passwords visible in `ps`, `/proc`, EDR telemetry, shell history | HIGH — opsec failure on assumed-breach host | LOW — `--proxy-auth-env` already implemented | NONE — strictly reduces disclosure | **IMPLEMENTED** (PROXY-CHECK-1) |
| **G2** | Active command evidence provenance missing `timestamp`, `command` | MEDIUM — automation/reporting must correlate by hand | MEDIUM — reproducible evidence chains | LOW — additive JSON fields | NONE — additive only | **IMPLEMENT** (Phase B) |
| **G3** | Text renderer encoding crashes on cp1252 (`═`/`—` → `UnicodeEncodeError`) | HIGH — redirected output fails on Windows | HIGH — robustness blocker for operators | LOW — centralized `text_stream` wrapper exists | NONE — single boundary | **IMPLEMENTED** (writer.py) |
| **G4** | No packaging/release evidence (build, install, CI, Python matrix) | HIGH — cannot verify release artifacts | HIGH — supply chain / reproducibility | MEDIUM — CI config, matrix testing, clean install verification | NONE | **IMPLEMENT** (Phase D) |
| **G5** | No standalone evidence-gap analysis (`pivotcheck gaps NETWORK` or `explain --gaps`) | MEDIUM — operator manually audits what evidence is missing | HIGH — prevents wasted validation time | MEDIUM — new command or subcommand | LOW — passive only, no network activity | **IMPLEMENT** (Phase B) |
| **G6** | No standalone candidate explanation (`pivotcheck explain NETWORK` without baseline) | MEDIUM — operator cannot trace `next` output to evidence without baseline | HIGH — traceability is architectural invariant | MEDIUM — extend `explain` to work without comparison | LOW — pure analysis | **IMPLEMENT** (Phase B) |
| **G7** | UDP validation semantics undefined | LOW — TCP covers most pivot validation needs | LOW — UDP is connectionless, unreliable evidence | HIGH — requires careful epistemic design | MEDIUM — must not overclaim | **DEFER** (document decision) |
| **G8** | Application-protocol validation (SSH, HTTP CONNECT, WinRM, SMB, LDAP, RDP) | LOW — transport validation is the project scope | LOW — specialized tools exist (`nmap`, `impacket`, `crackmapexec`) | HIGH — scope creep, maintenance burden | HIGH — violates "transport-focused" architecture | **REJECT** (out of scope) |
| **G9** | Controlled batch validation (`--target-file`) | LOW — explicit per-target is deliberate safety boundary | LOW — duplicates `proxychains`/`nmap` usage | MEDIUM — but architecture forbids scanning patterns | HIGH — risks becoming a scanner | **REJECT** (architectural violation) |
| **G10** | Schema version in JSON envelopes (`schema_version`, `command`) | MEDIUM — consumers lack stable version signal | MEDIUM — automation stability | LOW — additive field | NONE — additive | **IMPLEMENT** (Phase B) |
| **G11** | Determinism testing (regression suite) | LOW — current tests pass but no explicit permutation tests | MEDIUM — architectural guarantee | LOW — add test cases | NONE | **IMPLEMENT** (Phase E) |
| **G12** | Network safety invariant regression tests (no CIDR expansion, no scanning, etc.) | LOW — invariants documented but not all tested | HIGH — security boundary | LOW — add explicit test assertions | NONE | **IMPLEMENT** (Phase E) |

---

## 3. Critical Real-World Gap — Validation Protocol Coverage

### Current Protocol Coverage

| Protocol | Implemented | Evidence Produced | Operator Question Answered |
|---|---|---|---|
| **TCP** | ✅ `check` | `SUCCESS`/`REFUSED`/`TIMEOUT`/`NO_ROUTE`/`UNREACHABLE`/`DNS_ERROR`/`INVALID_TARGET`/`LOCAL_ERROR` | "Can I establish a TCP connection to this explicit target:port?" |
| **SOCKS5 CONNECT** | ✅ `proxy-check` | 3-stage: `proxy_tcp` → `socks5_negotiation` → `destination_connect` (RFC 1928 reply codes) | "Can this explicit SOCKS5 proxy reach this explicit destination:port?" |

### Protocol Gap Analysis

| Protocol | Operator Need | PivotCheck Scope? | Implement? | Rationale |
|---|---|---|---|---|
| **UDP** | Validate UDP reachability to DNS, NTP, VPN, custom services | ❓ Borderline | **DEFER** — Requires epistemic design document first. UDP silence ≠ unreachable. Must model `NO_RESPONSE_OBSERVED` / `ICMP_UNREACHABLE_OBSERVED` / `UDP_RESPONSE_OBSERVED` without claiming "port open". |
| **SSH** | Validate SSH service availability / banner | ❌ Application layer | **REJECT** — Use `ssh -o BatchMode=yes` or `nmap -sV`. Transport TCP 22 check already exists. |
| **Telnet** | Validate Telnet service | ❌ Application layer | **REJECT** — Obsolete protocol; transport TCP 23 check exists. |
| **HTTP CONNECT** | Validate HTTP proxy tunnel | ❌ Proxy layer (not SOCKS5) | **REJECT** — Out of scope; SOCKS5 CONNECT is the pivot protocol. |
| **WinRM** | Validate Windows remote management | ❌ Application layer | **REJECT** — Use `evil-winrm`, `crackmapexec`. |
| **SMB** | Validate SMB/file sharing | ❌ Application layer | **REJECT** — Use `smbclient`, `nmap --script smb-*`. |
| **LDAP** | Validate directory services | ❌ Application layer | **REJECT** — Use `ldapsearch`, `nmap --script ldap-*`. |
| **RDP** | Validate Remote Desktop | ❌ Application layer | **REJECT** — Use `xfreerdp`, `nmap --script rdp-*`. |
| **DNS** | Validate DNS resolution via pivot | ❌ Application layer | **REJECT** — Proxy-check already sends hostname to proxy (ATYP 0x03). Local DNS validation is not pivot validation. |

### UDP Special Analysis (if pursued)

**Fundamental Semantic Problem:**
- UDP is connectionless — no SYN/ACK equivalent
- No response ≠ unreachable (filtering, loss, service state)
- ICMP errors (Port Unreachable, Host Unreachable, Network Unreachable) provide evidence but may be filtered
- Application-layer responses provide stronger evidence but require protocol knowledge
- Local socket bind/send success does NOT prove destination reachability

**If Implemented — Required Design:**
```bash
pivotcheck udp-check 10.10.20.25 --port 53  # explicit target only
```

**Evidence States (honest semantics):**
| State | Meaning |
|---|---|
| `UDP_RESPONSE_OBSERVED` | Application-layer reply received |
| `ICMP_PORT_UNREACHABLE` | ICMP Type 3 Code 3 received |
| `ICMP_HOST_UNREACHABLE` | ICMP Type 3 Code 1 received |
| `ICMP_NETWORK_UNREACHABLE` | ICMP Type 3 Code 0 received |
| `TIMEOUT` | No response within timeout (AMBIGUOUS) |
| `LOCAL_ERROR` | OS socket error |

**Never Output:** `UDP PORT OPEN` (solely from silence).

---

## 4. SSH / Telnet / Netcat Gap Analysis

### Network-Path vs. Service Validation Distinction

| Check | What It Proves | What It Does NOT Prove |
|---|---|---|
| `pivotcheck check host --port 22` → `SUCCESS` | TCP 22 reachable from current vantage | SSH service accepts connections, authentication works, banner is valid |
| `pivotcheck check host --port 23` → `SUCCESS` | TCP 23 reachable | Telnet service works, authentication works |
| `nc host 22` | TCP transport works | SSH protocol negotiation succeeds |

### Determination

**PivotCheck remains transport-focused.**

- `check` validates **network path + TCP acceptance**
- `proxy-check` validates **SOCKS5 relay path + CONNECT acceptance**
- Application-protocol validation (SSH banner, auth, HTTP CONNECT, WinRM, SMB, LDAP, RDP) belongs to specialized tooling (`nmap -sV`, `impacket`, `crackmapexec`, `evil-winrm`)

**Potential Future Abstraction (not implementing now):**
```
ValidationTransport
    ├── TCP (check)
    ├── UDP (if G7 pursued)
    └── SOCKS5/TCP (proxy-check)
```
Application protocols remain outside PivotCheck unless evidence-driven reason emerges.

---

## 5. High-Value Features — Implementation Priority

### Priority 1: Evidence Gap Analysis (`gaps` / `explain --gaps`)

**Operator Question:** *"What evidence is missing before I spend time validating this candidate?"*

**Proposed CLI:**
```bash
pivotcheck gaps 10.50.0.0/16           # new command
# or
pivotcheck explain 10.50.0.0/16 --gaps # subcommand of explain
```

**Output Distinction (non-interchangeable):**
| State | Meaning |
|---|---|
| `NOT_OBSERVED` | Collector ran but did not observe this evidence type |
| `NOT_COLLECTED` | Collector was unavailable/degraded for this evidence type |
| `NEGATIVE_EVIDENCE` | Collector explicitly observed absence (e.g., neighbor state = FAILED) |
| `NOT_APPLICABLE` | Evidence type does not apply to this network context |

**Example Output:**
```
EVIDENCE GAPS FOR 10.50.0.0/16
════════════════════════════════════════════════════════════

ROUTE:
  OBSERVED (metric 50, via 10.10.20.254 dev eth1)

NEIGHBOR:
  NOT_OBSERVED (no ARP/ND entry for gateway)

CONNECTIONS:
  NOT_COLLECTED (socket collection unavailable)

ACTIVE VALIDATION:
  NOT_PERFORMED

LIMITATION:
  Passive evidence only. Active validation required to confirm reachability.
```

**Architecture:** Pure passive analysis — no network activity.

---

### Priority 2: Candidate Explanation (`explain NETWORK`)

**Operator Question:** *"Why is this a candidate?"*

**Proposed CLI:**
```bash
pivotcheck explain 10.50.0.0/16        # standalone, no baseline required
pivotcheck explain 10.50.0.0/16 --baseline pre-pivot  # with comparison
```

**Explanation Chain:**
```
Observed Route
    +
Observed Neighbor
    +
Observed Connection
    +
Baseline Difference (if applicable)
    ↓
Deterministic Analysis Rules
    ↓
Transit Assessment (e.g., MULTIPLE_SUPPORTING_SIGNALS)
    ↓
Priority (HIGH/MEDIUM/LOW)
    ↓
Recommendation + Limitations
```

**Must Include:**
- Observed evidence (with source: route/neighbor/connection)
- Inference (transit assessment)
- Reasoning rule (why this assessment → this priority)
- Missing evidence (gaps)
- Limitations (explicit: "route evidence ≠ reachability")
- Suggested explicit action

**Never Claim:** `PIVOT CONFIRMED` when only passive evidence exists.

---

### Priority 3: Validation Evidence Provenance (Close G2)

**Current Deficit:** `check` and `proxy-check` JSON lack `timestamp` and `command` fields.

**Target Envelope (additive, non-breaking):**
```json
{
  "tool": "pivotcheck",
  "version": "0.1.0",
  "command": "check",
  "schema_version": "1.1",
  "timestamp": "2026-08-29T12:34:56.789Z",
  "perspective": {
    "hostname": "workstation-01",
    "session_id": "abc123..."
  },
  "target": "10.50.10.25",
  "port": 443,
  "protocol": "tcp",
  "result": {...},
  "limitations": [...]
}
```

**Privacy Decision:** 
- Include `hostname` (local system identity) — operator can suppress with `--no-hostname` if needed
- Include `session_id` (random per-invocation UUID) — enables correlation without persistent identity
- **Never** include: passwords, proxy passwords, credentials, environment secrets, auth tokens

**Cryptographic Attestation:** 
- **NOT IMPLEMENTED** — `PROVENANCE ≠ AUTHENTICITY` documented explicitly
- Timestamp identifies when tool generated record; does not prove result was unmodified

---

### Priority 4: Machine-Readable Output Consistency

**Audit Target:** Every command's JSON output

**Canonical Envelope Strategy:**
```
Command Result
      ↓
Canonical Output Envelope (additive evolution)
      ↓
Text Renderer ←→ JSON Renderer
```

**Required Fields (additive where missing):**
```json
{
  "schema_version": "1.x",
  "tool": "pivotcheck",
  "version": "0.1.0",
  "command": "discover|map|check|proxy-check|next|compare|baseline",
  "timestamp": "ISO8601",
  "perspective": { "hostname": "...", "session_id": "..." },
  "data": {},
  "warnings": [],
  "limitations": []
}
```

**Test Strategy:** Model → `to_dict()` → JSON (not duplicated semantic structures in renderers).

---

## 6. Protocol Scope Decision Matrix

| Protocol | Implement | Defer | Reject | Reason |
|---|---|---|---|---|
| **TCP** | ✅ | | | Core — explicit target validation |
| **SOCKS5 CONNECT** | ✅ | | | Pivot validation — RFC 1928/1929 |
| **UDP** | | 🔍 Investigate | | Semantics require careful epistemic design; document decision |
| **SSH** | | 🔍 Investigate | | Application-layer; transport check exists |
| **Telnet** | | | ❌ | Obsolete; transport check exists |
| **HTTP CONNECT** | | | ❌ | Explicit project boundary (SOCKS5 only) |
| **SOCKS4/4a** | | | ❌ | Scope creep |
| **UDP ASSOCIATE** | | | ❌ | SOCKS5 relay scope (not CONNECT) |
| **BIND** | | | ❌ | Not needed for pivot validation |
| **SMB** | | 🔍 Investigate | | Likely belongs to specialized tooling (`impacket`) |
| **WinRM** | | | ❌ | Application-layer |
| **LDAP** | | | ❌ | Application-layer |
| **RDP** | | | ❌ | Application-layer |

**Decision Principle:** Narrow functionality answering specific PivotCheck questions. Do not become `nmap`, `netcat`, `curl`, `proxychains`, `ssh`, `impacket`.

---

## 7. Repository Hygiene Audit

| Category | Items Found | Action |
|---|---|---|
| `__pycache__/` | Multiple directories | `gitignore` (already in .gitignore) |
| `.pytest_cache/` | Present | `gitignore` |
| `.mypy_cache/` | Present | `gitignore` |
| `.ruff_cache/` | Present | `gitignore` |
| `.venv/` | Not present | N/A |
| `*.egg-info/` | `pivotcheck.egg-info/` | `gitignore` |
| `.pytest_tmp/` | Present (OneDrive workaround) | `gitignore` |
| Temporary JSON artifacts | None found | N/A |
| Agent-generated files | `.autoclaw/`, `.clinerules/` | Keep (project metadata) |
| Stale reports | `AUDIT_REPORT.md` (superseded) | Archive with clear marker |
| Duplicate documents | None | N/A |
| Unused modules | None detected | N/A |
| Dead code | None detected | N/A |
| Unused imports | Clean (ruff passes) | N/A |
| Unused fixtures | None detected | N/A |
| Duplicate tests | None detected | N/A |
| Obsolete simulations | `project_output_simulation.md` (historical) | Keep with marker |
| Historical documents | `AUDIT_REPORT.md` | Archive with pointer to `STABILIZATION_REPORT.md` |

---

## 8. Packaging / Release Engineering Status

| Check | Status | Evidence |
|---|---|---|
| `python -m build` | **NOT TESTED** | Must verify |
| Clean install in venv | **NOT TESTED** | Must verify |
| `pivotcheck --version` | **NOT TESTED** | Must verify |
| `pivotcheck --help` | **NOT TESTED** | Must verify |
| Runtime dependencies = ZERO | ✅ Confirmed | `dependencies = []` in pyproject.toml |
| Wheel contents audit | **NOT TESTED** | Must verify |
| sdist contents audit | **NOT TESTED** | Must verify |
| Entry point works | **NOT TESTED** | Must verify |
| Package version | ✅ `0.1.0` | pyproject.toml |
| README included | ✅ | `readme = "README.md"` |
| License included | ✅ | `license = { text = "MIT" }` |
| Python requirement | ✅ `>=3.10` | pyproject.toml |
| Python matrix tested | ❌ | Only 3.14 tested locally |

---

## 9. Python Version Matrix

| Version | Tested | Supported | Notes |
|---|---|---|---|
| 3.10 | ❌ | ✅ Declared | Minimum declared |
| 3.11 | ❌ | ✅ Declared | |
| 3.12 | ❌ | ✅ Declared | |
| 3.13 | ❌ | ✅ Declared | |
| 3.14 | ✅ | ✅ Declared | Current test environment |

**Requirement:** Test on 3.10, 3.11, 3.12, 3.13, 3.14 before claiming support.

---

## 10. CI Pipeline Requirements

**Minimal Serious CI:**
```yaml
# .github/workflows/ci.yml
jobs:
  test:
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12", "3.13", "3.14"]
        os: [ubuntu-latest, windows-latest, macos-latest]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with: { python-version: ${{ matrix.python-version }} }
      - run: pip install -e ".[dev]"
      - run: pytest
      - run: ruff check .
      - run: mypy pivotcheck
      - run: python -m build
      - run: |
          python -m venv /tmp/pivotcheck-test
          /tmp/pivotcheck-test/bin/pip install dist/*.whl
          /tmp/pivotcheck-test/bin/pivotcheck --version
          /tmp/pivotcheck-test/bin/pivotcheck --help
```

---

## 11. Coverage Strategy

**Do Not Game Coverage.**

Measure only if useful. Target areas:
- Models (all assessment states, validation paths)
- Analysis (priority ranking, tie-breaking, evidence correlation)
- Checks (error states, timeout paths, protocol parser paths)
- Output (text/JSON renderers, encoding paths, ANSI separation)
- CLI (exit codes, argument validation, error paths)

**Blind Spot Focus:**
- Negative evidence paths (`ROUTING_WITH_NEGATIVE_L2_EVIDENCE`, `CONTRADICTORY_EVIDENCE`)
- Credential paths (redaction, env var, mutual exclusion)
- Encoding paths (cp1252, UTF-8, JSON ASCII)
- Exit code matrix (all 4 codes per command)

---

## 12. Adversarial Testing Checklist

| Attack Vector | Test Required | Expected Behavior |
|---|---|---|
| Malformed target (IPv4, IPv6, CIDR, hostname, invalid) | ✅ | Usage error (exit 2), no crash |
| Invalid port (negative, >65535, range, list) | ✅ | Usage error (exit 2) |
| Invalid timeout (negative, zero, huge) | ✅ | Usage error (exit 2) |
| Invalid proxy URL (bad scheme, missing host/port, CIDR host) | ✅ | Usage error (exit 2) |
| Missing/empty env var for `--proxy-auth-env` | ✅ | Usage error (exit 2) |
| Credential leakage (argv, logs, JSON, exceptions, repr) | ✅ | Never appears |
| Unicode output (cp1252, UTF-8) | ✅ | No crash, graceful fallback |
| JSON ANSI contamination | ✅ | Never |
| stderr/stdout separation | ✅ | Diagnostics on stderr only |
| Broken socket / connection reset | ✅ | Classified, not crash |
| DNS failure | ✅ | `DNS_ERROR` status |
| Partial/malformed SOCKS reply | ✅ | `PROXY_PROTOCOL_ERROR` |
| Unknown SOCKS reply code | ✅ | `PROXY_PROTOCOL_ERROR` (never success) |
| Auth failure | ✅ | `AUTH_FAILED` |
| Destination refusal / timeout | ✅ | Appropriate status |
| Proxy refusal / timeout | ✅ | Appropriate status |

---

## 13. Determinism Testing

| Property | Test Required |
|---|---|
| Same input → same normalized evidence | ✅ |
| Same input → same analysis result | ✅ |
| Same input → same priority ordering | ✅ |
| Same input → same candidate selection | ✅ |
| Same input → same JSON structure | ✅ |
| Same input → same JSON key ordering | ✅ |
| Dictionary/set iteration never affects output | ✅ |
| Timestamps isolated from semantic fields | ✅ |

---

## 14. Network Safety Invariant Regression Tests

| Invariant | Test Required |
|---|---|
| No CIDR expansion in `check` | ✅ (CLI rejects CIDR) |
| No port-range expansion in `check` | ✅ (parser rejects ranges) |
| No automatic target generation in `next` | ✅ (uses only `PivotPath` from routes) |
| No hidden scanning in any command | ✅ (architecture enforces) |
| No automatic validation of `next` candidates | ✅ (explicit operator action required) |
| No retries unless explicitly specified | ✅ (single attempt only) |
| No autonomous pivoting | ✅ (architecture) |
| No exploitation | ✅ (architecture) |
| No credential persistence | ✅ (in-memory only) |
| No credential logging | ✅ (redaction in `display_url`, `to_dict`, `__repr__`) |
| `proxy-check` exactly one proxy transaction | ✅ (single `check_proxy` call) |
| `proxy-check` exactly one CONNECT attempt | ✅ (single `encode_connect_request`) |
| No destination-local resolution for hostname targets in `proxy-check` | ✅ (ATYP 0x03) |
| Proxy performs hostname resolution via ATYP 0x03 | ✅ (encode_connect_request) |

---

## 15. Output Semantics Audit

### Forbidden Language (must never appear)

| Avoid | Use Instead |
|---|---|
| `PIVOT AVAILABLE` | `TRANSIT CANDIDATE` |
| `TARGET REACHABLE` | `ROUTE EVIDENCE OBSERVED` / `ACTIVE TCP VALIDATION SUCCEEDED` |
| `NETWORK ACCESSIBLE` | `ROUTE CONTEXT EXISTS` |
| `BOUNDARY BYPASSED` | `ROUTING DOMAIN TRANSITION OBSERVED` |
| `PIVOT CONFIRMED` | `ACTIVE VALIDATION SUCCEEDED` / `SOCKS5 CONNECT SUCCEEDED` |
| `reachable` (unqualified) | `route evidence observed` |
| `viable pivot` | `inferred pivot context` |
| `accessible` | `route context exists` |
| `pivotable` | `transit candidate with supporting evidence` |
| `confirmed` | `actively validated` |
| `working` | `evidence observed` |

### Current Compliance Check

| Command | Compliance | Issues Found |
|---|---|---|
| `discover` | ✅ | Uses "inferred", "confidence", "limitation" correctly |
| `map` | ✅ | `--show-pivots` shows "[INFERRED]" label |
| `compare` | ✅ | `--recommend` shows priorities, not validation |
| `check` | ✅ | Statuses precise; "Important: this result applies to explicit target" |
| `proxy-check` | ✅ | Staged output; limitation text explicit |
| `next` | ✅ | Limitation: "Route and topology evidence do not prove active reachability" |

---

## 16. Architecture Compliance

### Dependency Direction (Must Remain One-Way)

```
MODELS
   ↓
DISCOVERY / NORMALIZATION
   ↓
ANALYSIS
   ↓
OUTPUT
   ↓
CLI / ORCHESTRATION
```

### Verified Compliance

| Layer | Imports From | Imports To (Forbidden) |
|---|---|---|
| Models | (stdlib only) | — |
| Discovery | Models | Analysis, Output, CLI |
| Analysis | Models, Discovery | Output, CLI |
| Output | Models, Analysis | Discovery, CLI |
| CLI | All (orchestration only) | — |

**No violations detected** in current codebase.

---

## 17. Implementation Order (Per Architecture)

### Stage A — Evidence & Architecture (COMPLETE)
- ✅ Fresh baseline established (511 tests pass, ruff clean, mypy clean)
- ✅ Gap analysis (this document)
- ✅ Architecture audit (no violations)
- ✅ Protocol decision (this document)
- ✅ Output-contract audit (this document)

### Stage B — High-Value Semantic Improvements (PENDING)
- [ ] Evidence provenance (G2) — add `timestamp`, `command`, `schema_version` to active commands
- [ ] Evidence-gap analysis (G5) — new `gaps` command or `explain --gaps`
- [ ] Explainability (G6) — standalone `explain NETWORK` command
- [ ] Output-envelope consistency (G10) — canonical envelope across all commands

### Stage C — Validation Expansion Decision (PENDING)
- [ ] UDP feasibility analysis (G7) — document decision
- [ ] Transport abstraction — if UDP pursued
- [ ] Protocol scope decision (this document — done)
- [ ] Implement ONLY justified protocols (none currently justified beyond TCP/SOCKS5)

### Stage D — Release Engineering (PENDING)
- [ ] Repository cleanup (gitignore, archive stale docs)
- [ ] Packaging verification (`python -m build`, clean install)
- [ ] Python matrix (3.10–3.14)
- [ ] CI pipeline
- [ ] Coverage measurement (if useful)

### Stage E — Final Adversarial Verification (PENDING)
- [ ] Full test suite
- [ ] Integration tests
- [ ] Protocol tests (TCP, SOCKS5)
- [ ] Security tests (credential leakage, input validation)
- [ ] Encoding tests (cp1252, UTF-8, JSON)
- [ ] Determinism tests (permutation stability)
- [ ] Packaging tests (wheel, sdist, install)
- [ ] CLI smoke tests (all commands, all flags)
- [ ] Documentation verification

---

## 18. Release Readiness Gates

| Gate | Status | Evidence |
|---|---|---|
| Full tests pass | ✅ | 511 passed, 4 deselected |
| Integration tests pass | ✅ | 4 passed |
| Ruff clean | ✅ | All checks passed |
| MyPy clean | ✅ | Success: no issues in 52 files |
| Python support matrix verified | ❌ | Only 3.14 tested |
| Package builds | ❌ | Not tested |
| Wheel installs cleanly | ❌ | Not tested |
| Source distribution builds | ❌ | Not tested |
| CLI entry point works | ❌ | Not tested from artifact |
| Runtime dependencies verified | ✅ | Zero deps |
| CI passes | ❌ | No CI configured |
| Repository clean | ⚠️ | Stale `AUDIT_REPORT.md`, caches not ignored |
| Generated artifacts excluded | ⚠️ | `.pytest_tmp/`, `*.egg-info/` not in gitignore |
| No secrets | ✅ | Verified |
| Credential leakage tests pass | ✅ | Proxy redaction verified |
| JSON contracts verified | ✅ | `to_dict()` based, tested |
| Text contracts verified | ✅ | Renderer tests exist |
| Encoding tests pass | ✅ | `test_output_encoding.py` passes |
| ANSI tests pass | ✅ | `--no-color` tested |
| Exit-code tests pass | ✅ | CLI tests verify codes |
| Determinism tests pass | ⚠️ | Partial — needs permutation tests |
| Network safety invariants pass | ⚠️ | Documented, not all regression-tested |
| No CIDR expansion | ✅ | CLI rejects |
| No scanning | ✅ | Architecture |
| No autonomous validation | ✅ | Architecture |
| No automatic target generation | ✅ | Architecture |
| No evidence overclaims | ✅ | Verified in output |
| Proxy-check one-transaction invariant | ✅ | Verified in code |
| UDP decision documented | ❌ | This document |
| SSH/Telnet/NC scope documented | ✅ | This document |
| Evidence provenance documented | ❌ | This document |
| Limitations documented | ✅ | In output and docs |
| README matches reality | ✅ | Verified |
| Architecture docs match reality | ✅ | Verified |
| Output docs match serializers | ✅ | `PROJECT_OUTPUT.md` current |
| Simulation docs match reality | ✅ | Marked historical |
| Historical docs are labelled | ⚠️ | `AUDIT_REPORT.md` needs pointer |
| No dead production modules | ✅ | Verified |
| No unnecessary files | ⚠️ | Caches, egg-info need gitignore |
| Release artifact contents audited | ❌ | Not tested |

---

## 19. Final Verdict

**Current State:** `RELEASE READY WITH DOCUMENTED LIMITATIONS` for core functionality (discover, map, baseline, compare, check, next, proxy-check).

**Blockers for Full Release:**
1. Python version matrix not verified (3.10–3.13 untested)
2. Packaging/install not verified from artifacts
3. CI pipeline not configured
4. Repository hygiene (gitignore, stale docs)
5. Evidence provenance (G2) — additive improvement
6. Evidence gap analysis (G5) — high operator value
7. Standalone explain (G6) — high operator value
8. Determinism regression tests
9. Network safety invariant regression tests

**Recommended Path:**
1. Complete Stage B (semantic improvements — G2, G5, G6, G10)
2. Complete Stage D (release engineering)
3. Complete Stage E (adversarial verification)
4. Declare `RELEASE READY`

---

## 20. Accepted Limitations (Documented)

1. **Linux-only discovery** — `discover`/`map` require Linux networking tools (`ip`, `ss`, `resolv.conf`); `check`/`proxy-check`/`baseline`/`compare`/`next` are cross-platform.
2. **No UDP validation** — Epistemic limitations documented; TCP/SOCKS5 cover primary pivot validation needs.
3. **No application-protocol validation** — SSH, WinRM, SMB, LDAP, RDP, HTTP CONNECT out of scope.
4. **No batch/scanning validation** — Explicit per-target only; architectural invariant.
4. **Provenance ≠ Authenticity** — Timestamps identify generation time; no cryptographic attestation.
5. **Single vantage point per invocation** — No multi-host correlation in one run.
6. **Baseline comparison is passive** — Cannot compare active validation results to passive topology.

---

*End of Operator Gap Analysis*