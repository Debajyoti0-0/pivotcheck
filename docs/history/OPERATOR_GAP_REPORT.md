# PivotCheck — Operator Gap Report (RELEASE-HARDENING)

**Status:** Frozen 2026-08-29. Evidence-based; derived from live execution, code
inspection, and the red-team workflow review. This report gates what may be
implemented in the hardening milestone. Feature development beyond it is
frozen.

## 1. Operator workflow coverage assessment

| Workflow stage | PivotCheck capability | Residual operator burden |
|---|---|---|
| Foothold → local visibility | `discover` (interfaces, routes, neighbors, DNS, sockets; SSH vantage) | none significant |
| Route/topology understanding | `map` (confidence-graded, interface-aware) | minor: multi-interface ambiguity prose |
| Transit identification | passive correlation (`PivotPath`, transit evidence) | none significant |
| Change detection | `baseline create/list/show/delete` + `compare` (`--changes-only`, `--evidence`, `--recommend`, `--explain`) | none significant |
| Prioritization | `next` (deterministic, evidence chain in output) | none significant |
| Direct validation | `check` (precise status taxonomy, explicit target/port) | evidence provenance (G2) |
| SOCKS relay validation | `proxy-check` (3-stage RFC 1928/1929) | credential input safety (G1), provenance (G2) |
| Evidence capture | `--json` on every command | G2, G3 |

## 2. Accepted gaps (in scope for hardening)

### G1 — Credential exposure via process command line — **HIGH (security)**
- **Scenario:** `proxy-check --proxy socks5://op:pass@pivot:1080 …` on an
  assumed-breach host. Password is visible in argv (`ps`, `/proc`, EDR process
  telemetry, shell history).
- **Impact:** leaks pivot credentials to the monitored environment's own
  logging. Undermines the tool's opsec model.
- **Fix direction (single mechanism):** a safe credential source —
  `--proxy-auth-env NAME` reading `user:password` from a named environment
  variable. Chosen over `--proxy-auth-file` for minimal surface (no file
  lifecycle to leak), and over interactive prompts (breaks scripting on
  short-lived shells).
- **Safety impact:** none on network behavior; strictly reduces disclosure.
- **Compatibility:** argv URL userinfo remains accepted and documented as
  logged-by-the-environment; redaction behavior unchanged.

### G2 — Evidence provenance on active commands — **MEDIUM (automation/reporting)**
- `check` and `proxy-check` JSON lack `timestamp` (and vantage context);
  `next` has `timestamp` but no `command`. Reports and automation must
  correlate results by hand.
- **Fix direction:** add `timestamp` to both active-command envelopes;
  record an explicit decision on `command` field consistency (F19). No
  breaking key changes; additive only.

### G3 — Encoding robustness — **HIGH (robustness blocker)**
- Text renderers use `═`/`—`; cp1252 file redirection raises
  `UnicodeEncodeError` (exit 1). Affects `check` and `proxy-check` today;
  every text renderer is latently exposed.
- **Fix direction:** one centralized writer-level policy (see §5); no
  per-renderer patches.

### G4 — Packaging/release evidence — **HIGH (process blocker)**
- No build/install-from-artifact proof, no CI, no VCS. Phase 8 of the
  hardening plan.

## 3. Deferred (not in this milestone)

- **G5 raw snapshot export/re-ingestion** — baselines partially cover it;
  passive discovery is cheap to re-run; adds a second persistence format.
- **G6 ARP evidence-aging heuristics** — HIGH already requires REACHABLE
  neighbor + TCP corroboration; deeper aging adds complexity for marginal gain.
- **Coverage configuration** — record, don't chase percentages.

## 4. Rejected ideas (with reasons)

| Idea | Verdict | Reason |
|---|---|---|
| SOCKS4/4a, HTTP CONNECT, UDP ASSOCIATE, BIND, GSSAPI | REJECTED | scope expansion without operator need; SOCKS5 CONNECT covers the stated workflow |
| Proxy chaining / multi-hop validation | REJECTED | destroys single-transaction stage attribution |
| Multi-destination / batch proxy-check | REJECTED | scan-shaped; violates one-transaction invariant |
| Automatic validation of `next` candidates | REJECTED | removes operator control; the core safety property |
| Port ranges/lists for active checks | REJECTED | scanner territory; already rejected at CLI layer |
| `--auto` / `--execute` on `next` | REJECTED | autonomous validation forbidden |
| Credential store / keyring integration | REJECTED | secret persistence the project explicitly avoids |
| Retry/parallel connection engines | REJECTED | noise, nondeterminism |
| Raw snapshot ingestion (G5) | DEFERRED | value real but not blocking |
| Coverage-percentage gaming | REJECTED | tests must assert contracts, not lines |

## 5. Encoding design note (for Phase 3 review)

Requirement: one boundary. Proposed shape — a central `OutputWriter`/
stream-wrapping policy applied where commands obtain their output stream:
detect stream encoding; if it cannot represent the rendered text, re-encode
with deterministic replacement (`errors="backslashreplace"` or ASCII-fallback
decoration) instead of crashing. JSON paths remain `ensure_ascii`-safe and
never flow through lossy re-encoding. Full design presented for approval
before implementation.
