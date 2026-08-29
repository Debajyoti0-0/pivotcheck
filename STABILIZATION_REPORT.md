# PivotCheck — Stabilization Report

**Date:** 2026-08-27
**Milestone:** STABILIZATION, CONTRACT RECONCILIATION & RELEASE GATE RECOVERY
**Verdict:** ✅ **AUTHORIZED FOR MVP COMPLETION**

---

## A. Baseline Before Changes (verified live, not taken from AUDIT_REPORT.md)

| Gate | Result on takeover |
|---|---|
| Tests | 414 passed / **1 failed** (`test_next_step_cli.py::test_next_candidate_present_json`) / 4 integration deselected |
| Ruff | **2 errors** (BLE001 + RUF100, both in `conftest.py`) |
| MyPy | **Clean** — 0 errors in 48 source files |
| Broken commands | **None.** `next` works with and without candidates |
| Known architecture violations from audit | All four already resolved in tree (see D) |

**Important:** `AUDIT_REPORT.md` (dated 2026-08-27) is **stale relative to the repository**. Its claims of 6 test failures, 170 ruff errors, 32 mypy errors, a broken `TransitPriority(str)`, unreachable `INSUFFICIENT_EVIDENCE`, CLI `SystemExit` inconsistency, leaked `NEW_REACHABILITY` label, and a duplicated test method do **not** match the current tree. The audit describes an earlier state; the tree has since been reconciled.

## B. Root Cause Analysis

### Defect 1 — failing test `test_next_candidate_present_json`
- **Symptom:** `KeyError: 'evidence'` at `tests/test_next_step_cli.py:223`.
- **Root cause:** Stale assertion in the *test*, not the implementation. The test asserted `candidate["evidence"]["connections"]["tcp_count"]`, but the documented candidate contract (PROJECT_OUTPUT.md §10) — and the implementation, and the *same test two lines earlier* — use `observed_evidence`. The test predated the output-contract reconciliation and kept one orphaned key.
- **Affected layers:** Test only. No production code involved.
- **Why the fix is correct:** Authority order puts the explicit output contract above tests. PROJECT_OUTPUT.md §10 JSON example shows `"observed_evidence": {}` inside the candidate object; `NextStepCandidate.to_dict()` implements exactly that. Fixed the assertion to `candidate["observed_evidence"]["connections"]["tcp_count"] == 1`. No assertion was weakened — the same check now runs against the contract-correct key.

### Defect 2 — ruff BLE001/RUF100 in `conftest.py`
- **Symptom:** `except Exception:` flagged as blind except; a `# noqa: BLE001` on the `return` line two lines below was unused.
- **Root cause:** The suppression comment was placed on the wrong line (off-by-two), so ruff saw both an unsuppressed violation and an unused directive.
- **Fix:** Moved `# noqa: BLE001` onto the `except Exception:` line. The blind except is deliberate (platform/user-db dependent `getpass.getuser()` during pytest temp-dir detection); suppression is now minimal, explained, and located correctly. No semantic change.

### Non-defects verified (audit Blockers A & B)
- **TransitPriority:** `class TransitPriority(str, Enum)` in `analysis/transit_priority.py` — a deliberate canonical representation. `.value` works for serialization, `==`/construction with plain strings works, MyPy sees member types. No `.value` on a bare `str` subclass exists anywhere. Blocker A does not exist in the current tree.
- **INSUFFICIENT_EVIDENCE:** `_derive_transit_assessment()` returns it when `route_present=False`; `TransitEvidence.__post_init__` accepts it in that exact state; `assess_transit_priority()` maps it to `NONE` priority; `select_next_investigation` skips NONE candidates. Model validation == derivation == tests. The state is reachable (explicitly: candidates without route evidence) and coherent. Blocker B does not exist in the current tree.
- **CLI exit-code contract:** `main()` returns integer exit codes; argparse-owned usage errors raise `SystemExit(EXIT_USAGE)` — and the tests assert exactly this dual contract (`pytest.raises(SystemExit)` for `--invalid`, integer return for baseline-not-found). Consistent, documented, tested. Audit Violation 3 does not exist in the current tree.
- **Public vocabulary boundary:** `public_comparison_label()` in `models/check.py` is the single serialization-boundary mapping; `ComparisonContext.to_dict()` passes `relationship` and `classification` through it. Internal `NEW_REACHABILITY` cannot leak into JSON. `next_step.py` additionally maps DiffFinding classifications to the `ComparisonContext` vocabulary via `_CONTEXT_RELATIONSHIP`. Audit Violation 4 does not exist in the current tree.

## C. Files Changed

| File | Reason | Responsibility | Risk | Tests |
|---|---|---|---|---|
| `tests/test_next_step_cli.py` (1 line, :223) | Stale key `evidence` → contract-correct `observed_evidence` | Test suite (output-contract conformance) | None — test-only | `pytest tests/test_next_step_cli.py` (all green) |
| `conftest.py` (comment move, :36–37) | Place `# noqa: BLE001` on the offending line | Test infrastructure (pytest temp-dir redirect) | None — comment-only | Full suite green; temp-dir logic untouched |

No production code was modified. **Total diff: 2 lines in 2 files.**

## D. Contract Reconciliation

| Point | Audit claim | Current tree reality | Resolution |
|---|---|---|---|
| TransitPriority type | `str` subclass, `.value` crashes | `str, Enum` with documented rationale | Already reconciled; verified via mypy + runtime tests |
| INSUFFICIENT_EVIDENCE | Unreachable, validation contradiction | Reachable via `route_present=False`; derivation, model, priority, and tests agree | Already reconciled; truth table holds for all 11 states |
| CLI exit behavior | Two conflicting contracts | Integer returns + documented `SystemExit` for argparse usage errors, both asserted | Already reconciled |
| Internal label leakage | `NEW_REACHABILITY` may leak | `public_comparison_label()` guards every serialization boundary | Already reconciled |
| `next` JSON candidate key | — (not audited) | Contract: `observed_evidence`; one test asserted legacy `evidence` | **Fixed this milestone** |

Ambiguity removed: the only place the legacy `evidence` key survived was one stale test line; public JSON now has exactly one conforming producer and one conforming test.

## E. Test Results (exact)

```
pytest (full)      : 415 passed, 4 deselected in 2.04s   (deselected = integration-marked, by config)
pytest (this host) : no skips beyond config; conftest temp-dir redirect active for OneDrive-locked temp
ruff check .       : All checks passed!
mypy pivotcheck    : Success: no issues found in 48 source files
```

Manual CLI verification (Windows host, zero-candidate environment):
```
python -m pivotcheck next --help    → usage text renders
python -m pivotcheck next           → NO INVESTIGATION CANDIDATES (text, exit 0)
python -m pivotcheck next --json    → valid JSON: tool/version/timestamp/candidate:null/message
```
Candidate-present text/JSON/no-color/--format paths are proven by `tests/test_next_step_cli.py` fixtures (all passing), which is the correct instrument on a zero-candidate host.

## F. Architecture Status After Stabilization

Percentages use the audit's own denominators, re-scored against the verified current tree:

- **Architecture completion: 19/20 components ≈ 95%.** Missing: `proxy-check` (design only). Resolved since audit: INSUFFICIENT_EVIDENCE state machine, TransitPriority representation.
- **Functional completion: 6/7 commands ≈ 86%.** discover / map / baseline / compare / check / next all working; proxy-check not implemented.
- **MVP completion: 6/7 ≈ 86%** (same denominator basis as the audit's 5/7 = 71%).
- **Production readiness:** all 8 audit-rubric gates now green (tests, commands, lint, types, docs, architecture direction, determinism, safety invariants). Remaining readiness gaps are feature-scope (proxy-check) and process (stale audit doc, no coverage config), not defects.

## G. Remaining Work

**BLOCKING:** none.

**HIGH PRIORITY:**
1. `AUDIT_REPORT.md` is stale and actively misleading (wrong counts, wrong verdict against current tree). Regenerate or archive it with a pointer to this report.
2. Implement `proxy-check` (the MVP scope gap).

**FUTURE:**
3. Coverage measurement config (`pytest-cov` is already in dev extras).
4. Windows/macOS discovery support (currently Linux-oriented, as documented).
5. Periodic release-gate run in CI so the audit-vs-tree drift cannot recur.

## H. Authorization Decision

```
AUTHORIZED FOR MVP COMPLETION
```

All acceptance gates are green: `next` works with and without candidates; TransitPriority has one coherent representation; every documented assessment state is reachable or intentionally unmapped; model validation matches derivation; public JSON matches PROJECT_OUTPUT.md; no internal label leakage; CLI exit-code contract is coherent and tested; full suite, ruff, and mypy all pass; no regression in discover/map/baseline/compare/check; dependency direction and safety invariants unchanged. The next authorized milestone is `proxy-check` — nothing else.

**Safety invariants re-verified:** no CIDR expansion, no automatic target generation, no sweeping, no autonomous validation, no reachability claims from route evidence. The `next` output retains its explicit limitation language ("do not prove active reachability", "not validation evidence").

---

# I. Addendum — PROXY-CHECK-1 Milestone (2026-08-29)

The authorized follow-up milestone (`proxy-check`) has been implemented and
verified. This section does not rewrite the report above; it records the
milestone that G.2 requested.

**Delivered:** `pivotcheck proxy-check` — operator-controlled SOCKS5 CONNECT
validation (RFC 1928 + RFC 1929), stdlib-only engine (`checks/proxy.py`),
frozen stage/verdict models (`models/proxy_check.py`), staged text + JSON
renderers (`output/proxy_check.py`), CLI orchestration (`cli.py`), and a
deterministic loopback test suite (`tests/test_proxy_check.py`,
`tests/test_proxy_protocol.py`, `tests/test_proxy_check_cli.py`).

**Contract decisions recorded:** single explicit port (no lists/ranges);
destination resolved by the proxy (ATYP 0x03), never locally; `--baseline`
deliberately not offered (passive topology evidence is not comparable to an
active transaction result); exit 3 reserved for proxy-endpoint DNS failure;
transport failures after the TCP stage fall back deterministically to
PROXY_PROTOCOL_ERROR (never success).

**Evidence at close:** 489 unit tests + 4 integration tests pass; ruff clean;
mypy clean; live loopback verification of NO-AUTH VALIDATED, AUTH success,
AUTH failure, and CONNECT reply-code classification, with redaction verified.

**Known limitation (pre-existing, project-wide):** text renderers (including
the existing `check` command) use `═`/`—`; on Windows hosts where redirected
stdout uses the cp1252 codepage this raises `UnicodeEncodeError` (exit 1).
JSON output is ASCII-safe and unaffected. Not introduced by this milestone;
behavior is identical to `check` and left unchanged for convention
consistency.
