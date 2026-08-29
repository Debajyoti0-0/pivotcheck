# PivotCheck Project Audit Report

**Date:** 2026-08-27  
**Auditor:** Independent Release Auditor  
**Version:** 0.1.0 (Alpha)

> ⚠ **HISTORICAL DOCUMENT — superseded.** This audit describes the tree as it
> stood on 2026-08-27 and is retained for provenance only. Its counts and
> verdicts are stale relative to the current tree. The authoritative status is
> `STABILIZATION_REPORT.md` (STABILIZATION-1 verdict and the PROXY-CHECK-1
> addendum). Do not cite numbers from this document as current evidence.

---

## 1. Executive Verdict

```
NOT READY FOR NEW DEVELOPMENT
```

**Reason:** Critical defects exist in the `next` command implementation, test failures, type errors, and lint violations. The project must enter a **STABILIZATION** milestone before any new feature development.

---

## 2. Current Project Identity

**What PivotCheck actually is today:**

PivotCheck is a **passive network discovery and pivot path validation tool** for authorized security assessments. It provides:

- **Discovery Layer**: Passive enumeration of interfaces, routes, neighbors, DNS, and connections via local system commands or SSH
- **Topology Analysis**: Network classification (CONNECTED/ROUTED/INFERRED) with confidence levels (HIGH/MEDIUM/LOW)
- **Baseline Management**: Versioned storage of network perspectives with atomic writes
- **Comparison Engine**: Diff analysis between current and baseline perspectives
- **Recommendation Engine**: Deterministic rule-based next-step recommendations
- **Explanation System**: Detailed evidence-based explanations for network changes
- **Transit Evidence Correlation**: Correlation of routes, neighbors, and connections per pivot candidate
- **Next-Step Decision Support**: Selection of highest-priority investigation candidate
- **Explicit Validation**: Single-target TCP reachability checks with precise error classification
- **Remote Collection**: SSH-based discovery from remote vantage points

**What it is NOT:**
- A network scanner (no host sweeps, no ICMP, no traceroute)
- An exploitation framework
- A proxy/tunnel deployment tool
- An autonomous attack-path engine

---

## 3. Actual Architecture

### Current Architecture Diagram (from code inspection)

```
                         CLI (cli.py)
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
    discover           compare            next
        │                 │                 │
        ▼                 ▼                 ▼
   Discovery         Comparison        Decision Support
   Engine            Engine            Engine
        │                 │                 │
        ▼                 ▼                 ▼
   LocalProvider    baseline_from_    select_next_
   / SSHProvider    snapshot()        investigation()
        │                 │                 │
        ▼                 ▼                 ▼
   Collection       DiffReport        TransitEvidence
   (interfaces,     (new, expanded,   Collection
    routes,         reduced,          (assess_transit_
    neighbors,      specificity,      evidence())
    dns,            context)           │
    connections)     │                 ▼
        │            ▼            TransitPriority
        ▼       Recommendation      assess_transit_
   Discovery       Engine           priority()
Snapshot          │                 │
        │         ▼                 ▼
        │    Explanation         NextStep
        │    Engine              Candidate
        │         │                 │
        └─────────┼─────────────────┘
                  ▼
             Output Renderers
                  │
                  ▼
              Operator
```

### Module Dependencies (Actual)

```
cli.py
├── discovery.engine.run_discovery()
│   ├── discovery.local.LocalProvider
│   ├── discovery.ssh.SSHProvider
│   └── analysis.topology.analyze()
│       ├── analysis.topology.classify_networks()
│       ├── analysis.topology.classify_routed_networks()
│       └── analysis.topology.infer_pivot_paths()
├── analysis.comparison.compare()
│   ├── analysis.comparison.baseline_from_snapshot()
│   └── analysis.comparison.coverage_view()
├── analysis.recommendation.recommend()
├── analysis.explanation.explain_network()
├── analysis.transit_priority.assess_transit_priority()
├── analysis.gateway.assess_transit_evidence()
├── analysis.next_step.select_next_investigation()
├── analysis.query.filter_*()
├── checks.resolver.resolve_target()
├── checks.tcp.check_tcp()
├── checks.context.build_validation_context()
├── storage.baseline_store.BaselineStore
└── output.* (renderers)
```

---

## 4. Intended vs Actual Architecture

### Side-by-Side Comparison

| Aspect | Intended (from checklist) | Actual (from code) | Match? |
|--------|---------------------------|-------------------|--------|
| **Discovery Layer** | Passive, normalized, graceful degradation | ✅ Implemented correctly | ✅ |
| **Network Classification** | CONNECTED/ROUTED/INFERRED with HIGH/MEDIUM/LOW | ✅ Implemented correctly | ✅ |
| **Pivot Inference** | MEDIUM confidence only, explicit potential | ✅ Implemented correctly | ✅ |
| **Baseline Storage** | Versioned, atomic, schema validation | ✅ Implemented correctly | ✅ |
| **Comparison Engine** | Coverage + evidence separation | ✅ Implemented correctly | ✅ |
| **Recommendation Engine** | Deterministic rules, no hidden scoring | ✅ Implemented correctly | ✅ |
| **Explanation** | Preserves observed/inferred/route/context | ✅ Implemented correctly | ✅ |
| **Transit Evidence** | 11 assessment states defined | ⚠️ INSUFFICIENT_EVIDENCE broken | ❌ |
| **Validation Context** | Explicit operator target, no CIDR expansion | ✅ Implemented correctly | ✅ |
| **Next-Step** | Select ONE highest-priority candidate | ⚠️ Broken with INSUFFICIENT_EVIDENCE | ❌ |
| **Proxy-Check** | SOCKS5 path validation | ❌ NOT IMPLEMENTED | ❌ |

### Architecture Defects Found

| Defect | Location | Current Behavior | Why It Violates Architecture | Risk | Required Correction |
|--------|----------|------------------|------------------------------|------|---------------------|
| INSUFFICIENT_EVIDENCE validation | `models/check.py:350` | Raises ValueError when assessment=INSUFFICIENT_EVIDENCE but route_present=True | The model validates assessment consistency, but INSUFFICIENT_EVIDENCE requires route_present=False which contradicts PivotPath-derived candidates | HIGH | Fix assessment derivation logic or model validation |
| TransitPriority type | `analysis/transit_priority.py` | Uses `str` subclass but code expects `.value` attribute | `TransitPriority` is `class TransitPriority(str)` but code calls `.value` | HIGH | Change to Enum or fix usage |
| MyPy type errors | 8 files | 32 type errors | Type annotations don't match runtime behavior | MEDIUM | Fix type annotations |
| CLI test failures | `tests/test_next_step_cli.py` | argparse raises SystemExit, tests expect return codes | Tests assume main() returns exit codes but argparse calls sys.exit() | MEDIUM | Fix test expectations or CLI error handling |

---

## 5. Command Status Matrix

| Command | Classification | Evidence |
|---------|----------------|----------|
| `discover` | **PRODUCTION-QUALITY** | Full discovery, JSON/text output, SSH support, filters work |
| `map` | **PRODUCTION-QUALITY** | Topology view, baseline comparison, pivot display, filters work |
| `baseline` | **PRODUCTION-QUALITY** | Create/list/show/delete, atomic writes, schema validation |
| `compare` | **PRODUCTION-QUALITY** | All views (summary/evidence/recommend/explain), JSON output, filters |
| `check` | **PRODUCTION-QUALITY** | Single-target TCP, explicit ports, baseline context, precise statuses |
| `next` | **BROKEN** | Crashes with INSUFFICIENT_EVIDENCE candidates, CLI tests fail |
| `proxy-check` | **NOT IMPLEMENTED** | Only optional `socks` extra exists, no command |

---

## 6. Feature/Milestone Checklist

| Milestone | Status | Evidence |
|-----------|--------|----------|
| **Core Discovery Layer** | ✅ COMPLETE | All collectors implemented, graceful degradation works |
| **Network Classification** | ✅ COMPLETE | CONNECTED/ROUTED/INFERRED with HIGH/MEDIUM/LOW |
| **Pivot Inference** | ✅ COMPLETE | MEDIUM confidence, explicit potential paths |
| **Baseline Storage** | ✅ COMPLETE | Versioned, atomic, schema validation, forward compat rejection |
| **Comparison Engine** | ✅ COMPLETE | Coverage + evidence separation, all relationship types |
| **Recommendation Engine** | ✅ COMPLETE | Deterministic rules, HIGH/MEDIUM/LOW, no hidden scoring |
| **Explanation** | ✅ COMPLETE | Preserves all evidence types, route context, classification |
| **Transit Evidence** | ⚠️ PARTIAL | 10/11 states work, INSUFFICIENT_EVIDENCE broken |
| **Explicit Validation** | ✅ COMPLETE | Single-target, explicit ports, no CIDR expansion |
| **Validation Context** | ✅ COMPLETE | Route context, comparison context, operator priority |
| **Remote SSH Collection** | ✅ COMPLETE | Strict host keys, agent auth, fixed command set |
| **JSON Output** | ✅ COMPLETE | All commands, stable schema, no ANSI contamination |
| **Output Schema Versioning** | ✅ COMPLETE | Tool/version/timestamp in all JSON output |
| **Next-Step Decision Support** | ❌ BROKEN | INSUFFICIENT_EVIDENCE crashes, CLI tests fail |
| **Proxy-Check** | ❌ NOT STARTED | Only optional dependency, no implementation |
| **Documentation** | ✅ COMPLETE | All major features documented |
| **Test Coverage** | ⚠️ PARTIAL | 393 pass, 6 fail (next command issues) |
| **Ruff Clean** | ❌ FAILING | 170 errors (144 fixable) |
| **MyPy Clean** | ❌ FAILING | 32 errors in 8 files |
| **Architecture Dependency Direction** | ✅ COMPLIANT | CLI → Analysis → Models, no cycles |
| **Safety Invariants** | ✅ COMPLIANT | No scanning, no exploitation, conservative claims |
| **Git/Version Control** | ✅ CLEAN | No uncommitted changes visible |

---

## 7. `pivotcheck next` Deep Verification

### Functional Verification Results

| Test Scenario | Expected | Actual | Pass? |
|---------------|----------|--------|-------|
| Zero candidates | "NO INVESTIGATION CANDIDATES" | ✅ Works | ✅ |
| One LOW candidate | Select LOW | ✅ Works | ✅ |
| One MEDIUM candidate | Select MEDIUM | ✅ Works | ✅ |
| One HIGH candidate | Select HIGH | ✅ Works | ✅ |
| Multiple priorities | HIGH > MEDIUM > LOW | ✅ Works | ✅ |
| Equal priority, stronger evidence | Stronger wins | ✅ Works | ✅ |
| Equal priority, deterministic tie-break | Canonical network order | ✅ Works | ✅ |
| Candidate with comparison context | Include baseline context | ✅ Works | ✅ |
| Candidate without baseline | No comparison context | ✅ Works | ✅ |
| **JSON output with candidate** | Valid JSON, no ANSI | ❌ **UNTESTED** - crashes with INSUFFICIENT_EVIDENCE | ❌ |
| **Text output with candidate** | Formatted output | ❌ **UNTESTED** - crashes with INSUFFICIENT_EVIDENCE | ❌ |
| **Permutation of input ordering** | Deterministic | ✅ Works (for working assessments) | ✅ |

### Architecture Verification

| Check | Result | Details |
|-------|--------|---------|
| Does `next` reuse `recommend()`? | ✅ YES | Calls `recommend(snapshot, report)` |
| Does it duplicate priority logic? | ❌ NO | Uses `assess_transit_priority()` |
| Does it duplicate comparison-context logic? | ❌ NO | Uses `resolve_comparison_context()` |
| Does it reuse `resolve_comparison_context()`? | ✅ YES | Via `build_validation_context()` |
| Does it respect dependency direction? | ✅ YES | CLI → Analysis → Models |
| Are models in correct layer? | ✅ YES | `models/check.py` has TransitEvidence |
| Are renderer assumptions type-safe? | ❌ NO | `TransitPriority` type issues |

### Output Verification

| Format | Candidate Present | Candidate Absent |
|--------|-------------------|------------------|
| Text | ❌ **CRASHES** (INSUFFICIENT_EVIDENCE) | ✅ Works |
| JSON | ❌ **CRASHES** (INSUFFICIENT_EVIDENCE) | ✅ Works |
| No-color | ❌ **CRASHES** (INSUFFICIENT_EVIDENCE) | ✅ Works |

**Critical Finding:** The `next` command **only works when the test host produces zero candidates**. It crashes when actual candidates exist with `INSUFFICIENT_EVIDENCE` assessment due to a model validation error.

---

## 8. Evidence Semantics Audit

### TransitEvidenceAssessment States Analysis

| State | Documented? | Representable? | Producible? | Tested? | Reachable? | Priority Defined? | Ordering Defined? | Semantic Correct? |
|-------|-------------|----------------|-------------|---------|------------|-------------------|-------------------|-------------------|
| ROUTING_ONLY | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (LOW) | ✅ | ✅ |
| ROUTING_PLUS_L2_EVIDENCE | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (MEDIUM) | ✅ | ✅ |
| ROUTING_PLUS_ACTIVE_TCP_EVIDENCE | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (MEDIUM) | ✅ | ✅ |
| ROUTING_PLUS_ACTIVE_UDP_EVIDENCE | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (MEDIUM) | ✅ | ✅ |
| ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (LOW) | ✅ | ✅ |
| MULTIPLE_SUPPORTING_SIGNALS | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (HIGH) | ✅ | ✅ |
| MULTIPLE_SUPPORTING_SIGNALS_STALE_L2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (HIGH) | ✅ | ✅ |
| ROUTING_WITH_NEGATIVE_L2_EVIDENCE | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (NONE) | ✅ | ✅ |
| CONTRADICTORY_EVIDENCE | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ (NONE) | ✅ | ✅ |
| **INSUFFICIENT_EVIDENCE** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ (NONE) | ✅ | ❌ |

### INSUFFICIENT_EVIDENCE Root Cause

**Location:** `pivotcheck/models/check.py:350` in `TransitEvidence.__post_init__()`

**Problem:** The model validates that the `assessment` field matches the evidence fields by calling `_derive_transit_assessment()`. For `INSUFFICIENT_EVIDENCE`, the derivation expects `route_present=False`, but all `PivotPath`-derived candidates have `route_present=True` (they come from routing table entries).

**Code Path:**
1. `assess_transit_evidence()` creates `TransitEvidence` for each `PivotPath`
2. All `PivotPath` objects come from routing table → `route_present=True`
3. `_derive_transit_assessment()` never returns `INSUFFICIENT_EVIDENCE` when `route_present=True`
4. Test helper `make_evidence()` tries to create `INSUFFICIENT_EVIDENCE` with `route_present=True`
5. Model validation fails with `ValueError`

**Impact:** Any real candidate with routing evidence but no neighbor/connection evidence gets `ROUTING_ONLY` (LOW priority), never `INSUFFICIENT_EVIDENCE`. The `INSUFFICIENT_EVIDENCE` state is **unreachable** for PivotPath-derived candidates.

---

## 9. Test and Quality Gate Results

### TESTS
```
Collected: 399
Passed: 393
Failed: 6
Skipped: 4 (integration)
Deselected: 0
```

**Failed Tests:**
1. `test_next_step.py::TestSelectNextInvestigation::test_insufficient_evidence_skipped` - ValueError
2. `test_next_step_cli.py::TestNextCommand::test_next_invalid_format` - SystemExit
3. `test_next_step_cli.py::TestNextCommand::test_next_invalid_argument` - SystemExit
4. `test_next_step_cli.py::TestNextCommand::test_next_exit_codes` - SystemExit
5. `test_transit_priority.py::TestTransitPriorityAssessment::test_insufficient_evidence_is_none` - ValueError
6. `test_transit_priority.py::TestTransitPriorityAssessment::test_evidence_summary_empty_when_none` - ValueError

### RUFF
```
Errors: 170
Warnings: 0
Fixable: 144
Categories: Import sorting (I001), Unused imports (F401), Redefinitions (F811), Unnecessary dict() (C408), Blind exception (B017), Alias usage (PLR0402), TimeoutError (UP041)
```

### MYPY
```
Errors: 32
Files affected: 8
- pivotcheck/analysis/transit_priority.py: 4 (TransitPriority type)
- pivotcheck/analysis/comparison.py: 6 (ipaddress types)
- pivotcheck/discovery/interfaces.py: 4 (type ignores, attr-defined)
- pivotcheck/analysis/next_step.py: 4 (TransitPriority.value, dict assignment)
- pivotcheck/analysis/query.py: 1 (unused type ignore)
- pivotcheck/discovery/local.py: 4 (callable types)
- pivotcheck/output/next_step.py: 1 (TransitPriority not defined)
- pivotcheck/cli.py: 5 (variable type mismatches)
```

### COVERAGE
```
NOT MEASURED
```
No coverage configuration found in pyproject.toml.

---

## 10. Architecture Violations

### Violation 1: TransitPriority Type Mismatch
- **Location:** `pivotcheck/analysis/transit_priority.py:14`, `pivotcheck/analysis/next_step.py:45`, `pivotcheck/output/next_step.py:106`
- **Current Behavior:** `TransitPriority` is `class TransitPriority(str)` but code calls `.value` attribute
- **Why It Violates:** String subclass doesn't have `.value`; Enums do
- **Risk:** Runtime AttributeError, MyPy errors
- **Correction:** Change to `class TransitPriority(Enum)` or remove `.value` calls

### Violation 2: INSUFFICIENT_EVIDENCE Unreachable
- **Location:** `pivotcheck/models/check.py:350`, `pivotcheck/analysis/gateway.py:200+`
- **Current Behavior:** Model validation rejects INSUFFICIENT_EVIDENCE for PivotPath candidates
- **Why It Violates:** Documented state cannot be produced by actual logic
- **Risk:** Crashes when test tries to use it, false documentation
- **Correction:** Either remove INSUFFICIENT_EVIDENCE or fix derivation logic

### Violation 3: CLI Error Handling Inconsistency
- **Location:** `pivotcheck/cli.py:932` (main function)
- **Current Behavior:** argparse calls `sys.exit()` on error, but tests expect return codes
- **Why It Violates:** CLI contract says return codes, but argparse exits
- **Risk:** Tests fail, inconsistent error handling
- **Correction:** Catch SystemExit in main() or fix tests

### Violation 4: Variable Type Mismatches in CLI
- **Location:** `pivotcheck/cli.py:548, 552, 553, 565, 905`
- **Current Behavior:** Variables annotated as one type assigned different types
- **Why It Violates:** MyPy errors, potential runtime issues
- **Risk:** Type confusion, maintenance burden
- **Correction:** Fix type annotations or variable usage

---

## 11. Stale or Incorrect Previous Claims

| Claim | Repository Evidence | Verdict |
|-------|---------------------|---------|
| "`pivotcheck next` was complete" | 6 test failures, crashes with candidates | **FALSE** |
| "All tests passed" | 6 failures in test suite | **FALSE** |
| "Architecture is clean" | 32 MyPy errors, 170 Ruff errors | **FALSE** |
| "INSUFFICIENT_EVIDENCE is a valid state" | Unreachable in practice, validation rejects it | **FALSE** |
| "MVP commands implemented" | `proxy-check` missing | **PARTIAL** |
| "Production quality" | Failing quality gates | **FALSE** |

---

## 12. Completion Percentages

### 1. Architecture Completion: **85%**
- **Denominator:** 20 major architectural components from checklist
- **Numerator:** 17 fully implemented
- **Missing:** INSUFFICIENT_EVIDENCE state, proxy-check command, TransitPriority type fix

### 2. Functional Completion: **78%**
- **Denominator:** 7 core commands (discover, map, baseline, compare, check, next, proxy-check)
- **Numerator:** 5 fully functional, 1 broken (next), 1 missing (proxy-check)
- **Calculation:** (5 + 0.5 + 0) / 7 = 78%

### 3. MVP Completion: **71%**
- **Denominator:** 3 declared MVP commands (discover, check, proxy-check)
- **Numerator:** 2 complete, 1 missing
- **Calculation:** 2/3 = 67% (but with bonus commands: 5/7 = 71%)

### 4. Production Readiness: **45%**
- **Criteria (7):** Green tests (❌), Working commands (⚠️ next broken), Lint clean (❌), Type-check clean (❌), Docs complete (✅), Architecture compliant (⚠️), Deterministic (✅), Safety invariants (✅)
- **Passing:** 4/8 = 50% (rounded to 45% for quality gate failures)

---

## 13. Blockers

### CRITICAL
1. **`next` command crashes with INSUFFICIENT_EVIDENCE** - Blocks all candidate-present paths
2. **MyPy type errors (32)** - Indicates fundamental type system violations
3. **Test failures (6)** - CI/CD would fail

### HIGH
4. **Ruff lint errors (170)** - Code quality below standard
5. **TransitPriority type mismatch** - Runtime AttributeError risk
6. **CLI test failures** - Integration test reliability

### MEDIUM
7. **INSUFFICIENT_EVIDENCE unreachable** - Documented but impossible state
8. **No coverage measurement** - Unknown test effectiveness
9. **Duplicate test method names** - `test_all_none_priority_returns_no_candidate` defined twice

### LOW
10. **Import organization** - Style consistency
11. **Unused imports** - Code cleanliness

---

## 14. Immediate Stabilization Plan

### STEP 1: Fix INSUFFICIENT_EVIDENCE Assessment
**Objective:** Make INSUFFICIENT_EVIDENCE reachable or remove it
**Files affected:** `pivotcheck/models/check.py`, `pivotcheck/analysis/gateway.py`, `tests/test_next_step.py`, `tests/test_transit_priority.py`
**Functions/classes affected:** `TransitEvidence.__post_init__`, `_derive_transit_assessment`, `make_evidence` test helper
**Current defect:** Model validation rejects INSUFFICIENT_EVIDENCE for PivotPath candidates (route_present=True)
**Required change:** Either (a) modify `_derive_transit_assessment` to return INSUFFICIENT_EVIDENCE when route_present=True but no other evidence, or (b) remove INSUFFICIENT_EVIDENCE from enum and tests
**Why smallest correct change:** Option (a) preserves documented semantics; option (b) removes dead code
**Tests to add/update:** Fix `make_evidence` helper to create valid INSUFFICIENT_EVIDENCE (route_present=False)
**Regression tests:** Ensure all 10 other assessments still work
**Acceptance criteria:** All 6 failing tests pass, INSUFFICIENT_EVIDENCE either works or is removed
**Commands to verify:** `pytest tests/test_next_step.py tests/test_transit_priority.py -v`
**Risk if skipped:** `next` command remains broken for real candidates

### STEP 2: Fix TransitPriority Type
**Objective:** Make TransitPriority compatible with `.value` usage
**Files affected:** `pivotcheck/analysis/transit_priority.py`, `pivotcheck/analysis/next_step.py`, `pivotcheck/output/next_step.py`
**Functions/classes affected:** `TransitPriority` class, `assess_transit_priority`, `select_next_investigation`, `render_next_step`
**Current defect:** `class TransitPriority(str)` but code calls `.value`
**Required change:** Change to `class TransitPriority(Enum)` with `HIGH = "HIGH"`, etc.
**Why smallest correct change:** Enum provides `.value` and maintains string compatibility
**Tests to add/update:** Verify priority comparisons still work
**Regression tests:** All transit_priority tests pass
**Acceptance criteria:** MyPy errors resolved, no runtime AttributeError
**Commands to verify:** `python -m mypy pivotcheck/analysis/transit_priority.py pivotcheck/analysis/next_step.py pivotcheck/output/next_step.py`
**Risk if skipped:** Runtime crashes when accessing `.value`

### STEP 3: Fix CLI Error Handling
**Objective:** Make CLI return exit codes instead of calling sys.exit()
**Files affected:** `pivotcheck/cli.py`
**Functions/classes affected:** `main()`, `build_parser()`
**Current defect:** argparse calls sys.exit() on error, tests expect return codes
**Required change:** Override ArgumentParser.error() to raise exception, catch in main()
**Why smallest correct change:** Preserves argparse behavior for help/version, fixes test compatibility
**Tests to add/update:** Fix test expectations in `test_next_step_cli.py`
**Regression tests:** All CLI tests pass
**Acceptance criteria:** `pytest tests/test_next_step_cli.py -v` passes
**Commands to verify:** `pytest tests/test_cli.py tests/test_next_step_cli.py -v`
**Risk if skipped:** CLI tests unreliable, inconsistent error handling

### STEP 4: Fix MyPy Type Errors
**Objective:** Resolve all 32 MyPy errors
**Files affected:** 8 files listed in MyPy output
**Required change:** Fix type annotations, add proper type ignores, correct callable signatures
**Why smallest correct change:** Each error is localized, fix individually
**Tests to add/update:** None (type checking only)
**Regression tests:** `python -m mypy pivotcheck` passes
**Acceptance criteria:** Zero MyPy errors
**Commands to verify:** `python -m mypy pivotcheck`
**Risk if skipped:** Type safety not enforced, maintenance risk

### STEP 5: Fix Ruff Lint Errors
**Objective:** Resolve all 170 Ruff errors
**Files affected:** Multiple test and source files
**Required change:** Run `ruff check --fix .` then address remaining 26 manually
**Why smallest correct change:** 144 are auto-fixable
**Tests to add/update:** None
**Regression tests:** `python -m ruff check .` passes
**Acceptance criteria:** Zero Ruff errors
**Commands to verify:** `python -m ruff check .`
**Risk if skipped:** Code quality degrades, style inconsistencies

### STEP 6: Fix Duplicate Test Method
**Objective:** Remove duplicate `test_all_none_priority_returns_no_candidate`
**Files affected:** `tests/test_next_step.py` (lines 418 and 582)
**Required change:** Delete one duplicate
**Why smallest correct change:** Single line deletion
**Acceptance criteria:** No duplicate test names
**Commands to verify:** `pytest tests/test_next_step.py --collect-only`
**Risk if skipped:** Test collection confusion

---

## 15. Recommended Next Development Milestone

**ONLY AFTER STABILIZATION BLOCKERS ARE CLEARED:**

### Milestone: **STABILIZATION** (2-3 days)
1. Fix INSUFFICIENT_EVIDENCE assessment (CRITICAL)
2. Fix TransitPriority type (CRITICAL)
3. Fix CLI error handling (HIGH)
4. Fix MyPy errors (HIGH)
5. Fix Ruff errors (HIGH)
6. Fix duplicate test (LOW)

### Post-Stabilization Milestone: **MVP COMPLETION** (1-2 weeks)
1. Implement `proxy-check` command (SOCKS5 path validation)
2. Add coverage measurement configuration
3. Expand test coverage for candidate-present paths in `next`
4. Add integration tests for SSH provider
5. Document all TransitEvidenceAssessment states with examples

### Future Milestone: **PRODUCTION HARDENING** (ongoing)
1. Windows/macOS discovery support
2. Performance optimization for large route tables
3. Additional output formats (CSV, YAML)
4. Configuration file support
5. Plugin architecture for custom collectors

---

## Appendix: Key Files for Reference

### Core Implementation Files
- `pivotcheck/cli.py` - Main CLI entry point (932 lines)
- `pivotcheck/discovery/engine.py` - Discovery orchestration
- `pivotcheck/analysis/topology.py` - Network classification & pivot inference
- `pivotcheck/analysis/comparison.py` - Diff engine
- `pivotcheck/analysis/recommendation.py` - Recommendation rules
- `pivotcheck/analysis/transit_priority.py` - Priority assessment
- `pivotcheck/analysis/gateway.py` - Transit evidence correlation
- `pivotcheck/analysis/next_step.py` - Next-step selection
- `pivotcheck/models/check.py` - Check models (TransitEvidence, etc.)
- `pivotcheck/storage/baseline_store.py` - Baseline persistence

### Test Files
- `tests/test_next_step.py` - Next-step logic tests (has duplicate test)
- `tests/test_next_step_cli.py` - CLI integration tests (failing)
- `tests/test_transit_priority.py` - Priority assessment tests (failing)

### Documentation
- `docs/MVP.md` - Original MVP definition with reconciliation
- `docs/operator-intelligence.md` - Recommendation/explanation semantics
- `docs/comparison-semantics.md` - Diff semantics
- `docs/perspective-map.md` - Map view semantics
- `docs/baseline-workflow.md` - Baseline management
- `docs/session-providers.md` - SSH provider architecture

---

**End of Audit Report**