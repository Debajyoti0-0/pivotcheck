# PivotCheck — Project Plan

## 1. Project Vision

PivotCheck is a **passive network-perspective analysis and decision-support tool** for red teamers, penetration testers, and security operators.

The project is designed to answer a practical question:

> **From my current network vantage point, what networks, routes, topology relationships, and transit opportunities can I observe—and what should I investigate next?**

PivotCheck is **not intended to replace scanners, exploitation frameworks, or active validation tools**.

Its core value is:

1. Collect network evidence from the current perspective.
2. Normalize that evidence into a deterministic model.
3. Infer network and transit context without overclaiming.
4. Compare perspectives over time using baselines.
5. Prioritize investigation candidates.
6. Allow explicitly operator-controlled validation.

The project must maintain a strict distinction between:

- **Observed evidence**
- **Inferred context**
- **Prioritization**
- **Active validation**

---

# 2. Core Evidence Philosophy

PivotCheck must never collapse different evidence levels into the same claim.

## 2.1 Evidence hierarchy

```text
RAW SYSTEM OBSERVATION
        │
        ▼
NORMALIZED DISCOVERY EVIDENCE
        │
        ▼
DETERMINISTIC INFERENCE
        │
        ├── Network topology
        ├── Pivot context
        └── Transit assessment
        │
        ▼
OPERATOR PRIORITIZATION
        │
        ▼
EXPLICIT OPERATOR VALIDATION
```

## 2.2 Mandatory semantic rules

```text
OBSERVED ≠ INFERRED

ROUTE EVIDENCE ≠ ACTIVE REACHABILITY

TRANSIT ASSESSMENT ≠ PIVOT CAPABILITY

PRIORITIZATION ≠ VALIDATION

NOT OBSERVED ≠ NOT COLLECTED

NOT COLLECTED ≠ NEGATIVE EVIDENCE

INFERRED ≠ CONFIRMED
```

## 2.3 Forbidden overclaims

PivotCheck must not claim a target or network is:

- reachable, unless explicitly validated
- accessible, based only on topology evidence
- a viable pivot, based only on route evidence
- confirmed, without direct validation
- working, unless the relevant operation actually succeeded
- a confirmed security boundary, based only on routing changes

Preferred language includes:

- route evidence observed
- inferred pivot context
- transit candidate with supporting evidence
- actively validated
- routing domain change observed
- gateway transition detected

---

# 3. Target Architecture

## 3.1 High-level architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                         CLI LAYER                           │
│                                                             │
│ discover │ map │ baseline │ compare │ check │ next          │
└──────────────────────────────┬──────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                     ORCHESTRATION LAYER                     │
│                                                             │
│ Discovery execution │ Baseline loading │ Command workflows  │
└──────────────────────────────┬──────────────────────────────┘
                               │
                ┌──────────────┴──────────────┐
                ▼                             ▼
┌───────────────────────────┐    ┌───────────────────────────┐
│      DISCOVERY LAYER      │    │      ANALYSIS LAYER       │
│                           │    │                           │
│ Interfaces                │    │ Topology                 │
│ Routes                    │    │ Comparison               │
│ Neighbors                 │    │ Recommendations          │
│ Connections               │    │ Transit evidence         │
│ DNS                       │    │ Transit priority         │
│ SSH collection            │    │ Next-step selection      │
└──────────────┬────────────┘    └──────────────┬────────────┘
               │                                 │
               └──────────────┬──────────────────┘
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        MODEL LAYER                          │
│                                                             │
│ DiscoverySnapshot │ Route │ Interface │ Neighbor            │
│ Connection │ Network │ PivotPath │ TransitEvidence          │
│ Recommendation │ ComparisonContext │ ValidationContext      │
└──────────────────────────────┬──────────────────────────────┘
                               │
                ┌──────────────┴──────────────┐
                ▼                             ▼
┌───────────────────────────┐    ┌───────────────────────────┐
│       OUTPUT LAYER        │    │      STORAGE LAYER        │
│                           │    │                           │
│ Text renderers            │    │ Baselines                 │
│ JSON renderers            │    │ Atomic persistence        │
│ Deterministic formatting  │    │ Schema validation         │
└───────────────────────────┘    └───────────────────────────┘
```

## 3.2 Dependency direction

Dependencies must remain one-way:

```text
Models
  ↓
Analysis
  ↓
Output
  ↓
CLI / Orchestration
```

Discovery and active checks are separate operational concerns:

```text
Discovery ───────────────► Models
Checks ──────────────────► Models
Storage ─────────────────► Models

Analysis consumes Models.
Analysis must not perform network activity.
Output consumes Models/Analysis results.
CLI orchestrates everything.
```

### Architectural rule

**Analysis functions must be pure whenever possible.**

They must not:

- open sockets
- execute shell commands
- write files
- mutate global state
- perform hidden discovery
- perform hidden validation

---

# 4. Existing Functional Scope

The current project architecture includes the following major commands.

## 4.1 `discover`

Purpose:

- collect passive network evidence from the current host or remote SSH perspective
- enumerate interfaces
- inspect routes
- inspect neighbors
- inspect connections
- derive normalized network context

Status target:

```text
Production-quality
```

## 4.2 `map`

Purpose:

- present topology-focused interpretation
- show networks and route relationships
- show inferred pivot paths
- apply presentation filters

Status target:

```text
Production-quality
```

## 4.3 `baseline`

Purpose:

- save a network perspective
- list saved perspectives
- inspect baselines
- delete baselines

Status target:

```text
Production-quality
```

## 4.4 `compare`

Purpose:

- compare the current perspective against a saved baseline
- identify new, expanded, reduced, or context-changed coverage
- provide evidence and recommendation views

Status target:

```text
Production-quality
```

## 4.5 `check`

Purpose:

- explicitly validate a user-specified TCP target and port
- provide precise validation status
- optionally include baseline context

Important limitation:

```text
No automatic target generation.
No CIDR expansion.
No hidden scanning.
```

Status target:

```text
Production-quality
```

## 4.6 `next`

Purpose:

- select the single highest-priority investigation candidate
- combine existing evidence deterministically
- provide prioritization context
- recommend explicit operator-controlled next action

Current status:

```text
Implemented but entering stabilization.
```

## 4.7 `proxy-check`

Current status:

```text
Implemented (PROXY-CHECK-1 milestone, 2026-08-29).
Scope: SOCKS5 CONNECT only (RFC 1928 + RFC 1929), stdlib-only engine,
one proxy / one destination / one port / one attempt per invocation.
See PROJECT_ARCHITECTURE.md §14.1 and PROJECT_OUTPUT.md §10A for the
authoritative architecture and output contracts.
```

---

# 5. Current Development Milestone

# STABILIZATION-1

## Semantic and Quality Gate Recovery

No new feature development should begin until this milestone is complete.

> **Note (2026-08-29):** STABILIZATION-1 is complete per
> `STABILIZATION_REPORT.md`; the follow-up milestone PROXY-CHECK-1 has since
> been implemented. The checklist in §16 is retained as the historical
> definition of done for STABILIZATION-1 (its final item, "proxy-check has
> NOT been started", was a scoping guard for that milestone only).

---

# 6. Phase 0 — Establish the Real Baseline

Before modifying code, establish the actual repository state.

## Required commands

```bash
python -m pytest tests/ -v
```

Run dedicated next-related tests:

```bash
python -m pytest     tests/test_transit_priority.py     tests/test_next_step.py     tests/test_next_step_cli.py     -v
```

Run static checks according to repository configuration:

```bash
mypy ...
ruff check ...
```

Run basic command checks:

```bash
python -m pivotcheck next
python -m pivotcheck next --json
python -m pivotcheck next --help
```

## Critical requirement

A command returning:

```text
NO INVESTIGATION CANDIDATES
```

does **not** prove that the feature works.

A deterministic candidate-present scenario must be tested.

### Baseline report format

```text
TESTS:
NEXT COMMAND:
CANDIDATE-PRESENT PATH:
MYPY:
RUFF:
GIT STATUS:
```

---

# 7. Phase 1 — Repair TransitEvidence Semantics

This is the highest-priority technical task.

## Problem area

The current audit identified a semantic mismatch involving:

```text
INSUFFICIENT_EVIDENCE
```

The project must determine whether this state is:

1. valid and reachable
2. valid but currently unreachable
3. obsolete
4. valid only without route evidence
5. incorrectly introduced into the next-step flow

## Required lifecycle trace

```text
Raw observation
      │
      ▼
Evidence normalization
      │
      ▼
Transit assessment derivation
      │
      ▼
TransitEvidence model validation
      │
      ▼
Transit priority mapping
      │
      ▼
Next-step candidate construction
      │
      ▼
CLI rendering
```

Every transition must be inspected.

## Required truth matrix

| Route | Neighbor | Connection | Negative Evidence | Derived Assessment | Model Valid |
|---|---|---|---|---|---|
| Present | None | None | No | TBD | TBD |
| Present | Positive | None | No | TBD | TBD |
| Present | None | Positive | No | TBD | TBD |
| Present | Positive | Positive | No | TBD | TBD |
| Present | Negative | None | Yes | TBD | TBD |
| Absent | None | None | No | TBD | TBD |

## Required invariant

```text
Every state produced by derivation
MUST be accepted by model validation.

Every state rejected by model validation
MUST be impossible for derivation to produce.
```

No command-specific workaround is acceptable.

---

# 8. Phase 2 — Stabilize TransitPriority

The TransitPriority representation must be audited before changing it.

Possible designs:

```python
class TransitPriority(str):
    ...
```

or:

```python
class TransitPriority(str, Enum):
    ...
```

or another project-consistent representation.

## Required audit

Inspect all usage:

- equality comparisons
- ranking
- sorting
- JSON serialization
- CLI output
- tests
- public API imports
- type annotations

## Decision criteria

Choose the representation that provides:

1. semantic clarity
2. type safety
3. JSON compatibility
4. deterministic comparison
5. minimal public API breakage

## Required invariant

```text
Internal representation
        =
Analysis representation
        =
Tests
        =
JSON serialization
        =
Output rendering
```

No `.value` ambiguity should remain.

---

# 9. Phase 3 — Harden Next-Step Selection

The function:

```python
select_next_investigation(...)
```

must be audited as a pure deterministic selection engine.

## Required priority ordering

```text
HIGH
  >
MEDIUM
  >
LOW
  >
NONE
```

## Selection architecture

```text
Recommendation Context
        │
        ├──────────────┐
        ▼              ▼
Priority         Transit Evidence
        │              │
        └──────┬───────┘
               ▼
       Candidate Pool
               │
               ▼
    Deterministic Ranking
               │
               ▼
    Canonical Tie-Breaking
               │
               ▼
     Single Next Candidate
```

## Required deterministic sort key

Conceptually:

```text
(
    priority_rank,
    evidence_strength_rank,
    canonical_network_key
)
```

The exact ascending/descending direction must be explicit.

## Required tests

- empty input
- one candidate
- HIGH beats MEDIUM
- MEDIUM beats LOW
- NONE excluded
- evidence strength ordering
- deterministic network tie-breaker
- baseline present
- baseline absent
- input permutation stability
- candidate-present execution without exception

---

# 10. Phase 4 — CLI Contract Validation

Audit `pivotcheck next`.

Required supported commands:

```bash
pivotcheck next
pivotcheck next --json
pivotcheck next --format json
pivotcheck --no-color next
pivotcheck -v next
pivotcheck next --baseline NAME
```

## Error conditions

Validate:

- missing baseline
- malformed baseline
- invalid CLI format
- discovery failure
- unexpected runtime failure
- no candidate found

## Required exit-code matrix

| Condition | Expected Code | Actual Code | Test |
|---|---:|---:|---|
| Success with candidate | 0 | TBD | Required |
| Success with no candidate | 0 | TBD | Required |
| Usage error | 2 | TBD | Required |
| Baseline not found | 3 | TBD | Required |
| Baseline schema error | 4 | TBD | Required |
| Fatal runtime error | 1 | TBD | Required |

## Important architecture rule

Do not mix argparse behavior and return-code behavior without understanding the existing CLI contract.

Differentiate:

```text
Argument parsing failure
        ≠
Runtime command failure
        ≠
Expected command result
```

---

# 11. Phase 5 — Output Contract

## JSON requirements

JSON output must be:

- valid
- machine-readable
- ANSI-free
- deterministic
- internally type-consistent

Required candidate-present fields should include:

```text
network
priority
reason
evidence
transit_assessment
comparison_context (when applicable)
limitation
suggested_action
```

## Text requirements

Text output must clearly distinguish:

```text
PRIORITIZATION CONTEXT
```

from:

```text
ACTIVE VALIDATION
```

Required limitation:

> Route and topology evidence do not prove active reachability. This is prioritization context, not validation evidence.

---

# 12. Phase 6 — Test Reconstruction

Dedicated tests must exist for every newly introduced component.

## A. Transit priority tests

Test:

- valid assessment mapping
- priority ordering
- NONE behavior
- evidence summary behavior
- invalid state rejection

## B. Next-step analysis tests

Test:

- empty pool
- one candidate
- multiple priorities
- equal priorities
- evidence strength
- deterministic tie-breaking
- input permutations
- baseline context
- no baseline
- real candidate path

## C. CLI tests

Test:

```text
Help
Default output
JSON shorthand
Explicit JSON
Global no-color
Global verbose
Baseline success
Missing baseline
No candidate
Candidate present
Candidate-present JSON
Exit codes
```

## D. Regression tests

The following command families must remain stable:

```text
discover
map
baseline
compare
check
gateway/transit evidence
```

---

# 13. Phase 7 — MyPy Recovery

The project currently requires a complete type audit.

Every MyPy error must be categorized:

1. real implementation bug
2. missing annotation
3. Optional handling problem
4. collection type mismatch
5. public API mismatch
6. third-party limitation
7. genuine tool/configuration issue

## Rules

Do not use broad suppression.

Avoid:

```python
# type: ignore
```

without a specific reason.

If an ignore is unavoidable, it must contain:

- precise error code
- local justification
- confirmation that the code remains safe

Goal:

```text
ZERO unexplained MyPy errors
```

---

# 14. Phase 8 — Ruff Recovery

Ruff findings must be separated into:

```text
A. Safe mechanical fixes
B. Style issues
C. Potential semantic changes
```

Only automatically apply changes that are semantically safe.

After each fix batch:

```bash
python -m pytest tests/ -v
mypy ...
ruff check ...
```

Inspect the diff before continuing.

Avoid unrelated repository-wide churn.

Goal:

```text
ZERO unexplained Ruff errors
```

---

# 15. Phase 9 — Stabilization Quality Gates

STABILIZATION-1 is complete only when all gates pass.

## Functional gate

```bash
python -m pytest tests/ -v
```

Result:

```text
ALL PASS
```

## Next feature gate

```text
All dedicated next/transit tests pass.
```

## Candidate-present gate

```text
A real deterministic candidate can be selected
without exception.
```

## JSON gate

```text
Candidate-present JSON output is valid and parses correctly.
```

## Type gate

```text
MyPy clean according to project policy.
```

## Lint gate

```text
Ruff clean according to project policy.
```

## CLI gate

```text
Exit codes match the documented contract.
```

## Architecture gate

Verify:

- no hidden network activity was introduced
- no automatic scanning was introduced
- no automatic target expansion was introduced
- existing commands did not regress
- no unrelated feature scope was added

---

# 16. Definition of Done for STABILIZATION-1

The milestone is complete only if:

```text
[ ] Full test suite passes
[ ] Dedicated next tests pass
[ ] Candidate-present path passes
[ ] TransitEvidence semantic matrix is internally consistent
[ ] Impossible states cannot be derived
[ ] Derived states pass validation
[ ] TransitPriority representation is consistent
[ ] CLI exit codes are verified
[ ] JSON output is valid
[ ] MyPy is clean or all exceptions are justified
[ ] Ruff is clean or all exceptions are justified
[ ] Git diff contains no unrelated feature work
[ ] proxy-check has NOT been started
```

---

# 17. Development After Stabilization

Only after STABILIZATION-1 is green should feature development resume.

Recommended development order:

## Milestone 2 — Evidence Gap Analysis

Operator question:

> What evidence is missing before I spend time validating this transit candidate?

Possible capabilities:

- route evidence status
- neighbor evidence status
- connection evidence status
- validation status
- explicit distinction between NOT OBSERVED and NOT COLLECTED

Possible command direction:

```bash
pivotcheck gaps NETWORK
```

or:

```bash
pivotcheck explain NETWORK --gaps
```

This must remain passive analysis.

---

## Milestone 3 — Pivot Candidate Explanation

Operator question:

> Why is this network considered an investigation candidate?

The explanation should show:

```text
Observed route evidence
        +
Observed neighbor evidence
        +
Observed connection evidence
        +
Comparison context
        ↓
Inferred transit assessment
        ↓
Operator priority
```

It must explicitly list limitations.

---

## Milestone 4 — Controlled Batch Validation

Potential purpose:

Allow an operator to validate a small explicit list of targets.

Strict limitations:

- explicit targets only
- no CIDR expansion
- no automatic discovery
- no automatic port ranges
- bounded target count
- machine-readable output

---

## Milestone 5 — Routing Domain / Boundary Signals

Potential analysis:

- gateway transitions
- interface transitions
- default-route changes
- routing-domain changes

Required wording:

```text
POSSIBLE ROUTING DOMAIN TRANSITION
```

Never:

```text
SECURITY BOUNDARY CONFIRMED
```

without evidence beyond PivotCheck's collection model.

---

## Milestone 6 — Structured Output Evolution

Enhance machine-readable output with:

```text
schema_version
command_metadata
perspective identity
structured limitations
stable serialization contracts
```

---

# 18. Long-Term Target Architecture

```text
                         PIVOTCHECK
                             │
        ┌────────────────────┼────────────────────┐
        ▼                    ▼                    ▼
   DISCOVER              ANALYZE               VALIDATE
        │                    │                    │
        │                    │                    └─ Explicit only
        │                    │
        │             ┌──────┴──────┐
        │             ▼             ▼
        │         TOPOLOGY       COMPARISON
        │             │             │
        │             ▼             ▼
        │       TRANSIT CONTEXT  CHANGE CONTEXT
        │             │             │
        └─────────────┴──────┬──────┘
                             ▼
                    OPERATOR INTELLIGENCE
                             │
             ┌───────────────┼───────────────┐
             ▼               ▼               ▼
          MAP VIEW        NEXT STEP       EXPLAIN
                             │
                             ▼
                     EXPLICIT VALIDATION
```

The intended operator workflow is:

```text
1. DISCOVER
      │
      ▼
2. MAP THE CURRENT PERSPECTIVE
      │
      ▼
3. SAVE / COMPARE A BASELINE
      │
      ▼
4. IDENTIFY CHANGES
      │
      ▼
5. PRIORITIZE WITH `next`
      │
      ▼
6. EXPLAIN THE CANDIDATE
      │
      ▼
7. IDENTIFY EVIDENCE GAPS
      │
      ▼
8. OPERATOR CHOOSES EXPLICIT TARGET
      │
      ▼
9. VALIDATE WITH `check`
      │
      ▼
10. RECORD THE NEW PERSPECTIVE
```

---

# 19. Final Engineering Principle

PivotCheck should become a tool that is trusted because it is conservative.

The tool must prefer:

```text
"I observed this evidence."
```

over:

```text
"This is definitely possible."
```

It must prefer:

```text
"Here is the highest-priority candidate."
```

over:

```text
"Attack this network."
```

It must prefer:

```text
"Explicit validation is required."
```

over:

```text
"Route evidence proves access."
```

The central engineering objective is therefore:

> **Turn fragmented network evidence into deterministic operator decision support without confusing inference with proof.**
