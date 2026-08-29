# PivotCheck — Project Architecture

**Status:** Architecture Specification  
**Project:** PivotCheck  
**Purpose:** Evidence-driven network perspective discovery, topology interpretation, comparison, and operator decision support.

---

# 1. Architectural Mission

PivotCheck is designed to answer a narrow but difficult operational question:

> **What does this current network vantage point reveal, what changed from a previous vantage point, and what evidence-backed investigation should an operator consider next?**

PivotCheck is **not** a network scanner, exploitation framework, automatic pivot engine, or attack automation platform.

Its architecture is built around one central principle:

> **Observed evidence must remain distinguishable from deterministic inference, prioritization, and active validation.**

The project therefore separates:

- collection,
- normalized facts,
- deterministic analysis,
- operator decision support,
- explicit validation,
- rendering,
- persistence,
- CLI orchestration.

No presentation layer should invent evidence. No recommendation layer should silently become validation. No inferred conclusion should be represented as directly observed fact.

---

# 2. High-Level Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│                         OPERATOR                             │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                           CLI                                │
│                                                              │
│ discover | map | baseline | compare | check | next          │
└──────────────────────────────┬───────────────────────────────┘
                               │
                CLI orchestration only
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                    DISCOVERY / COLLECTION                    │
│                                                              │
│ local providers | remote SSH providers | parsers            │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                     NORMALIZED MODELS                        │
│                                                              │
│ Interface | Address | Route | Neighbor | Connection          │
│ DNS | Network | PivotPath | DiscoverySnapshot               │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                    PURE ANALYSIS LAYER                       │
│                                                              │
│ topology | comparison | recommendation | gateway             │
│ transit priority | next-step selection                       │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                   OPERATOR INTELLIGENCE                      │
│                                                              │
│ DiffReport | Recommendation | TransitEvidence                │
│ ComparisonContext | NextStepCandidate                        │
└──────────────────────────────┬───────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────┐
│                    OUTPUT / SERIALIZATION                    │
│                                                              │
│ text renderers | JSON renderers | deterministic ordering     │
└──────────────────────────────────────────────────────────────┘
```

---

# 3. Layered Dependency Contract

The intended dependency direction is:

```text
MODELS
   ↓
DISCOVERY / NORMALIZATION
   ↓
ANALYSIS
   ↓
OUTPUT
   ↓
CLI
```

Persistence and validation interact with models and analysis where necessary but must not create circular dependencies.

## Forbidden dependency direction

```text
models  ──X──> cli
analysis ──X──> cli
output   ──X──> discovery
models   ──X──> output
```

The core rule is:

> **Lower layers must never depend on higher presentation or orchestration layers.**

---

# 4. Repository-Level Architecture

The expected conceptual repository layout is:

```text
pivotcheck/
│
├── __init__.py
├── cli.py
│
├── models/
│   ├── discovery.py
│   ├── topology.py
│   ├── comparison.py
│   ├── recommendation.py
│   ├── check.py
│   └── next_step.py
│
├── discovery/
│   ├── collectors/
│   ├── providers/
│   ├── parsers/
│   └── normalization/
│
├── analysis/
│   ├── topology.py
│   ├── comparison.py
│   ├── recommendation.py
│   ├── gateway.py
│   ├── transit_priority.py
│   └── next_step.py
│
├── checks/
│   ├── resolver.py
│   └── tcp.py
│
├── storage/
│   ├── baseline.py
│   └── schema.py
│
├── output/
│   ├── terminal.py
│   ├── discovery.py
│   ├── map_view.py
│   ├── comparison.py
│   ├── check.py
│   └── next_step.py
│
└── tests/
    ├── unit/
    ├── integration/
    └── regression/
```

The exact current repository structure may differ. This document describes the target architectural responsibility boundaries.

---

# 5. Core Data Flow

## 5.1 Discovery Flow

```text
Operating System / SSH Host
        │
        ▼
Raw Commands / Provider Data
        │
        ▼
Parser
        │
        ▼
Normalized Domain Models
        │
        ▼
DiscoverySnapshot
```

The discovery system should collect facts without deciding whether something is an interesting pivot.

For example:

```text
Raw route:
10.50.0.0/16 via 10.10.20.254 dev eth1 metric 50

             │
             ▼

Normalized Route:
Route(
    destination="10.50.0.0/16",
    gateway="10.10.20.254",
    interface="eth1",
    metric=50
)
```

The parser does not say:

> "This is a viable pivot."

That conclusion belongs to a higher analysis layer.

---

# 6. DiscoverySnapshot as the Evidence Boundary

`DiscoverySnapshot` is the primary normalized representation of one network perspective.

Conceptually:

```text
DiscoverySnapshot
│
├── interfaces
│   ├── name
│   ├── state
│   └── addresses
│
├── routes
│   ├── destination
│   ├── gateway
│   ├── interface
│   ├── metric
│   └── route type
│
├── neighbors
│   ├── address
│   ├── interface
│   ├── state
│   └── link-layer address
│
├── connections
│   ├── protocol
│   ├── local endpoint
│   ├── remote endpoint
│   └── state
│
├── DNS configuration
│
├── inferred networks
│
└── inferred pivot paths
```

This object is the boundary between **collection** and **analysis**.

---

# 7. Evidence Architecture

PivotCheck must maintain an explicit evidence hierarchy.

```text
LEVEL 1 — OBSERVED
│
│ Directly collected facts
│
├── Route observed
├── Neighbor observed
├── Connection observed
└── Interface observed

        ↓ deterministic analysis

LEVEL 2 — INFERRED
│
├── Network classification
├── Pivot path
├── Transit assessment
└── Topology relationship

        ↓ deterministic prioritization

LEVEL 3 — PRIORITIZATION
│
├── HIGH
├── MEDIUM
├── LOW
└── NONE

        ↓ explicit operator action

LEVEL 4 — ACTIVE VALIDATION
│
├── TCP success
├── Connection refused
├── Timeout
├── No route
└── DNS error
```

These levels must never be collapsed.

---

# 8. Transit Evidence Architecture

Transit evidence is a composition layer.

Conceptually:

```text
                 Route
                   │
                   ▼
            ┌───────────────┐
Neighbor ──▶│ TransitEvidence│◀── Connection
            └───────────────┘
                   │
                   ▼
          Transit Assessment
```

The analysis may produce states such as:

```text
MULTIPLE_SUPPORTING_SIGNALS
ROUTING_PLUS_L2_EVIDENCE
ROUTING_PLUS_ACTIVE_TCP_EVIDENCE
ROUTING_PLUS_ACTIVE_UDP_EVIDENCE
ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE
ROUTING_ONLY
ROUTING_WITH_NEGATIVE_L2_EVIDENCE
CONTRADICTORY_EVIDENCE
INSUFFICIENT_EVIDENCE
```

## Architectural invariant

Every declared assessment state must satisfy all three conditions:

```text
DOCUMENTED
    AND
VALID MODEL STATE
    AND
REACHABLE FROM DERIVATION
```

Formally:

```text
State ∈ Documentation
        ==
State accepted by model
        ==
State producible by analysis
```

If this is false, the state machine is architecturally inconsistent.

---

# 9. Transit Evidence State Machine

The target design should make state transitions explicit.

```text
Raw evidence
    │
    ├── no usable evidence
    │        └──> INSUFFICIENT_EVIDENCE
    │
    ├── route only
    │        └──> ROUTING_ONLY
    │
    ├── route + neighbor
    │        └──> ROUTING_PLUS_L2_EVIDENCE
    │
    ├── route + active TCP evidence
    │        └──> ROUTING_PLUS_ACTIVE_TCP_EVIDENCE
    │
    ├── route + historical TCP evidence
    │        └──> ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE
    │
    └── conflicting signals
             └──> CONTRADICTORY_EVIDENCE
```

The model validation must support every state that the derivation function can return.

The derivation function must not return states prohibited by the model.

---

# 10. Comparison Architecture

Comparison is a pure relationship analysis between two perspectives.

```text
Baseline Snapshot
       │
       │
       ├──────────────┐
       │              │
       ▼              ▼
Current Snapshot    Normalization
       │              │
       └──────┬───────┘
              ▼
       Comparison Engine
              │
              ▼
          DiffReport
              │
              ├── NEW
              ├── EXPANDED
              ├── REDUCED
              ├── MORE_SPECIFIC
              ├── CONTEXT_CHANGED
              └── UNCHANGED
```

Comparison answers:

> What changed?

It must not directly answer:

> What is reachable?

That belongs to explicit validation.

---

# 11. Recommendation Architecture

Recommendations are derived from evidence and comparison findings.

```text
DiffReport
    │
    ▼
Recommendation Rules
    │
    ├── HIGH
    ├── MEDIUM
    ├── LOW
    └── NONE
```

A recommendation contains:

```text
Priority
Reason
Network
Supporting context
```

A recommendation is **decision support**, not proof.

---

# 12. Next-Step Architecture

The `next` command is the top-level operator prioritization feature.

```text
DiscoverySnapshot
      │
      ├──────────────► Transit Evidence
      │
      ├──────────────► Comparison Context (optional)
      │
      └──────────────► Recommendations
                         │
                         ▼
                 Candidate Construction
                         │
                         ▼
                 Deterministic Ranking
                         │
                         ▼
                 Single Candidate
                         │
                         ▼
                    NextStepReport
```

## Ranking pipeline

```text
Candidate Pool
      │
      ▼
Priority Rank
HIGH > MEDIUM > LOW
      │
      ▼
Evidence Strength Rank
      │
      ▼
Deterministic Network Tie-break
      │
      ▼
Selected Candidate
```

No random behavior is permitted.

No external network activity is permitted.

---

# 13. `pivotcheck next` Execution Flow

```text
pivotcheck next
       │
       ▼
Parse CLI arguments
       │
       ▼
Run discovery once
       │
       ├── baseline absent
       │       └── analyze current evidence
       │
       └── baseline present
               │
               ▼
         Load baseline
               │
               ▼
         Compare perspectives
               │
               ▼
         Generate recommendation context
       │
       ▼
Assess transit evidence
       │
       ▼
Select next investigation
       │
       ▼
Render text or JSON
```

The CLI must orchestrate only. It should not duplicate selection logic.

---

# 14. Active Validation Architecture

`check` is intentionally separate from `next`.

```text
NEXT
│
│ "What should receive attention?"
│
▼
Operator chooses explicit target + port
│
▼
CHECK
│
▼
TCP validation
│
├── SUCCESS
├── REFUSED
├── TIMEOUT
├── NO_ROUTE
├── UNREACHABLE
├── DNS_ERROR
├── INVALID_TARGET
└── LOCAL_ERROR
```

This separation is critical.

`next` may say:

> Investigate this network first.

It must not say:

> A target in this network is reachable.

Only explicit validation may provide validation evidence.

---

# 14.1 SOCKS5 Proxy-Path Validation (`proxy-check`)

`proxy-check` is the second explicit-validation surface, alongside `check`.
It answers exactly one operator question:

> Can this explicitly supplied SOCKS5 proxy endpoint establish a TCP
> connection to this explicitly supplied destination host:port right now,
> under this timeout?

## Component placement

```text
CLI (cli.py: _run_proxy_check)
  │  argument validation only — no network activity
  ▼
checks/proxy.py          parse_proxy_url / check_proxy (protocol engine)
  │                        │ reuses checks/resolver.py (proxy endpoint only)
  │                        │ reuses checks/tcp.py (validate_port/timeout, error classification)
  ▼
models/proxy_check.py    ProxyCheckReport / ProxyStage / verdict invariants
  │
  ▼
output/proxy_check.py    render_proxy_check (text) / render_proxy_check_json
```

Dependency direction is unchanged: CLI → checks → models; output → models.
The protocol engine never imports CLI or output modules and is testable
without them.

## Three-stage model

1. **proxy_tcp** — TCP connection from the local operator vantage to the
   proxy endpoint. Uses `CheckStatus`-compatible transport semantics
   (SUCCESS, REFUSED, TIMEOUT, NO_ROUTE, UNREACHABLE, DNS_ERROR, LOCAL_ERROR).
2. **socks5_negotiation** — RFC 1928 method selection plus optional RFC 1929
   username/password authentication. Outcomes: SUCCESS, TIMEOUT,
   PROXY_PROTOCOL_ERROR, NO_ACCEPTABLE_AUTH_METHOD, AUTH_FAILED.
3. **destination_connect** — the SOCKS5 CONNECT transaction. Preserves RFC
   1928 §6 reply codes verbatim (SUCCESS, GENERAL_FAILURE,
   NOT_ALLOWED_BY_RULESET, NETWORK_UNREACHABLE, HOST_UNREACHABLE,
   CONNECTION_REFUSED, TTL_EXPIRED, COMMAND_NOT_SUPPORTED,
   ADDRESS_TYPE_NOT_SUPPORTED) plus TIMEOUT and PROXY_PROTOCOL_ERROR.

The verdict is `VALIDATED` only when all three stages succeeded; otherwise
the first failing stage's classification stands (`NOT_VALIDATED`). The model
forbids impossible stage/status combinations by construction.

## Deterministic fallback classification

Raw transport failures occurring *after* the TCP stage (for example, a
connection reset mid-exchange) carry no SOCKS5 reply meaning, and the model
forbids transport-only statuses on later stages. Such failures are
classified **PROXY_PROTOCOL_ERROR** — never success — with the raw OS error
preserved in the stage `detail`. TIMEOUT is passed through verbatim, since
every stage model permits it.

## DNS semantics

The destination is validated syntactically only. Hostname destinations are
sent to the proxy with ATYP 0x03 (proxy-side DNS) and are **never resolved
locally**; IPv4/IPv6 literals are sent verbatim with ATYP 0x01 / 0x04. Only
the proxy endpoint itself uses the local resolver.

## Safety invariants

One invocation performs exactly one controlled SOCKS5 transaction: no
scanning, no port ranges or lists (single explicit port), no CIDR
expansion, no automatic target generation, no retries, no chaining, no
tunneling or payload relay, no credential persistence beyond the invocation.

---

# 15. Baseline Storage Architecture

```text
Baseline Create
      │
      ▼
DiscoverySnapshot
      │
      ▼
Schema Validation
      │
      ▼
Versioned Baseline Document
      │
      ▼
Atomic Write
```

Read flow:

```text
Baseline Name
      │
      ▼
Load File
      │
      ▼
Schema Validation
      │
      ▼
Normalized Baseline Object
      │
      ▼
Comparison / Context
```

Storage must not modify analytical semantics.

---

# 16. Output Architecture

All output modules should consume already-derived domain/report objects.

```text
Analysis Result
      │
      ├──────────────► Text Renderer
      │
      └──────────────► JSON Renderer
```

Renderers must not:

- perform discovery,
- infer new topology,
- assign priority,
- alter evidence,
- perform validation.

## JSON requirements

JSON output should eventually standardize around:

```json
{
  "schema_version": "1.x",
  "tool": "pivotcheck",
  "version": "x.y.z",
  "command": "next",
  "timestamp": "...",
  "data": {},
  "limitations": []
}
```

JSON must be deterministic and ANSI-free.

---

# 17. CLI Architecture

The CLI is the composition root.

```text
Argument Parser
      │
      ▼
Command Dispatch
      │
      ├── discover
      ├── map
      ├── baseline
      ├── compare
      ├── check
      └── next
             │
             ▼
      Application Orchestration
             │
             ▼
        Analysis / Storage
             │
             ▼
           Output
```

Each command handler should follow:

```text
1. Validate arguments
2. Collect/load required input
3. Call pure domain/analysis functions
4. Render result
5. Return explicit exit code
```

Avoid:

```text
CLI handler
    ├── collection logic
    ├── comparison logic
    ├── ranking logic
    └── rendering logic
```

inside one function.

---

# 18. Type Architecture

The project should use explicit domain types for closed sets of values.

Examples:

```text
TransitAssessment
RecommendationPriority
ComparisonRelationship
ValidationStatus
AddressFamily
RouteType
```

## Target rule

Use an `Enum` or equivalent closed domain abstraction when:

- values are finite,
- validation matters,
- ordering/mapping depends on the value,
- serialization must be controlled.

Avoid ambiguous string-only state handling for core semantics.

---

# 19. Testing Architecture

Testing should mirror architecture.

```text
                    FULL REGRESSION
                           ▲
                           │
                    CLI INTEGRATION
                           ▲
                           │
                     OUTPUT TESTS
                           ▲
                           │
                    ANALYSIS TESTS
                           ▲
                           │
                     MODEL TESTS
```

## Model tests

Verify:

- valid states,
- invalid states,
- immutability,
- serialization.

## Analysis tests

Verify:

- deterministic ranking,
- state derivation,
- evidence combinations,
- permutation invariance.

## CLI tests

Verify:

- syntax,
- exit codes,
- baseline handling,
- JSON,
- no-candidate behavior.

## Regression tests

Verify existing commands remain unchanged.

---

# 20. Architecture Quality Gates

Before a milestone is considered complete:

```text
[ ] Full pytest suite passes
[ ] New feature tests exist
[ ] No known runtime crash path
[ ] MyPy passes at agreed scope
[ ] Ruff passes
[ ] Imports are clean
[ ] No circular dependencies
[ ] CLI exit codes are tested
[ ] JSON output is tested
[ ] Determinism is tested
[ ] Evidence semantics are documented
```

A feature is not complete merely because manual execution succeeds.

---

# 21. Current Stabilization Architecture Priority

The immediate architectural work should be:

```text
STABILIZATION-1
│
├── Repair TransitEvidence state consistency
│
├── Repair/confirm TransitPriority type contract
│
├── Make `next` candidate construction safe
│
├── Add dedicated next/transit tests
│
├── Repair CLI error-path semantics
│
├── Resolve MyPy errors
│
└── Resolve Ruff errors
```

The critical invariant is:

```text
Observed Evidence
      ↓
Valid Model
      ↓
Reachable Analysis State
      ↓
Valid Priority
      ↓
Valid Candidate
      ↓
Stable Output
```

Any break in this chain is a production defect.

---

# 22. Target Future Architecture

After stabilization:

```text
                         PivotCheck
                             │
          ┌──────────────────┼──────────────────┐
          │                  │                  │
      Perspective        Comparison         Validation
      Discovery          Intelligence        Workflow
          │                  │                  │
          ▼                  ▼                  ▼
      discover/map      compare/next        check
          │                  │                  │
          └──────────────┬───┴──────────────────┘
                         ▼
                  Evidence Model
                         │
                         ▼
              Future Analysis Extensions
                         │
          ┌──────────────┼──────────────┐
          ▼              ▼              ▼
    Evidence Gaps   Pivot Explain   Route Analysis
```

Future modules should reuse the evidence model rather than introduce duplicate evidence representations.

---

# 23. Architectural Non-Negotiables

## PivotCheck must always preserve:

1. **Observed facts remain distinguishable from inference.**
2. **Inference remains distinguishable from prioritization.**
3. **Prioritization remains distinguishable from validation.**
4. **No automatic target expansion occurs without explicit operator intent.**
5. **Analysis remains deterministic.**
6. **Core analysis remains side-effect free.**
7. **Output layers do not invent evidence.**
8. **Every documented semantic state is model-valid and derivation-reachable.**
9. **CLI is orchestration, not business logic.**
10. **Quality gates are part of the architecture, not post-development cleanup.**

---

# 24. Final Architecture Summary

PivotCheck should evolve as an evidence-first intelligence pipeline:

```text
COLLECT
   ↓
NORMALIZE
   ↓
OBSERVE
   ↓
INFER
   ↓
COMPARE
   ↓
PRIORITIZE
   ↓
EXPLAIN
   ↓
OPERATOR CHOOSES
   ↓
EXPLICITLY VALIDATE
```

The project succeeds architecturally when an operator can trace every conclusion backward:

```text
Recommendation
    ↓
Analysis Rule
    ↓
Inference
    ↓
Observed Evidence
```

And every active validation result remains independently identifiable:

```text
Validation Result
    ↓
Explicit Operator Action
    ↓
Target + Port
    ↓
Observed Runtime Outcome
```

That traceability is the architectural foundation of PivotCheck.
