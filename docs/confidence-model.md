# Confidence Model — Exact Semantics

This document specifies precisely how PivotCheck assigns network
confidence levels, what can and cannot change them, and what confidence
does not mean. The rules below describe the implementation in
`pivotcheck/analysis/topology.py` (the only producer of confidence) and
`pivotcheck/models/network.py` (the enum definitions). They are
deterministic: the same evidence always produces the same confidence.

## The three levels

Confidence describes **how directly the network's presence is evidenced
from this vantage point**. It is a semantic label derived from evidence
attributes at classification time — never a score, never accumulated,
never recomputed from richer evidence later.

| Level | Produced by | Rule |
|-------|-------------|------|
| HIGH  | `classify_networks()` | The network address is carried by an interface whose state is UP. |
| MEDIUM | `classify_routed_networks()` | A STATIC routing-table entry via a gateway names the network. |
| LOW   | `classify_networks()` / `analyze_evidence_gaps()` | The address is carried by a DOWN or UNKNOWN-state interface, or the network is inferred only (not in the snapshot — treated as not observed). |

Exact rules, by source:

- **HIGH** requires an UP interface carrying the address
  (`topology.py`: `confidence = HIGH if iface.state == InterfaceState.UP
  else LOW`). There is no other path to HIGH.
- **MEDIUM** is assigned unconditionally to STATIC routes with a gateway
  (`topology.py:56-71`). Routing evidence can never raise confidence
  above MEDIUM: **routing ≠ reachability**.
- **LOW** covers down/unknown interfaces and inferred (not-observed)
  networks (`evidence_gaps.py:98-106` synthesizes absent networks as
  `INFERRED`/LOW).

## Merge and precedence rules

- Routed entries that duplicate a connected network are dropped — direct
  connectivity supersedes a gateway path to the same CIDR
  (`analyze()`, `topology.py:100-115`).
- Pivot paths into an already-connected network are not created.
- If the same CIDR is seen twice (e.g., an interface flapped), the
  HIGH-confidence entry is preferred for the stable result.
- `/0` prefixes are skipped entirely: they carry no usable local network
  information.

## What confidence is NOT

- **Confidence is not reachability.** A MEDIUM network is *routed from
  this vantage point*; nothing more. It is never presented as reachable.
- **Confidence is not investigation priority.** A separate,
  independently-derived `TransitPriority` (HIGH/MEDIUM/LOW/NONE in
  `analysis/transit_priority.py`) ranks what to investigate next.
  Stale L2 evidence plus an active TCP observation can yield HIGH
  *priority* (`MULTIPLE_SUPPORTING_SIGNALS_STALE_L2`) while the network's
  confidence remains unchanged. Priority is decision support; confidence
  is evidence classification.
- **Confidence is not prediction.** OPSEC intelligence predicts the
  observability of a *validation action*; it never feeds confidence.

## Contradictions and stale evidence

- Negative or contradictory evidence is surfaced, never normalized into
  a higher confidence: a FAILED neighbor alongside an active TCP
  observation yields `CONTRADICTORY_EVIDENCE` and priority NONE
  (`models/check.py:515-516`).
- Routing plus negative L2 evidence yields
  `ROUTING_WITH_NEGATIVE_L2_EVIDENCE` and priority NONE
  (`models/check.py:524-525`).
- In the graph view, a positive claim conflicting with a negative claim
  merges to `CONTRADICTORY` — "never silently normalized"
  (`analysis/graph.py:61-82`, `models/graph.py:15`).
- Assessment consistency is enforced structurally:
  `TransitEvidence.__post_init__` rejects inconsistent combinations
  (`models/check.py:395-410`).

**Invariant: neither stale nor contradictory evidence can raise network
confidence to HIGH.** HIGH is reachable only through an UP interface
carrying the address.

## Where confidence appears in output

- `discover` / `map`: per-network HIGH/MEDIUM/LOW labels.
- `map --minimum-confidence LEVEL`: presentation filtering only; the
  underlying comparison semantics are never altered by query options.
- Baselines: confidence is retained per network and surfaces as a
  `ROUTE_CONTEXT_CHANGED` finding when it changes between two
  perspectives.
