# Perspective-aware maps

`pivotcheck map` continues to show only the current discovered topology.

`pivotcheck map --baseline workstation` adds saved-perspective context: it
maps current evidence and groups the already-computed comparison delta. Use
`--format json` for the same presentation groups as machine-readable data.

Markers are meaningful without color:

- `[+]` newly observed address-space coverage
- `[>]` expanded coverage
- `[*]` more-specific topology evidence
- `[~]` route context changed
- `[-]` baseline coverage not observed from the current vantage point
- `[=]` current or unchanged evidence
- `[?]` inferred pivot context

The map shows discovered interfaces, routes, and inferred pivot paths. It
does not validate active reachability or assert that an inferred pivot is
available.

## Evidence graph (v2.0 Step 4)

`analysis/graph.py` builds a directed evidence-bounded graph from
normalized edge specifications (or directly from a `DiscoverySnapshot`)
and performs bounded simple-path discovery. It is pure analysis: no
network, subprocess, filesystem, or environment access.

- Edge kinds mirror real evidence: `ROUTABLE_TO` (route-table entry;
  INFERRED — the entry is observed, forwarding is not), `L2_NEIGHBOR`
  (ARP observation; OBSERVED), `NETWORK_CONNECTED`, `SERVICE_OBSERVED`,
  `AUTH_VALIDATED` (explicit prior validation only).
- Every edge and node carries an epistemic state (OBSERVED / INFERRED /
  EXPLICITLY_VALIDATED / NEGATIVE / CONTRADICTORY / UNKNOWN). Conflicting
  evidence merges to CONTRADICTORY — never silently normalized.
- IPv4 and IPv6 are structurally isolated: cross-family edges are
  rejected at construction.
- Paths are evidence-composition candidates
  (`EVIDENCE_SUPPORTED` / `PARTIALLY_VALIDATED` / `INFERRED_ONLY` /
  `CONTRADICTED` / `EXPLICITLY_VALIDATED`), ranked deterministically,
  bounded by `max_hops` (default 4) and `max_paths` (default 32), with
  simple-path cycle handling.

A path never means "this pivot works". Connectivity is not
authentication, forwarding, execution, tunneling, or capability — the
graph is the reasoning layer; explicit validation remains the proof layer.
