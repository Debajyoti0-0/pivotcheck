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
