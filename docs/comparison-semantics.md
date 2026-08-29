# Network perspective comparison semantics

PivotCheck compares **coverage** separately from the evidence used to describe
that coverage. Exact identity means identical canonical CIDRs. For CIDR blocks
in one address family, overlap always means equality or containment; a genuine
partial-overlap state is impossible. IPv4 and IPv6 are independent.

The coverage view uses `ipaddress.collapse_addresses()`. Therefore
`10.20.0.0/25` plus `10.20.0.128/25` and `10.20.0.0/24` have equivalent
coverage: neither is new reachability. The individual input entries remain in
the evidence view, so their operational context is not discarded.

A current `10.20.10.0/24` beneath baseline `10.20.0.0/16` is not new
reachability: baseline covers it. It is a more-specific, topology-novel piece
of evidence. Conversely, a current `/16` over a baseline `/24` expands
reachability. A baseline `/16` followed by current `/24` records reduced
coverage against the original `/16`; version 1 deliberately does not generate
residual CIDRs.

An exact CIDR with a different interface, gateway, route type, or confidence
is a route-context change, not a new network. Route evidence remains evidence,
not proof that every address in a route is actively reachable.
