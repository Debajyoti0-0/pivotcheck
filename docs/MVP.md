# PivotCheck — MVP Definition (v0.1.0)

Status: **Implemented.** This document is the original v0.1.0 plan, retained for
historical context. Delivered scope has since diverged from the proposal below;
**§0 is the authoritative reconciliation** of what actually shipped.

---

## 0. Implementation Status (reconciliation)

This section is the source of truth for *what shipped*; the numbered sections
that follow are the original proposal, left unedited on purpose.

**Shipped as planned**
- `discover`: OS / interface / route / neighbor / DNS / socket enumeration,
  normalized topology model, confidence classification, and text + `--json`
  output (§2 items 1–8).
- `check`: single-target TCP validation with precise error classification —
  deliberately *not* a scanner (explicit ports only, ranges rejected, ≤ 16
  ports per invocation).

**Deferred at v0.1.0, since implemented**
- `proxy-check` (SOCKS5 path validation — §2 item 10, §4) was initially
  deferred and has now been **implemented** (PROXY-CHECK-1 milestone) with a
  **stdlib-only** engine: RFC 1928 method negotiation (NO-AUTH,
  USERNAME/PASSWORD per RFC 1929) and one CONNECT request per invocation.
  `PySocks` remains unused by the implementation; the optional `socks` extra
  stays reserved for future work.

**Added beyond the original MVP** (listed as non-goals in §3, but since built)
- `baseline create|list|show|delete` — save and manage named perspectives.
  See [baseline-workflow.md](baseline-workflow.md).
- `compare <baseline>` with `--summary` / `--evidence` / `--recommend` /
  `--explain` views. See [comparison-semantics.md](comparison-semantics.md) and
  [operator-intelligence.md](operator-intelligence.md).
- `map` — topology-focused presentation of the same discovery data.
  See [perspective-map.md](perspective-map.md).
- Remote collection over SSH (`--ssh` / `--ssh-user`).
  See [session-providers.md](session-providers.md).

For current usage, see the top-level [README.md](../README.md).

---

## 1. Core Problem Analysis

Obtaining a foothold answers "can I execute commands here?" — it does not answer
"what can I actually reach from here?". Today that question is answered by manually
stitching together output from `ip`, `route`, `arp`, `ss`, `/etc/resolv.conf`,
`ping`, `nc`, and proxy tooling, then reasoning about it by hand.

The biggest operational gap is not *gathering* this data (tools exist for that).
The gap is:

1. **Normalization** — turning heterogeneous system state into one coherent model.
2. **Classification** — separating *directly connected*, *routed*, and *inferred*
   networks with explicit confidence.
3. **Validation** — confirming whether a configured pivot path (SOCKS/SSH/chisel)
   actually reaches a target, with failure diagnosis (route vs firewall vs DNS vs
   proxy vs service-down).

PivotCheck v0.1.0 targets gaps 1 and 2 fully, and gap 3 partially (single-target
TCP checks + SOCKS5 proxy-check).

## 2. Smallest Valuable Feature Set

| # | Capability | Mode |
|---|------------|------|
| 1 | OS detection, interface enumeration (IPv4/IPv6, state, MAC) | `discover` |
| 2 | Routing table parse: default gw, connected routes, static routes | `discover` |
| 3 | ARP/neighbor table collection | `discover` |
| 4 | DNS resolver configuration discovery | `discover` |
| 5 | Listening sockets & established connections | `discover` |
| 6 | Normalized topology model + confidence classification | `discover` |
| 7 | Human-readable output with PIVOT SUMMARY + recommended next step | all |
| 8 | Structured JSON output (`--json`, stable schema) | all |
| 9 | Single-target TCP reachability check with error classification | `check` |
| 10 | SOCKS5 proxy path validation (negotiation + target connect) | `proxy-check` |

## 3. Explicit Non-Goals for v1

- ❌ Network scanning / host sweeps (no `nmap` replacement)
- ❌ ICMP ping sweeps or traceroute
- ❌ Proxy/tunnel deployment (no chisel/ligolo orchestration)
- ❌ SOCKS4 / HTTP CONNECT (SOCKS5 only in v1)
- ❌ Snapshot diffing (`diff`), multi-host comparison (`compare`)
- ❌ Windows/macOS support (architecture prepared, Linux implemented)
- ❌ Plugin system, graph export, HTML reports
- ❌ Any exploitation, credential, persistence, or attack functionality

## 4. CLI Commands (v1)

> **HISTORICAL SKETCH — SUPERSEDED BY THE SHIPPED CLI.** The syntax below is
> the original v0.1.0 draft, retained for provenance. The authoritative
> command surface is `README.md` and `PROJECT_OUTPUT.md`. Notably: the shipped
> `check` **rejects CIDR notation** (PivotCheck validates one explicit host at
> a time — a deliberate safety invariant), and `discover` never shipped
> `--save`/`--quiet` (persistence is provided by `baseline create`).

```
pivotcheck discover [--json] [--save FILE] [--quiet]
pivotcheck check <ip|cidr> [--port N] [--timeout S] [--json]
pivotcheck proxy-check --proxy socks5://host:port <target> [--port N] [--json]
pivotcheck --version
pivotcheck --help
```

Notes:
- `map` and `report` are deferred; `discover` covers both in v1. Fewer verbs,
  less confusion (Design Philosophy #3).
- `--save FILE` writes JSON now; `diff` consumes it later — forward-compatible
  without shipping the feature.

## 5. Project Structure

As specified in the master prompt (§6). One deviation: `checks/dns.py` merges
into `checks/tcp.py`-adjacent logic only if DNS checks are needed for `check`;
otherwise omitted until required. No speculative modules.

## 6. Normalized Data Models

```python
Interface(name, state, mac_address, ipv4_addresses, ipv6_addresses, networks)
Route(destination, gateway, interface, metric, route_type)  # default|connected|static
Neighbor(ip_address, mac_address, interface, state)
DNSServer(address, source)          # resolv.conf / NetworkManager
Connection(local, remote, state, protocol)
Network(cidr, origin, confidence)   # origin: connected|routed|inferred
ReachabilityResult(target, port, status, latency_ms, error_class, error_detail)
ProxyCheckResult(proxy, target, stages: dict[str, StageResult], verdict)
PivotPath(source_interface, gateway, destination_network, confidence)
DiscoverySnapshot(tool, version, timestamp, hostname, os, interfaces, routes,
                  neighbors, dns, connections, networks, pivot_paths)
```

Confidence: `HIGH` = directly connected + interface UP;
`MEDIUM` = explicit routing table entry via gateway;
`LOW` = inferred (reserved for future use; unused in v1).

## 7. Acceptance Criteria — v0.1.0

1. `pivotcheck discover` completes on a stock Linux host **without root**,
   degrading gracefully (warnings, never crash) when tables are unreadable.
2. Output matches sectioned terminal format incl. PIVOT SUMMARY and one
   evidence-backed recommended action.
3. `--json` emits valid JSON against the documented schema, no ANSI codes.
4. `check 10.10.20.25 --port 445` distinguishes: reachable / refused /
   timeout / no-route / resolution-failure.
5. `proxy-check --proxy socks5://... target` reports per-stage results
   (proxy TCP → SOCKS handshake → target connect) with clear verdict.
6. Unit tests ≥ 80% coverage on parsers and analysis; parsers tested against
   fixture outputs of `ip addr`, `ip route`, `ip neigh`, `ss -tunap`,
   `/etc/resolv.conf` from at least Debian and Arch variants.
7. `pip install .` works; runtime deps ≤ 1 third-party package (target: zero;
   stdlib-only including a hand-rolled minimal SOCKS5 client).
8. Full type hints on public APIs; passes ruff + mypy clean.

## 8. Highest Technical Risks

| Risk | Mitigation |
|------|-----------|
| Parsing `ip`/`ss` output varies across distros/locales | Parse with tolerant regexes + fixtures; prefer netlink-free stdlib parsing; pin `LC_ALL=C` when invoking commands |
| Root-required data (some neighbor details) | Degrade with explicit `[!]` warnings; never abort |
| Route ambiguity (multiple defaults, policy routing) | v1 handles main table only; document limitation; warn on multiple defaults |
| Timeout tuning across slow pivots | Configurable `--timeout`, sensible default (3s), concurrency cap (default 10 threads max) |
| SOCKS5 edge cases (auth methods, UDP ASSOCIATE) | v1: CONNECT only, NO-AUTH + user/pass; explicit unsupported-method error |
| Windows divergence | All platform calls isolated behind `discovery/` interfaces from day one |

## 9. Development Phases

Phase 1 Architecture ✅ (this document) → Phase 2 Passive Discovery →
Phase 3 Analysis → Phase 4 Reachability → Phase 5 Proxy Validation →
Phase 6 Output/Reporting → Phase 7 Quality/Tests/Docs.
