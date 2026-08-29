# PivotCheck — Project Output Simulation Design

## 1. Purpose

This document defines **simulated and expected output behavior** for PivotCheck.

It is not an implementation specification for new collection logic. It defines how the
operator should experience each command through:

- normal text output;
- JSON output;
- empty-result output;
- warning and degraded-evidence output;
- error output;
- baseline-aware output;
- evidence-state output;
- deterministic ordering.

The simulation design exists to make output behavior testable before and after implementation.
Every command should be able to produce predictable output fixtures for unit, integration,
regression, and operator-acceptance testing.

---

# 2. Core Simulation Principles

## 2.1 Simulation is deterministic

Given the same normalized input snapshot, baseline, filters, and command arguments:

1. the same records must be selected;
2. records must appear in the same order;
3. priorities must be identical;
4. JSON field ordering must be stable where serialization supports it;
5. text output must contain the same semantic sections.

Simulation fixtures must never depend on:

- current system clock unless explicitly injected;
- live network state;
- environment-specific interface ordering;
- randomized identifiers;
- host-specific temporary paths.

## 2.2 Simulation does not imply validation

A simulated output containing a network, route, neighbor, connection, or pivot path does not
mean the target is reachable.

Use these terms consistently:

| State | Meaning |
|---|---|
| OBSERVED | Directly collected |
| INFERRED | Deterministically derived from observed evidence |
| NOT_OBSERVED | Collector did not observe it |
| NOT_COLLECTED | Relevant collection was unavailable or degraded |
| UNKNOWN | Evidence cannot determine the state |
| NOT_ACTIVELY_VALIDATED | No explicit check was performed |
| PRIORITIZATION_CONTEXT | Decision-support information only |
| ACTIVELY_VALIDATED | Explicit validation produced a result |

Never simulate stronger certainty than the underlying fixture supports.

---

# 3. Global Simulation Contract

## 3.1 Global command shape

```text
pivotcheck [GLOBAL_OPTIONS] COMMAND [COMMAND_OPTIONS]
```

> **HISTORICAL — PARTIALLY SUPERSEDED.** The shipped CLI's global arguments
> are `--version`, `--data-dir PATH`, `-v/--verbose`, and `--no-color`; the
> shipped per-command flags are `--format {text,json}` and `--json`
> (see `README.md` and `PROJECT_OUTPUT.md` §3–§4). The `--snapshot`,
> `--json-pretty`, `--now`, `--quiet`, and `--strict` flags below were part of
> an earlier design generation and were **never shipped**.

## 3.2 Common global flags

| Flag | Values / Default | Effect |
|---|---|---|
| `--snapshot <FILE>` | Path, required unless explicitly defaulted | Loads snapshot fixture |
| `--format` | `text`, `json`, `json-pretty` (default: `text`) | Selects output formatter |
| `--baseline <FILE>` | Path, optional | Loads baseline snapshot fixture |
| `--now <TIMESTAMP>` | ISO-8601 string, optional | Injects reference time for relative-time calculations |
| `--quiet` | Flag | Suppresses non-critical warnings in text output |
| `--strict` | Flag | Escalates missing required collection fields to errors |

---

# 4. Command-by-Command Simulation Specifications

> **HISTORICAL — SUPERSEDED (§4.1–§4.5).** The commands specified in this
> section — `status`, `interfaces`, `routes`, `sockets`, `pivots` — were part
> of the original design sketch and are **NOT PART OF THE SHIPPED CLI**. The
> shipped command surface is:
>
> ```text
> discover  map  baseline  compare  check  next  proxy-check
> ```
>
> Rough equivalents in the shipped tool: `status` → `discover --summary`;
> `interfaces`/`routes`/`sockets` → `discover` (full detail or `--json`);
> `pivots` → `map --show-pivots` and `next`. Do not implement the §4.1–§4.5
> specifications; they are retained for design provenance only.
> Section **§4.6 (`proxy-check`) matches the shipped tool** and remains
> authoritative.

## 4.1 `pivotcheck status`

### Purpose
Provide a high-level summary of collected host, network, routing, process, and connection snapshot state.

### Command options
- `--snapshot <FILE>` (required): Input snapshot.
- `--baseline <FILE>` (optional): Baseline snapshot for comparative delta metrics.
- `--format {text|json|json-pretty}` (default: `text`).

### Step-by-Step Simulation Flow

1. Parse snapshot fixture path (`--snapshot`).
2. Extract host summary (hostname, OS, uptime, collector execution duration).
3. Compute evidence counts: total interfaces, active routes, open listening ports, active sockets, processes.
4. Calculate collection completeness score based on presence of non-empty collector payloads.
5. If `--baseline` is passed, compute delta metrics (new interfaces, missing routes, modified listening ports).
6. Format output to stdout according to `--format`.

---

### Command Arguments & Execution Examples

#### Command 1: Text output standard status
```bash
pivotcheck --snapshot fixtures/snapshot_01.json status
```

**Simulated Text Output:**
```text
PivotCheck Status Summary
=========================
Host Name       : web-prod-01
OS / Kernel     : Linux 5.15.0-88-generic
Collected At    : 2026-03-29T10:15:00Z
Completeness    : 100% (5/5 collectors successful)

Observed Snapshot Totals:
  Interfaces    : 3
  Active Routes : 4
  Listen Ports  : 3
  Active Sockets: 12
  Processes     : 142

Baseline Comparison: None (run with --baseline for delta analysis)
```

#### Command 2: JSON output status with baseline comparison
```bash
pivotcheck --snapshot fixtures/snapshot_02.json status --baseline fixtures/snapshot_01.json --format json-pretty
```

**Simulated JSON Output:**
```json
{
  "command": "status",
  "timestamp": "2026-03-29T11:00:00Z",
  "host": {
    "hostname": "web-prod-01",
    "os": "Linux 5.15.0-88-generic"
  },
  "metrics": {
    "interfaces": 4,
    "active_routes": 5,
    "listen_ports": 4,
    "active_sockets": 15,
    "processes": 145
  },
  "baseline_delta": {
    "baseline_file": "fixtures/snapshot_01.json",
    "added_interfaces": ["docker0"],
    "removed_routes": [],
    "added_listen_ports": [8080]
  },
  "evidence_state": "COMPLETE"
}
```

---

## 4.2 `pivotcheck interfaces`

### Purpose
List all network interfaces, assigned IP addresses, states, and physical/virtual characteristics.

### Command options
- `--snapshot <FILE>` (required).
- `--type {all|physical|virtual|loopback}` (default: `all`).
- `--up-only` (flag): Show only interfaces in UP state.
- `--format {text|json|json-pretty}` (default: `text`).

### Step-by-Step Simulation Flow

1. Load snapshot.
2. Filter interface array based on `--type` and `--up-only`.
3. Sort interface records deterministically by interface name (`eth0`, `eth1`, `lo`).
4. Generate output stream.

---

### Command Arguments & Execution Examples

#### Command 1: Text output filtered by physical interfaces
```bash
pivotcheck --snapshot fixtures/snapshot_01.json interfaces --type physical
```

**Simulated Text Output:**
```text
Interface Name   State   MAC Address         IP Address / Prefix
----------------------------------------------------------------
eth0             UP      52:54:00:12:34:56   192.168.1.50/24
eth1             DOWN    52:54:00:78:9a:bc   10.0.0.5/24
```

#### Command 2: Empty result output (json)
```bash
pivotcheck --snapshot fixtures/snapshot_01.json interfaces --type virtual --format json
```

**Simulated JSON Output:**
```json
{
  "command": "interfaces",
  "filter": { "type": "virtual" },
  "count": 0,
  "results": []
}
```

---

## 4.3 `pivotcheck routes`

### Purpose
Display kernel routing table entries, highlighting gateways, default routes, and egress interfaces.

### Command options
- `--snapshot <FILE>` (required).
- `--destination <CIDR_OR_IP>` (optional): Filter routes matching destination IP/network.
- `--format {text|json|json-pretty}` (default: `text`).

### Step-by-Step Simulation Flow

1. Load snapshot.
2. Filter routing records by destination match if provided.
3. Sort deterministically by prefix length descending, then network address ascending.
4. Output formatted table or JSON array.

---

### Command Arguments & Execution Examples

#### Command 1: Query routes for specific target
```bash
pivotcheck --snapshot fixtures/snapshot_01.json routes --destination 10.0.0.0/24
```

**Simulated Text Output:**
```text
Destination         Gateway         Genmask         Flags   Metric   Iface
--------------------------------------------------------------------------
10.0.0.0/24         0.0.0.0         255.255.255.0   U       0        eth1
```

---

## 4.4 `pivotcheck sockets`

### Purpose
Inspect active network sockets (listening and established) linked to processes.

### Command options
- `--snapshot <FILE>` (required).
- `--state {all|listen|established}` (default: `all`).
- `--port <PORT>` (optional): Filter by local or remote port.
- `--format {text|json|json-pretty}` (default: `text`).

### Step-by-Step Simulation Flow

1. Load socket metrics from snapshot.
2. Apply state and port filters.
3. Group/Sort by Local Address, Local Port, Remote Address, Remote Port.
4. Render output.

---

### Command Arguments & Execution Examples

#### Command 1: Filter established connections in JSON
```bash
pivotcheck --snapshot fixtures/snapshot_01.json sockets --state established --format json-pretty
```

**Simulated JSON Output:**
```json
{
  "command": "sockets",
  "state_filter": "established",
  "count": 1,
  "results": [
    {
      "protocol": "tcp",
      "local_address": "192.168.1.50:44322",
      "remote_address": "10.0.0.10:22",
      "state": "ESTABLISHED",
      "pid": 2045,
      "process_name": "ssh"
    }
  ]
}
```

---

## 4.5 `pivotcheck pivots`

### Purpose
Identify potential pivot vector paths based on observed interfaces, routes, and active established sockets across dual-homed or multi-interface hosts.

### Command options
- `--snapshot <FILE>` (required).
- `--source-iface <IFACE>` (optional): Limit entry interface.
- `--format {text|json|json-pretty}` (default: `text`).

### Step-by-Step Simulation Flow

1. Load snapshot.
2. Cross-reference active interfaces with non-default routes and active external connections.
3. Rank potential pivot pathways by connection density and interface exposure.
4. Output candidate pivot paths deterministically sorted by source interface and target subnet.

---

### Command Arguments & Execution Examples

#### Command 1: Identify pivot paths
```bash
pivotcheck --snapshot fixtures/snapshot_01.json pivots
```

**Simulated Text Output:**
```text
Potential Pivot Pathways Detected:
==================================

1. Pathway [eth0 -> eth1]
   Entry Point  : eth0 (192.168.1.50/24)
   Target Subnet: 10.0.0.0/24 (via eth1)
   Evidence     : OBSERVED route + INFERRED dual-homed bridge
   Confidence   : HIGH
   Validation   : NOT_ACTIVELY_VALIDATED
```

---

## 4.6 `pivotcheck proxy-check`

> Added by the PROXY-CHECK-1 milestone. Simulations below are deterministic
> protocol-level outcomes verified against a controlled loopback SOCKS5
> server. They do **not** prove behavior against real Internet proxies or
> real destinations.

### Purpose

Demonstrate every important proxy-check outcome class, the stage sequence
that produces it, the rendered output, the verdict, and the exit code.

### Command options

```bash
pivotcheck proxy-check --proxy socks5://[user:pass@]host:port <target> --port N [--timeout S] [--json]
```

### Step-by-Step Simulation Flow

1. Parse and validate `--proxy` (scheme socks5 only, optional userinfo).
2. Validate `target` syntax (never resolve it locally).
3. Validate `--port` (exactly one explicit port) and `--timeout` (0.1–30 s).
4. Execute one three-stage SOCKS5 transaction (proxy TCP → negotiation →
   CONNECT), bounded by the timeout at every socket operation.
5. Render the staged report; exit 0 unless a usage error (2), proxy-endpoint
   resolution failure (3), or local fatal error (1) occurs.

### Scenario simulations

Each scenario shows: command → stage sequence → verdict → exit code →
security/epistemic interpretation. Text output follows the layout specified
in `PROJECT_OUTPUT.md` §10A; JSON follows the stable schema in the same
section (ANSI-free; passwords structurally excluded).

**Scenario 1 — proxy TCP failure (REFUSED)**

```bash
pivotcheck proxy-check --proxy socks5://127.0.0.1:1080 t.example --port 443
```

Stages: `proxy_tcp=REFUSED` (negotiation and CONNECT not reached) →
`NOT_VALIDATED`, exit `0`.
Interpretation: the local vantage could not reach the proxy. Nothing is
inferred about the destination or the proxy's policy.

**Scenario 2 — SOCKS5 negotiation failure (protocol error)**

A server that answers with a non-SOCKS version byte yields
`socks5_negotiation=PROXY_PROTOCOL_ERROR` → `NOT_VALIDATED`, exit `0`.
Interpretation: the endpoint is not speaking SOCKS5. Data, not a CLI failure.

**Scenario 3 — authentication failure (RFC 1929)**

```bash
pivotcheck proxy-check --proxy socks5://bob:hunter2@proxy.internal:1080 target.internal --port 443 --json
```

Stages: `proxy_tcp=SUCCESS`, `socks5_negotiation=AUTH_FAILED` →
`NOT_VALIDATED`, exit `0`.
Security: the password never appears in stdout, stderr, or JSON — the proxy
renders as `socks5://bob:***@proxy.internal:1080` and
`"has_credentials": true`.

**Scenario 4 — destination refused (CONNECT reply 0x05)**

Stages: `proxy_tcp=SUCCESS`, `socks5_negotiation=SUCCESS`,
`destination_connect=CONNECTION_REFUSED (reply_code 5)` → `NOT_VALIDATED`,
exit `0`.
Interpretation: the PROXY reported that the destination refused the
connection from the proxy's network vantage, at test time.

**Scenario 5 — destination unreachable (reply 0x03 / 0x04)**

Same shape as Scenario 4 with `NETWORK_UNREACHABLE` / `HOST_UNREACHABLE`
and the corresponding reply code. Exit `0`.

**Scenario 6 — ruleset denial (reply 0x02)**

`destination_connect=NOT_ALLOWED_BY_RULESET (reply_code 2)` →
`NOT_VALIDATED`, exit `0`.
Interpretation: the proxy's policy refused this CONNECT. This is evidence
about one request, not about other destinations, ports, or future attempts.

**Scenario 7 — successful CONNECT**

```bash
pivotcheck proxy-check --proxy socks5://user:pass@proxy.internal:1080 target.internal --port 443 --json
```

Stages: `proxy_tcp=SUCCESS`, `socks5_negotiation=SUCCESS`,
`destination_connect=SUCCESS (reply_code 0)` → `VALIDATED`, exit `0`.
Epistemic boundary: this proves exactly that the supplied proxy accepted a
CONNECT for the supplied destination at the time of testing. It does NOT
prove general reachability, pivot capability, arbitrary forwarding, access
to other ports, or persistent availability.

### Exit-code simulation matrix

| Scenario | Exit | Why |
|---|---:|---|
| 1–7 (any staged outcome) | 0 | Validation data, not CLI failure |
| Proxy endpoint DNS failure | 3 | Mirrors `check` resolution contract |
| Bad scheme / bad target / CIDR / port list or range / timeout out of bounds | 2 | Usage error |
| Program defect (impossible model state) | 1 | Fatal local error |

---

# 5. Error & Degraded Simulation Scenarios
## 5.1 Invalid Snapshot Path
```bash
pivotcheck --snapshot non_existent.json status
```

**Simulated Error Output (stderr, exit status 1):**
```text
Error [ERR_FILE_NOT_FOUND]: Snapshot file 'non_existent.json' could not be found or opened.
```

## 5.2 Degraded Evidence Output
```bash
pivotcheck --snapshot fixtures/corrupted_collector_snapshot.json status
```

**Simulated Warning Output:**
```text
PivotCheck Status Summary
=========================
Host Name       : unknown-host
OS / Kernel     : Linux 5.15.0
Collected At    : 2026-03-29T10:15:00Z
Completeness    : 60% (DEGRADED: Process & Socket collection failed)

WARNING: Socket data is NOT_COLLECTED. Pivot pathways will rely solely on routing tables.
```

---

# 6. Summary Matrix of Simulation Fixtures

| Command | Argument Combo | Result Type | Primary Expected Indicator |
|---|---|---|---|
| `status` | Standard `--snapshot` | Text | Total counts & completeness |
| `status` | `--baseline` + `--format json-pretty` | JSON | `baseline_delta` object present |
| `interfaces` | `--type physical` | Text | Only physical interfaces listed |
| `interfaces` | Non-matching filter | JSON | `"count": 0, "results": []` |
| `routes` | `--destination` filter | Text | Matches target CIDR |
| `sockets` | `--state established` | JSON | Connection arrays with PID mapping |
| `pivots` | Standard `--snapshot` | Text | Ranked pivot pathways with evidence tag |
