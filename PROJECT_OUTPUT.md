# PivotCheck — Project Output Design

**Status:** Output and CLI Contract Specification  
**Project:** PivotCheck  
**Purpose:** Define what every command returns, how text and JSON output are structured, how arguments affect output, and how operators should interpret results.

---

# 1. Output Design Philosophy

PivotCheck output must be:

- evidence-first,
- deterministic,
- operationally concise,
- machine-readable when requested,
- explicit about limitations,
- consistent across commands.

The central rule is:

```text
OBSERVED FACT
      ≠
INFERRED CONTEXT
      ≠
PRIORITY
      ≠
ACTIVE VALIDATION
```

Output must never visually or semantically collapse these four categories.

## 1.1 Output pipeline

```text
CLI arguments
      │
      ▼
Command handler
      │
      ▼
Discovery / storage / validation
      │
      ▼
Pure analysis result
      │
      ├───────────────┐
      ▼               ▼
Text renderer      JSON renderer
      │               │
      ▼               ▼
Human output     Machine output
```

Renderers receive completed results. They do not collect evidence or make new analytical decisions.

---

# 2. Global Output Contract

All commands should follow these broad conventions.

## Standard output

```text
stdout
└── requested command result
```

## Diagnostic output

```text
stderr
└── verbose diagnostics / warnings / failures
```

## Exit status

Target command conventions:

| Exit Code | Meaning |
|---:|---|
| `0` | Command completed successfully |
| `1` | Fatal operational error |
| `2` | CLI usage / argument error |
| `3` | Requested resource not found or resolution failure where defined |
| `4` | Schema / invalid stored data error |

A command may have more specific semantics, but those semantics must be documented and tested.

---

# 3. Global Arguments

## `--version`

### Purpose

Display the PivotCheck version.

### Example

```bash
pivotcheck --version
```

### Expected output

```text
pivotcheck X.Y.Z
```

---

## `--data-dir PATH`

### Purpose

Override the default local baseline storage directory.

### Example

```bash
pivotcheck --data-dir ./pivot-data baseline list
```

### Output impact

The command result is unchanged, but persistence is read from or written to the selected directory.

### Important rule

`--data-dir` changes storage location only. It must not alter discovery or analysis semantics.

---

## `-v`, `--verbose`

### Purpose

Enable diagnostic information.

### Example

```bash
pivotcheck -v discover
```

### Output design

Normal command results remain on stdout.

Diagnostics should appear on stderr.

```text
STDOUT
------
DISCOVERY SUMMARY
...

STDERR
------
[debug] collecting route information
[debug] normalizing neighbor table
...
```

Verbose mode must not contaminate JSON stdout.

---

## `--no-color`

### Purpose

Disable ANSI terminal styling.

### Example

```bash
pivotcheck --no-color map
```

### Output rule

The semantic content must be identical with or without color.

```text
Color changes presentation only.
```

JSON output must never contain ANSI escape sequences regardless of this option.

---

# 4. Common Format Arguments

## `--format {text,json}`

### Purpose

Select human-readable or machine-readable output.

### Default

```text
text
```

### Examples

```bash
pivotcheck discover --format text
pivotcheck discover --format json
```

---

## `--json`

### Purpose

Shorthand for JSON output.

### Example

```bash
pivotcheck compare workstation --json
```

Equivalent intent:

```bash
pivotcheck compare workstation --format json
```

---

# 5. `discover` Output Design

## Purpose

Show the current network perspective collected from the local system or remote SSH perspective.

## Command

```bash
pivotcheck discover [arguments]
```

## Expected arguments

| Argument | Purpose | Output impact |
|---|---|---|
| `--summary` | Condensed discovery output | Shows high-level counts/context |
| `--format {text,json}` | Select renderer | Text or JSON |
| `--json` | JSON shorthand | Machine-readable output |
| `--interface IFACE` | Presentation filter | Restricts displayed evidence |
| `--family {ipv4,ipv6,all}` | Address-family filter | Restricts displayed addresses/routes |
| `--ssh HOST` | Remote collection | Output represents remote perspective |
| `--ssh-user USER@HOST` | Remote identity | Output represents selected remote host |
| `--ssh-port PORT` | Remote SSH port | Collection transport configuration |
| `--ssh-key PATH` | SSH key path | Collection authentication configuration |
| `--ssh-timeout SECONDS` | SSH timeout | Collection timeout configuration |
| `--ssh-accept-new-hostkeys` | First-contact host-key acceptance | Remote trust behavior |

## Full text output structure

```text
DISCOVERY
════════════════════════════════════════════════════

PERSPECTIVE
  Source: local
  Timestamp: ...

INTERFACES
  eth0
    Address: ...
    State: ...

ROUTES
  10.50.0.0/16
    Gateway: ...
    Interface: ...
    Metric: ...

NEIGHBORS
  ...

CONNECTIONS
  ...

NETWORKS
  ...

INFERRED PIVOT CONTEXT
  ...

LIMITATIONS
  ...
```

The exact sections may vary according to available evidence, but section ordering must be deterministic.

## Summary output

```bash
pivotcheck discover --summary
```

Expected style:

```text
DISCOVERY SUMMARY

Interfaces: N
Routes: N
Neighbors: N
Connections: N
Networks: N
Pivot contexts: N
```

Summary mode should not silently imply that omitted details were absent.

---

## JSON output

Recommended structure:

```json
{
  "schema_version": "1.x",
  "tool": "pivotcheck",
  "version": "X.Y.Z",
  "command": "discover",
  "timestamp": "...",
  "perspective": {},
  "interfaces": [],
  "routes": [],
  "neighbors": [],
  "connections": [],
  "networks": [],
  "pivot_paths": [],
  "warnings": [],
  "limitations": []
}
```

---

# 6. `map` Output Design

## Purpose

Provide a topology-oriented representation of discovery evidence.

## Command

```bash
pivotcheck map [arguments]
```

## Arguments

| Argument | Purpose |
|---|---|
| `--baseline NAME` | Load baseline context where supported |
| `--focus NETWORK` | Prioritize one network in presentation |
| `--changes-only` | Hide unchanged items |
| `--show-pivots` | Show only inferred pivot context |
| `--minimum-confidence {low,medium,high}` | Hide lower-confidence items |
| `--format {text,json}` | Output format |
| `--json` | JSON shorthand |
| `--interface IFACE` | Interface filter |
| `--family {ipv4,ipv6,all}` | Address-family filter |
| SSH arguments | Remote perspective collection |
| `--output PATH` | Output artifact where supported |

## Normal text output

```text
NETWORK MAP
════════════════════════════════════════════════════

INTERFACE: eth0
  │
  ├── CONNECTED NETWORK
  │     10.10.20.0/24
  │
  └── ROUTED NETWORK
        10.50.0.0/16
        via 10.10.20.254

PIVOT CONTEXT
  [INFERRED]
  Source interface: eth0
  Gateway: 10.10.20.254
  Destination: 10.50.0.0/16
  Confidence: ...
```

The map must clearly distinguish directly connected networks from routed or inferred context.

---

## `--focus NETWORK`

Example:

```bash
pivotcheck map --focus 10.50.0.0/16
```

Output should place the requested network first or visually prioritize it.

It must not discard evidence required to understand the focused network.

---

## `--show-pivots`

Example:

```bash
pivotcheck map --show-pivots
```

Expected:

```text
INFERRED PIVOT CONTEXT

10.50.0.0/16
  Source interface: eth0
  Gateway: 10.10.20.254
  Confidence: MEDIUM
```

Required limitation:

```text
Pivot context is inferred from observed topology evidence.
It does not prove forwarding, reachability, or pivot capability.
```

---

# 7. `baseline` Output Design

## Command family

```bash
pivotcheck baseline create --name NAME
pivotcheck baseline list
pivotcheck baseline show NAME
pivotcheck baseline delete NAME --yes
```

---

## `baseline create`

### Arguments

| Argument | Purpose |
|---|---|
| `--name NAME` | Baseline identifier |
| `--force` | Replace existing baseline where supported |
| SSH arguments | Create baseline from remote perspective |

### Output

```text
BASELINE CREATED

Name: workstation
Timestamp: ...
Storage: ...
```

---

## `baseline list`

### Output

```text
BASELINES

NAME             CREATED                  VERSION
workstation      ...                      ...
vpn              ...                      ...
internal-server  ...                      ...
```

JSON:

```json
{
  "schema_version": "1.x",
  "command": "baseline list",
  "baselines": []
}
```

---

## `baseline show NAME`

### Output

```text
BASELINE: workstation

Metadata
  Created: ...
  Schema: ...

Snapshot summary
  Interfaces: ...
  Routes: ...
  Networks: ...
```

---

## `baseline delete NAME --yes`

The `--yes` argument explicitly acknowledges deletion.

Expected output:

```text
BASELINE DELETED

Name: workstation
```

Without confirmation, the command should not silently delete persisted evidence.

---

# 8. `compare` Output Design

## Purpose

Compare current discovery perspective with a saved baseline.

## Command

```bash
pivotcheck compare BASELINE [arguments]
```

## Arguments

| Argument | Purpose |
|---|---|
| `BASELINE` | Required baseline name |
| `--summary` | Condensed comparison |
| `--evidence` | Evidence-oriented view |
| `--recommend` | Operator priority recommendations |
| `--explain NETWORK` | Explain one network |
| `--format {text,json}` | Output format |
| `--json` | JSON shorthand |
| `--output PATH` | Write JSON artifact |
| `--force` | Allow output replacement |
| `--changes-only` | Hide unchanged items |
| `--minimum-confidence LEVEL` | Confidence filter |
| `--focus NETWORK` | Focus network context |
| `--interface IFACE` | Interface filter |
| `--family FAMILY` | Address-family filter |

## View conflict rule

Presentation modes such as:

```text
--summary
--evidence
--recommend
--explain NETWORK
```

should remain mutually exclusive where the CLI contract defines them as separate views.

---

## Default text output

```text
COMPARISON
════════════════════════════════════════════════════

Baseline: workstation
Current perspective: ...

NEW
  10.50.0.0/16

EXPANDED
  ...

UNCHANGED
  ...

REDUCED
  ...
```

---

## `--summary`

```text
COMPARISON SUMMARY

New coverage: N
Expanded coverage: N
Reduced coverage: N
Context changed: N
Unchanged: N
```

---

## `--evidence`

Output should preserve why each finding exists.

```text
10.50.0.0/16
  Classification: NEW
  Evidence:
    Route observed: yes
    Interface: eth0
    Gateway: 10.10.20.254
```

---

## `--recommend`

```text
RECOMMENDED INVESTIGATION PRIORITIES

HIGH
  10.50.0.0/16
    Reason: ...

MEDIUM
  ...

LOW
  ...
```

Priority must be visually separated from validation evidence.

---

## `--explain NETWORK`

```bash
pivotcheck compare workstation --explain 10.50.0.0/16
```

Expected:

```text
NETWORK EXPLANATION

Network: 10.50.0.0/16
Relationship: NEW

Observed evidence:
  ...

Inferred context:
  ...

Recommendation:
  ...

Limitations:
  ...
```

---

## JSON artifact output

Example:

```bash
pivotcheck compare workstation --format json --output result.json
```

Target behavior:

```text
1. Generate comparison result.
2. Serialize deterministically.
3. Refuse accidental overwrite unless --force is provided.
4. Write atomically.
```

---

# 9. `check` Output Design

## Purpose

Perform explicit TCP validation against one operator-selected target and port.

## Command

```bash
pivotcheck check TARGET --port PORT [arguments]
```

## Arguments

| Argument | Purpose |
|---|---|
| `TARGET` | Explicit hostname or IP |
| `--port PORT` | Required TCP port |
| `--timeout SECONDS` | Connection timeout |
| `--baseline NAME` | Optional comparison context |
| `--format {text,json}` | Output format |
| `--json` | JSON shorthand |

## Validation result states

```text
SUCCESS
REFUSED
TIMEOUT
NO_ROUTE
UNREACHABLE
DNS_ERROR
INVALID_TARGET
LOCAL_ERROR
```

## Text output

```text
TCP CHECK

Target: 10.50.1.10
Port: 445
Result: SUCCESS

Validation context:
  Explicit TCP connection completed.

Baseline context:
  Network relationship: NEW

Important:
  This result applies to the explicit target and port checked.
  It does not establish reachability for the entire network.
```

---

## JSON output

Stable schema produced by `CheckReport.to_dict()` (one `results` entry per
resolved address × port; `validation_context` appears only when a
`--baseline` was requested and resolved):

```json
{
  "tool": "pivotcheck",
  "version": "0.1.0",
  "target": "10.50.1.10",
  "resolved_addresses": ["10.50.1.10"],
  "ports": [445],
  "timeout_s": 3.0,
  "results": [
    {
      "target": "10.50.1.10",
      "address": "10.50.1.10",
      "port": 445,
      "protocol": "tcp",
      "status": "SUCCESS",
      "elapsed_ms": 12.3,
      "error": null,
      "route_context": {
        "type": "UNKNOWN",
        "network": null,
        "gateway": null,
        "interface": null,
        "confidence": null
      }
    }
  ]
}
```

Limitations are carried in the text output; the per-result `status` values
are exactly the validation result states listed above.

---

# 10. `next` Output Design

## Purpose

Select one evidence-backed network context that deserves operator attention first.

## Command

```bash
pivotcheck next [arguments]
```

## Arguments

| Argument | Purpose |
|---|---|
| `--baseline NAME` | Add comparison context |
| `--format {text,json}` | Select output format |
| `--json` | JSON shorthand |

Global options also apply:

```text
--data-dir
-v / --verbose
--no-color
```

---

## Candidate output

```text
NEXT INVESTIGATION CANDIDATE
════════════════════════════════════════════════════

Network: 10.50.0.0/16
Priority: HIGH

Reason:
  New high-priority comparison context with supporting transit evidence.

OBSERVED EVIDENCE
  [x] Route
      Destination: 10.50.0.0/16
      Gateway: 10.10.20.254
      Interface: eth0

  [x] Neighbor
      State: REACHABLE

  [x] Connection evidence
      ...

  [ ] Active validation
      NOT PERFORMED

INFERRED TRANSIT ASSESSMENT
  MULTIPLE_SUPPORTING_SIGNALS

COMPARISON CONTEXT
  Baseline: workstation
  Relationship: NEW

SUGGESTED OPERATOR ACTION
  Choose an explicit target and port.
  Run:
    pivotcheck check <target> --port <port>

LIMITATION
  Route and topology evidence do not prove active reachability.
  This is prioritization context, not validation evidence.
```

---

## No candidate output

```text
NO INVESTIGATION CANDIDATES

No actionable prioritization context was derived from the available evidence.
```

This is a successful result and should normally return exit code `0`.

---

## `next` JSON output

Stable schema produced by `NextStepReport.to_dict()`:

```json
{
  "tool": "pivotcheck",
  "version": "0.1.0",
  "timestamp": "2026-08-29T08:08:26.553003+00:00",
  "candidate": {
    "network": "10.50.0.0/16",
    "priority": "HIGH",
    "reason": "Directly connected interface with corroborating transit evidence.",
    "observed_evidence": {
      "route": {"present": true, "metric": 100, "type": "default"},
      "neighbor": {"observed": true, "state": "REACHABLE", "mac": "aa:bb:cc:dd:ee:01"},
      "connections": {
        "tcp_count": 2,
        "tcp_states": ["ESTABLISHED"],
        "udp_count": 0,
        "has_listen": false,
        "has_loopback": false
      }
    },
    "transit_assessment": "MULTIPLE_SUPPORTING_SIGNALS",
    "comparison_context": {
      "baseline": "pre-pivot",
      "relationship": "SAME",
      "classification": null,
      "related_network": null
    }
  },
  "suggested_action": {
    "command_template": "Choose an explicit target and port. Run: pivotcheck check <target> --port <port>"
  },
  "limitations": [
    "Route and topology evidence do not prove active reachability. This is prioritization context, not validation evidence."
  ]
}
```

`comparison_context` is present only when `--baseline NAME` was supplied.
If no candidate exists:

```json
{
  "tool": "pivotcheck",
  "version": "0.1.0",
  "timestamp": "2026-08-29T08:08:26.553003+00:00",
  "candidate": null,
  "message": "NO INVESTIGATION CANDIDATES"
}
```

---

# 10A. `proxy-check` Output Design

> Added by the PROXY-CHECK-1 milestone. Follows the global contract (§2) and
> the validation epistemic rules (§11, §12, §14).

## Purpose

Report the staged outcome of one operator-controlled SOCKS5 CONNECT attempt
through an explicitly supplied proxy to one explicit destination, and state
precisely what the evidence does and does not prove.

## Command

```bash
pivotcheck proxy-check --proxy socks5://[user:pass@]host:port <target> --port N [--timeout S] [--format {text,json} | --json] [--no-color]
```

## Arguments

| Argument | Contract |
|---|---|
| `--proxy` | Required. `socks5://host:port` or `socks5://user:pass@host:port` only. Wrong scheme, missing port, username without password, CIDR host, or out-of-range port → usage error (exit 2). |
| `target` | Required. One explicit IP literal or hostname. CIDR notation is rejected (exit 2). Never resolved locally. |
| `--port` | Required. Exactly ONE explicit TCP port. Lists (`80,443`) and ranges (`100-200`) are deliberately rejected (exit 2). |
| `--timeout` | Optional. 0.1–30 seconds, default 3. Bounds every socket operation. |

## Staged result states

Three stages, in fixed execution order: `proxy_tcp`, `socks5_negotiation`,
`destination_connect`. Per-stage statuses follow PROJECT_ARCHITECTURE.md
§14.1; the model rejects impossible stage/status combinations. The verdict is
`VALIDATED` only when every stage succeeded.

## Text output

```text
════════════════════════════════════════════════════════════
             PIVOTCHECK — PROXY CHECK
════════════════════════════════════════════════════════════

Proxy:
  socks5://127.0.0.1:1080

Target:
  t.example:443

Stage 1 — Proxy TCP:
  REFUSED
  Elapsed: 2029.0 ms
  ConnectionRefusedError: [WinError 10061] No connection could be made because the target machine actively refused it

Verdict:
  NOT_VALIDATED

Limitation:
  This result validates only the explicitly requested SOCKS5
  CONNECT attempt from the supplied proxy to the supplied
  destination at the time of testing. It does not prove general
  network reachability, pivot capability, or arbitrary
  forwarding.
```

Credentials never appear: a proxy `socks5://user:pass@host` renders as
`socks5://user:***@host`.

## JSON output

Stable, ordered, ANSI-free schema (from `ProxyCheckReport.to_dict()`):

```json
{
  "tool": "pivotcheck",
  "version": "0.1.0",
  "command": "proxy-check",
  "proxy": {"scheme": "socks5", "host": "127.0.0.1", "port": 1080, "has_credentials": false},
  "target": {"host": "example.internal", "port": 443},
  "timeout_s": 3.0,
  "stages": [
    {"stage": "proxy_tcp", "status": "SUCCESS", "detail": null, "elapsed_ms": 12.5, "reply_code": null},
    {"stage": "socks5_negotiation", "status": "SUCCESS", "detail": null, "elapsed_ms": null, "reply_code": null},
    {"stage": "destination_connect", "status": "CONNECTION_REFUSED", "detail": "SOCKS5 reply code 0x05", "elapsed_ms": null, "reply_code": 5}
  ],
  "verdict": "NOT_VALIDATED",
  "limitation": "This result validates only the explicitly requested SOCKS5 CONNECT attempt from the supplied proxy to the supplied destination at the time of testing. It does not prove general network reachability, pivot capability, or arbitrary forwarding."
}
```

`reply_code` is populated only on the `destination_connect` stage. Passwords
are structurally excluded from serialization.

## Exit codes

| Code | Meaning |
|---:|---|
| `0` | Validation executed. Every staged outcome — VALIDATED, REFUSED, TIMEOUT, AUTH_FAILED, ruleset denial, CONNECT reply codes — is DATA, not a CLI failure. |
| `1` | Fatal internal/local execution failure (program defect, not network data). |
| `2` | Invalid CLI usage (proxy URL, target, port, timeout). |
| `3` | The **proxy** endpoint name could not be resolved (DNS_ERROR), mirroring `check`. The destination is never resolved locally, so it cannot produce this code. |

## Baseline semantics (deliberate decision)

`--baseline` is **not** offered. Passive topology evidence cannot be
meaningfully compared to an active SOCKS5 transaction result; manufacturing a
relationship would violate the evidence model. Nothing is compared; nothing
is claimed.

## Forbidden claims

VALIDATED never means: the network is reachable, the proxy provides pivot
capability, all ports are reachable, the destination is permanently
accessible, or the proxy can relay arbitrary traffic.

---

# 11. Output Semantic Labels

The renderer should use consistent labels.

## Observed

```text
OBSERVED EVIDENCE
```

Means the collector directly produced the evidence.

## Inferred

```text
INFERRED CONTEXT
```

Means deterministic analysis derived the result from observed facts.

## Priority

```text
PRIORITY
```

Means operator decision support.

## Validation

```text
ACTIVE VALIDATION
```

Means an explicit check occurred.

---

# 12. Forbidden Output Language

The following claims must not be emitted merely because topology or transit evidence exists:

| Avoid | Use instead |
|---|---|
| reachable | route evidence observed |
| viable pivot | inferred pivot context |
| accessible | route context exists |
| pivotable | transit candidate with supporting evidence |
| confirmed | actively validated |
| working | evidence observed |

A successful `check` may report the explicit validation result, but its scope must remain limited to that target and port.

---

# 13. Deterministic Output Rules

Every renderer should guarantee:

```text
same input
    ↓
same normalized result
    ↓
same ordering
    ↓
same semantic output
```

Recommended ordering:

1. Priority.
2. Confidence.
3. Canonical network ordering.
4. Stable lexical tie-break where required.

JSON should not depend on dictionary insertion accidents or collection timing.

---

# 14. Warning and Limitation Design

Warnings answer:

> What happened during execution that may affect collection completeness?

Example:

```text
WARNING
Neighbor collection unavailable.
```

Limitations answer:

> What does the evidence fundamentally not prove?

Example:

```text
LIMITATION
Route evidence does not prove active reachability.
```

These concepts must remain separate.

---

# 15. JSON Schema Evolution Guidance

Every mature machine-readable command should expose a schema version.

Recommended top-level contract:

```json
{
  "schema_version": "1.x",
  "tool": "pivotcheck",
  "version": "X.Y.Z",
  "command": "...",
  "timestamp": "...",
  "data": {},
  "warnings": [],
  "limitations": []
}
```

Future schema changes should follow:

```text
Compatible additive change
    → minor schema evolution

Breaking structural change
    → major schema version
```

Do not silently break automation consumers.

---

# 16. Output Testing Checklist

For every command and view:

```text
[ ] Text output tested
[ ] JSON output tested
[ ] ANSI-free JSON tested
[ ] --no-color tested
[ ] Deterministic ordering tested
[ ] Empty-result behavior tested
[ ] Warning behavior tested
[ ] Limitation text tested
[ ] Exit code tested
[ ] Invalid arguments tested
[ ] Baseline error path tested where applicable
```

For `next` additionally:

```text
[ ] HIGH priority candidate
[ ] MEDIUM priority candidate
[ ] LOW priority candidate
[ ] Deterministic tie-break
[ ] No candidate
[ ] Baseline context
[ ] No baseline context
[ ] Evidence rendering
[ ] Limitation rendering
```

---

# 17. Operator Workflow Output Design

The intended output journey is:

```text
pivotcheck discover
        │
        ▼
"What is visible?"

pivotcheck map
        │
        ▼
"How is this perspective connected?"

pivotcheck baseline create
        │
        ▼
"Save this perspective"

pivotcheck compare BASELINE
        │
        ▼
"What changed?"

pivotcheck compare BASELINE --recommend
        │
        ▼
"What deserves attention?"

pivotcheck next --baseline BASELINE
        │
        ▼
"Which context should I investigate first?"

Operator selects explicit target + port
        │
        ▼
pivotcheck check TARGET --port PORT
        │
        ▼
"What happened to this explicit validation attempt?"
```

The output design should make this progression obvious without claiming more than the evidence supports.

---

# 18. Final Output Design Rules

PivotCheck output is successful when:

```text
An operator can see:

WHAT WAS OBSERVED
        ↓
WHAT WAS INFERRED
        ↓
WHAT CHANGED
        ↓
WHAT WAS PRIORITIZED
        ↓
WHAT STILL NEEDS EXPLICIT VALIDATION
```

The final output contract is therefore:

```text
CLEAR
+
DETERMINISTIC
+
EVIDENCE-TRACEABLE
+
MACHINE-READABLE
+
SEMANTICALLY HONEST
```

No command should sacrifice evidence accuracy for more dramatic wording.
