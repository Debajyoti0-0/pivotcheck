# Operator intelligence controls

## Feature matrix (ownership)

| Capability | Existing data | Pure layer | CLI |
|---|---|---|---|
| interface/family/focus/changes/confidence filters | yes | `analysis/query.py` | wiring |
| summary | yes | `analysis/summary.py` | wiring |
| evidence/explain | yes | `analysis/explanation.py` | wiring |
| recommendations | yes | `analysis/recommendation.py` | wiring |
| inferred pivots | yes | map view query (`filter_map_view`) | wiring |
| credential/host correlation | yes (Step 1 credentials + caller-supplied host evidence) | `analysis/correlation.py` | internal model (no CLI yet) |
| output artifact | JSON result | `output/artifact.py` | wiring |

`--warnings` is deferred: discovery warnings already appear in discovery data
and do not describe a comparison result. Active scanning, SSH, credentials,
and transport controls remain out of scope.

## Credential/host correlation (v2.0 Step 3)

`analysis/correlation.py` correlates Step 1 credential *references* with
caller-supplied host evidence and ranks explicit-validation candidates.
It is pure analysis: no network, subprocess, filesystem, or environment
access; identical evidence in any input order produces an identical
report.

What it consumes: `CredentialRef` (type/provenance/state only — credential
material never enters the layer) and `HostEvidence` records using kinds
such as `KNOWN_HOST`, `SSH_SERVICE_OBSERVED`, `SSH_SERVICE_NOT_OBSERVED`
(explicit negative), `NETWORK_OBSERVED`, `NEIGHBOR_OBSERVED`,
`AUTH_VALIDATED`, `AUTH_FAILED`.

What a candidate means: `HIGH`/`MEDIUM`/`LOW` is INVESTIGATION priority
for explicit validation next — it is never a claim that the credential
works, that the host is reachable, or that a service is listening.
`KNOWN_HOST` is historical SSH client identity evidence only.
`AUTH_VALIDATED`/`AUTH_FAILED` can only be consumed from real prior
validation results (Step 2's checker); correlation never manufactures
them. Pairs with a prior `AUTH_FAILED` (and no success) are suppressed
from recommendations, and every candidate carries a reason chain stating
what is known and what is not.

No CLI surface yet: correlation is an internal analysis capability until a
consumer phase requires one.

## CLI interaction matrix

Comparison views answer different operator questions and are therefore a
mutually exclusive argparse group:

| Arguments | Relationship |
|---|---|
| `--summary` + `--evidence` / `--recommend` / `--explain` | INCOMPATIBLE (argparse-enforced) |
| `--evidence` + `--recommend` / `--explain` | INCOMPATIBLE (argparse-enforced) |
| `--interface` / `--family` / `--focus` / `--changes-only` / `--minimum-confidence` + any view | COMPATIBLE (filters compose) |
| `--format json` + any view | COMPATIBLE (view data becomes JSON sections) |
| `--output PATH` + `--format json` | COMPATIBLE (artifact is the same payload written to stdout) |
| `--output` without `--format json` | NOT SUPPORTED (artifact only defined for JSON compare output) |
| `--force` without `--output` | REDUNDANT (ignored) |
| `map --show-pivots` + other sections | PRECEDENCE: pivots-only view |

Filtering semantics:

- Filtering is presentation/query logic; it never changes discovery or CIDR
  comparison semantics.
- Entries without interface or confidence metadata are retained rather than
  incorrectly claimed absent.
- Focus includes every CIDR that overlaps or contains the supplied CIDR/IP;
  `resolve_focus_network` never chooses one arbitrary matching network —
  ambiguous input is a usage error listing the candidates.
- `--explain` accepts an exact CIDR or an IP inside exactly one known network.

Recommendations are deterministic: new high-confidence connected evidence is
HIGH; new or expanded routed evidence is MEDIUM; inferred pivot paths are LOW.
Every recommendation carries its reason, supporting evidence lines, a
suggested operator action, and the explicit limitation that route and
topology evidence do not prove active reachability.

## Output artifacts

`compare --format json --output PATH` writes the exact stdout payload to
PATH atomically (same-directory temp file + rename), UTF-8, refusing to
replace an existing file unless `--force` is given. Warnings/errors go to
stderr and are never mixed into the artifact. Result artifacts contain
sensitive reconnaissance data — store them accordingly; their lifecycle and
permissions are deliberately separate from baselines.