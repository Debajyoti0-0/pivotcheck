# Operator intelligence controls

## Feature matrix (ownership)

| Capability | Existing data | Pure layer | CLI |
|---|---|---|---|
| interface/family/focus/changes/confidence filters | yes | `analysis/query.py` | wiring |
| summary | yes | `analysis/summary.py` | wiring |
| evidence/explain | yes | `analysis/explanation.py` | wiring |
| recommendations | yes | `analysis/recommendation.py` | wiring |
| inferred pivots | yes | map view query (`filter_map_view`) | wiring |
| output artifact | JSON result | `output/artifact.py` | wiring |

`--warnings` is deferred: discovery warnings already appear in discovery data
and do not describe a comparison result. Active scanning, SSH, credentials,
and transport controls remain out of scope.

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