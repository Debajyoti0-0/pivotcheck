# PivotCheck

**Passive network discovery and pivot path validation for authorized security assessments.**

PivotCheck answers the question a foothold does *not*: **"what can I actually
reach from here?"** It normalizes heterogeneous host network state (`ip`,
`route`, `arp`/`neigh`, `ss`, `resolv.conf`) into one coherent model and
classifies each reachable network with an explicit **confidence** level —
instead of leaving you to stitch that picture together by hand.

> ⚠️ **Authorized use only.** PivotCheck is built for defensive review and
> sanctioned penetration testing. It is deliberately **not** a scanner: it
> performs passive local/remote discovery plus narrow, single-target
> reachability checks. Only run it against systems and networks you are
> explicitly authorized to assess.

Status: **v0.1.0 — Alpha.** Primary target platform is **Linux** (discovery
relies on Linux networking tools); baseline storage and TCP checks are
cross-platform.

---

## Highlights

- **Passive** discovery — reads existing system state; no host sweeps, no ICMP,
  no traceroute, no exploitation.
- **Confidence-classified** networks: `HIGH` (directly connected + interface
  up), `MEDIUM` (explicit route via gateway), `LOW` (inferred — never presented
  as fact).
- **Graceful degradation** — an unreadable table becomes a warning, never a
  crash.
- **Stable JSON** output on every command for scripting and pipelines.
- **Baselines & comparison** — save a perspective, then see exactly how a later
  perspective differs (new coverage, expanded/reduced reach, topology detail).
- **Remote vantage points** over SSH, using your existing agent/keys.
- **Zero required runtime dependencies** (Python standard library only).

## Requirements

- Python **3.10+**
- Linux for full `discover`/`map` collection (other platforms run `check` and
  baseline management, but local discovery is Linux-oriented)

## Install

```bash
pip install .
```

For development (tests, linting, type-checking):

```bash
pip install -e ".[dev]"
```

Optional SOCKS extra (unused by the current implementation; `proxy-check`
ships a stdlib-only SOCKS5 client — kept for future protocol work):

```bash
pip install ".[socks]"
```

This installs a `pivotcheck` console script. You can equivalently run
`python -m pivotcheck` or `python __main__.py` from the project root.

## Quick start

```bash
pivotcheck discover              # full detailed discovery
pivotcheck discover --summary    # concise operational summary
pivotcheck map                   # topology-focused view of the same data
pivotcheck discover --json > snapshot.json
```

## Commands

### `discover` — passive discovery
Enumerate interfaces, routes, neighbors, DNS, and sockets, then classify
reachable networks and potential pivot paths.

```bash
pivotcheck discover [--summary] [--interface IFACE] [--family ipv4|ipv6|all]
                    [--format text|json | --json]
```

### `map` — topology view
The same discovery data, presented as interface/network relationships with
confidence levels.

```bash
pivotcheck map [--focus NETWORK] [--changes-only] [--show-pivots]
               [--interface IFACE] [--family ...] [--baseline NAME] [--json]
```

`--show-pivots` shows **only** inferred pivot context (routing evidence — never
confirmed reachability).

### `check` — single-target TCP validation
Attempt a controlled TCP connection to one operator-selected host and classify
the result precisely. **This is not a scanner:** ports must be listed
explicitly, ranges are rejected, and at most 16 ports are accepted.

```bash
pivotcheck check 10.10.20.25 --port 445
pivotcheck check host.internal --port 445,3389 --timeout 3 --json
pivotcheck check 10.10.20.25 --port 445 --baseline pre-pivot   # add comparison context
```

Result statuses: `SUCCESS`, `REFUSED`, `TIMEOUT`, `NO_ROUTE`, `UNREACHABLE`,
`DNS_ERROR`, `INVALID_TARGET`, `LOCAL_ERROR`. (`--timeout` accepts 0.1–30s,
default 3.) A `TIMEOUT` is explicitly **ambiguous** and never treated as proof a
host is offline.

### `proxy-check` — SOCKS5 proxy-path validation

One operator-supplied proxy, one operator-supplied destination, one port,
one attempt. Hostnames are resolved by the **proxy** (ATYP 0x03), never
locally. Credentials are redacted in all output (`user:***@`).

```bash
pivotcheck proxy-check --proxy socks5://127.0.0.1:1080 10.10.20.25 --port 445
pivotcheck proxy-check --proxy socks5://user:pass@proxy.internal:1080 target.internal --port 443 --json
```

A staged result reports exactly which stage failed (proxy TCP → SOCKS5
negotiation → destination CONNECT) and a `VALIDATED` / `NOT_VALIDATED`
verdict. Validation success means only that the proxy accepted the CONNECT
request at test time — not general reachability or pivot capability.

### `baseline` — save and manage perspectives

```bash
pivotcheck baseline create --name pre-pivot   # discover + save
pivotcheck baseline list
pivotcheck baseline show pre-pivot
pivotcheck baseline delete pre-pivot --yes
```

Names are 1–63 lowercase letters, digits, or hyphens.

### `compare` — diff current perspective against a baseline

```bash
pivotcheck compare pre-pivot                       # full change detail
pivotcheck compare pre-pivot --summary             # concise change summary
pivotcheck compare pre-pivot --evidence            # evidence behind each change
pivotcheck compare pre-pivot --recommend           # rule-based next steps
pivotcheck compare pre-pivot --explain 10.10.20.0/24
pivotcheck compare pre-pivot --json --output result.json --force
```

The view flags are mutually exclusive; filters (`--interface`, `--family`,
`--changes-only`, `--minimum-confidence`) compose with any view. `--output`
requires JSON format.

## Remote collection (SSH)

`discover`, `map`, and `baseline create` accept a remote vantage point.
Authentication uses your existing SSH agent/keys/config; host keys are verified
**strictly** by default.

```bash
pivotcheck discover --ssh jump-host
pivotcheck discover --ssh-user operator@10.0.0.5 --ssh-port 2222
pivotcheck baseline create --name from-jump --ssh jump-host --ssh-accept-new-hostkeys
```

`--ssh-accept-new-hostkeys` trusts a first-contact key; changed keys are still
rejected. `--ssh-timeout` accepts up to 60s (default 10).

## Output & automation

Every command supports `--json` (alias for `--format json`); JSON output carries
no ANSI codes and follows a stable schema. Color is auto-enabled on a TTY and can
be disabled with `--no-color`. Use `-v`/`--verbose` for collector diagnostics on
stderr.

### Exit codes

**`discover` / `map`**
| Code | Meaning |
|------|---------|
| 0 | Discovery completed (partial collector degradation is reported, not failed) |
| 1 | Fatal execution failure (discovery engine could not run) |
| 2 | Invalid CLI usage |

**`check`**
| Code | Meaning |
|------|---------|
| 0 | Check executed normally (SUCCESS / REFUSED / TIMEOUT are data, not failures) |
| 1 | Fatal internal/local failure |
| 2 | Invalid CLI usage |
| 3 | Target could not be resolved, or requested `--baseline` not found |
| 4 | Requested `--baseline` is invalid/unsupported |

**`proxy-check`**
| Code | Meaning |
|------|---------|
| 0 | Validation executed (VALIDATED / REFUSED / TIMEOUT / AUTH_FAILED / CONNECT reply codes are data, not failures) |
| 1 | Fatal internal/local failure |
| 2 | Invalid CLI usage (proxy URL, target, port, timeout) |
| 3 | The **proxy** endpoint name could not be resolved (DNS_ERROR); the destination is never resolved locally |

## Baseline data location

Baselines are stored as versioned JSON. The directory is resolved as:

1. `--data-dir PATH` (highest precedence)
2. `PIVOTCHECK_DATA_DIR` environment variable
3. Platform default — `%LOCALAPPDATA%\pivotcheck` on Windows, or
   `$XDG_DATA_HOME/pivotcheck` (falling back to `~/.local/share/pivotcheck`)
   elsewhere.

## Development

```bash
pip install -e ".[dev]"
pytest            # unit tests (integration-marked tests are deselected by default)
ruff check .
mypy pivotcheck
```

Tests use OS-command fixtures (see `tests/fixtures/`) so parsers are exercised
without touching live network state. If your default system temp directory is
unwritable (e.g. a OneDrive-synced Windows profile with a locked
`pytest-of-<user>` folder), `conftest.py` transparently redirects pytest's
temporary files to a project-local `.pytest_tmp/`; healthy environments are
unaffected.

## Documentation

Design and behavior notes live in [`docs/`](docs/):

- [`MVP.md`](docs/MVP.md) — original v0.1.0 plan + shipped-scope reconciliation
- [`baseline-workflow.md`](docs/baseline-workflow.md)
- [`comparison-semantics.md`](docs/comparison-semantics.md)
- [`operator-intelligence.md`](docs/operator-intelligence.md)
- [`perspective-map.md`](docs/perspective-map.md)
- [`session-providers.md`](docs/session-providers.md)

## License

MIT — see [`pyproject.toml`](pyproject.toml). Copyright (c) 2026 PivotCheck
contributors.
