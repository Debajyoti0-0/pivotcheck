# Kali Tools submission notes

This document summarizes the packaging-relevant facts a Kali Tools
submission (or any distro packaging review) needs about PivotCheck.

## Purpose

PivotCheck helps an authorized operator reason about network position
during an assessment: it passively normalizes a host's network state,
classifies reachable networks by confidence, correlates transit evidence,
ranks what to investigate next, and explicitly validates one chosen
credential against one chosen service. It is decision support — it does
not scan, spray, exploit, tunnel, or execute commands remotely.

## Why it fits Kali

- Fills the gap between raw `ip`/`ss`/`arp` output and manual pivot
  reasoning: evidence-classified networks and multi-hop path candidates
  with per-hop limitations instead of undocumented guesswork.
- Validates credentials against SSH, SMB, and WinRM with strict
  one-target/one-attempt semantics (no spraying by design).
- Predictive OPSEC/observability analysis for validation actions.

## Package facts

| Field | Value |
|---|---|
| Name | `pivotcheck` |
| Version | 2.0.0 |
| License | GPL-3.0-only |
| Language | Python >= 3.10 |
| Entry point | `pivotcheck` (console script); `python -m pivotcheck` equivalent |
| Runtime dependencies | none (standard library only) |
| Optional extras | `socks` (PySocks), `smb` (smbprotocol), `winrm` (pywinrm) |
| Build system | setuptools (PEP 517, `pyproject.toml`) |
| Homepage | https://github.com/Debajyoti0-0/pivotcheck |
| Bug reports | https://github.com/Debajyoti0-0/pivotcheck/issues |

## Runtime behavior

- Passive commands (`discover`, `map`, `next`, `gaps`, `explain`,
  `baseline`, `compare`, `opsec`) perform zero network I/O; `discover`
  reads local system state only.
- Active commands (`check`, `proxy-check`) contact exactly the operator-
  specified target:port, one attempt.
- State (baselines) is written only to the user's data directory
  (`$XDG_DATA_HOME/pivotcheck` or `~/.local/share/pivotcheck` on Linux;
  overridable via `--data-dir` / `PIVOTCHECK_DATA_DIR`). No root required.
- Credential material is supplied only via environment variables
  (`--ssh-key-env`, `--credential-env`), never command-line arguments or
  files, and is never written to disk.
- Deterministic JSON on every command (`--json`); human output is
  ANSI-free by default in non-TTY contexts.

## Example usage

```bash
pivotcheck discover                  # passive perspective from this host
pivotcheck map --show-pivots         # topology with inferred pivot context
pivotcheck next                      # highest-priority investigation candidate
pivotcheck gaps 10.50.0.0/16         # evidence gaps for one network
pivotcheck check 10.10.20.25 --port 445            # one explicit TCP check
pivotcheck check 10.10.20.25 --port 22 --protocol ssh --ssh-key-env KEY_ENV
pivotcheck check 10.10.20.25 --port 445 --protocol smb --credential-env SMB_CRED
pivotcheck check 10.10.20.25 --port 5985 --protocol winrm --credential-env WINRM_CRED
pivotcheck opsec --action smb-auth --platform windows   # observability analysis
```

## Security model

- One target, one port, one protocol, one credential, one attempt per
  invocation. No scanning, no retries, no fallback chains, no CIDR
  expansion, no share enumeration, no remote execution.
- Authentication success never implies shell access, administrative
  access, or pivot capability; failures never imply host unavailability.
- Credential material is never serialized, logged, or written to disk.
- OPSEC intelligence is predictive analysis only — never evasion guidance.

## Upstream

Repository, issues, security policy, and changelog are linked from the
repository (see SECURITY.md for private vulnerability reporting).
