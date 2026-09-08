# Maintainer Guide

Operational documentation for maintaining PivotCheck. This guide
describes procedures, not people: it is written so that any competent
maintainer (current or future) can operate the project without tribal
knowledge. It deliberately does not name a team.

## Project shape

- Single Python package: `pivotcheck/` (pure standard library at runtime;
  optional extras: `socks`, `smb`, `winrm`; dev extra for tooling).
- Layered architecture, strict dependency direction:

  ```text
  Models → Discovery → Analysis → Checks → Output → CLI
  ```

  Nothing may depend upward. Analysis is pure and deterministic
  (zero network I/O). Discovery reads local OS state only. Checks are
  the sole active-I/O boundary (one target, one port, one attempt).
  Output renders; it never alters evidence semantics. CLI wires.

- Key module map:
  - `pivotcheck/models/` — frozen dataclasses + enums (evidence semantics live here)
  - `pivotcheck/discovery/` — platform collectors (`local.py` dispatches Windows/macOS/Linux), remote SSH transport
  - `pivotcheck/analysis/` — confidence (`topology.py`), gaps, explanation, comparison, recommendations
  - `pivotcheck/checks/` — validation providers (`tcp.py`, `http.py`, `ssh.py`, `smb.py`, `winrm.py`, `proxy.py`)
  - `pivotcheck/output/` — terminal + JSON renderers per command
  - `pivotcheck/cli.py` — argparse wiring + exit-code contract

## Development workflow

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup. The non-negotiable
gates before any merge:

```bash
python -m ruff check .                # lint
python -m mypy pivotcheck             # types (76+ files)
```

## Security invariants (immutable)

- Passive discovery and analysis: zero network I/O.
- Checks: one explicit target, one port, one attempt; no ranges, no CIDR
  expansion, no retries, no fallback chains, no guest fallback.
- TIMEOUT is ambiguous and never host-down proof.
- Authentication success is never execution capability.
- Absence of evidence is never negative evidence.
- No command execution, tunneling, credential dumping, persistence,
  telemetry, evasion capability, or secret serialization. Credentials
  enter only via environment variables and are redacted everywhere.

Any change that requires weakening an invariant must be rejected,
regardless of its other merits.

## Release procedure

1. Verify all gates green on a clean checkout.
2. Bump `__version__` in `pivotcheck/__init__.py` (single source; the
   package build reads it dynamically).
3. Update `CHANGELOG.md`: convert the `Unreleased` section to the new
   version with the release date.
4. Commit, tag `vX.Y.Z` on the release commit, push.
5. CI (`.github/workflows/ci.yml`) runs the full matrix; the release
   workflow (`.github/workflows/release.yml`) builds and publishes.
6. Verify the published artifact: fresh install, `--version`, smoke
   commands per the CI release job.
7. Never publish manually to bypass CI. Never bump the version without a
   changelog entry. `IMPLEMENTED ≠ RELEASE-AUTHORIZED`.

## Governance conventions

- Feature work is evidence-gated: real external signals are admitted
  through a documented gap/evidence register (see the STAGE reports in
  the repository for the decision history and the wait-state contract).
- Stage reports (`STAGE*_*.md`) are decision records: they capture
  baseline state, evidence, and authorization at each point. Keep them
  factual; derive repository-state claims from direct Git command output
  only.
- Community channels: GitHub Issues status must be verified against the
  actual public interface before being described anywhere; if issue
  creation is restricted, the channel is blocked and must be described
  as blocked.
- Security reports follow [SECURITY.md](SECURITY.md) (private channel,
  never public issues).

## Maintainer bus-factor notes

- All procedures above are deliberately written down so that
  maintenance can transfer. Do not fabricate maintainers, teams, or
  adoption; document reality only.
- When adding a subsystem, update this guide's module map and the
  invariants list in the same change.
