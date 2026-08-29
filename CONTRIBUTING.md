# Contributing to PivotCheck

Thank you for considering a contribution to PivotCheck. This document outlines the development workflow, architectural invariants, and contribution standards.

## Development Setup

### Prerequisites

- Python 3.10+
- Git

### Installation

```bash
git clone https://github.com/<owner>/pivotcheck.git
cd pivotcheck
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

### Verify Setup

```bash
python -m pytest tests/ -q
python -m pytest -m integration -q
ruff check .
mypy pivotcheck
```

## Architecture Invariants (Non-Negotiable)

Every contribution must preserve these architectural principles:

### 1. Layered Dependency Direction

```
Models
   ↓
Discovery
   ↓
Analysis
   ↓
Output
   ↓
CLI
```

**Never** create reverse dependencies (e.g., Analysis importing CLI, Output importing Discovery).

### 2. Pure Analysis

Analysis functions (`pivotcheck/analysis/`) must be:
- **Deterministic** — Same input → same output
- **Side-effect free** — No I/O, no network, no filesystem, no global state mutation
- **Pure** — No hidden network activity, no hidden subprocess calls

### 3. Evidence Semantics

The evidence hierarchy must never be collapsed:

```
OBSERVED
    ≠
INFERRED
    ≠
PRIORITIZED
    ≠
EXPLICITLY VALIDATED
```

**Never** use language that conflates these stages:
- "Route evidence" ≠ "Reachable"
- "Transit candidate" ≠ "Confirmed pivot"
- "Inferred" ≠ "Confirmed"
- "Not observed" ≠ "Negative evidence"

### 4. Network Safety

**Passive analysis commands must never perform network I/O:**

| Command | Network I/O Allowed? |
|---------|---------------------|
| `discover` | ❌ No |
| `map` | ❌ No |
| `gaps` | ❌ No |
| `explain` | ❌ No |
| `compare` | ❌ No |
| `next` | ❌ No |
| `baseline` | ❌ No |
| `check` | ✅ Yes (explicit target) |
| `proxy-check` | ✅ Yes (explicit proxy + target) |

**No exceptions.** Adding network I/O to passive commands is a regression.

### 5. No Hidden Scanning

- No CIDR expansion
- No port ranges
- No automatic target generation
- No host discovery
- No implicit retries

Every validation is a single, explicit, operator-controlled action.

### 6. Credential Safety

- No credential persistence (memory only)
- Redaction in all output (CLI args, JSON, logs, exceptions)
- `--proxy-auth-env` for environment-based credentials
- No credential logging in any form

### 7. IPv4/IPv6 Isolation

- Never mix address families implicitly
- Explicit family handling in all network operations
- Tests must cover both families where applicable

## Contribution Workflow

### 1. Fork and Branch

```bash
git checkout -b feature/your-feature-name
```

Use descriptive branch names: `feat/evidence-gaps`, `fix/encoding-crash`, `test/network-safety-regression`

### 2. Make Changes

- Follow existing code style (ruff, mypy)
- Add tests for new functionality
- Update documentation if behavior changes
- Preserve all architectural invariants

### 3. Run Quality Gates

```bash
python -m pytest tests/ -q
python -m pytest -m integration -q
ruff check .
mypy pivotcheck
```

All must pass locally before pushing.

### 4. Test New Code

Every change requires appropriate test coverage:

| Change Type | Required Tests |
|-------------|----------------|
| New command | CLI contract, JSON schema, exit codes |
| New analysis function | Determinism, input order independence, edge cases |
| Protocol change | Network safety, credential safety, epistemic audit |
| Bug fix | Regression test for the specific failure |
| CLI change | All exit codes, --help, --json, --no-color |

### 5. Documentation

Update relevant documentation:
- `README.md` — If user-facing behavior changes
- `PROJECT_ARCHITECTURE.md` — If architecture changes
- `PROJECT_OUTPUT.md` — If output contracts change
- `PROTOCOL_SCOPE.md` — If protocol scope changes
- Docstrings — For new public APIs

### 6. Commit Discipline

```bash
git status
git diff --check
git diff
```

Logical commit messages:
- `feat: add evidence gap analysis command`
- `fix: prevent UnicodeEncodeError on cp1252`
- `test: add network safety regression for gaps command`
- `docs: update README with explicit validation workflow`
- `ci: add Python 3.10–3.14 matrix`

No "WIP", "fix", "update" without context.

### 7. Pull Request

- Clear title and description
- Reference related issues
- List architectural impacts
- Include test evidence
- Pass CI (all Python versions)

## Code Standards

### Formatting

- `ruff` configuration in `pyproject.toml` (line-length=88, target-version=py310)
- Run `ruff check . --fix` before committing

### Typing

- `mypy` configuration in `pyproject.toml` (python_version=3.10)
- Public APIs must have type annotations
- Avoid `# type: ignore` unless absolutely necessary with justification

### Testing

- Use pytest fixtures from `tests/fixtures/`
- Mark integration tests with `@pytest.mark.integration`
- Determinism tests for all analysis functions
- Adversarial tests for edge cases

### Documentation

- Docstrings on all public classes/functions
- Architecture docs in `docs/` and root `.md` files
- Output contracts in `PROJECT_OUTPUT.md`

## What We Accept

### ✅ Welcome Contributions

- Bug fixes with regression tests
- Test coverage improvements
- Documentation clarity improvements
- Performance optimizations (with benchmarks)
- CI/CD improvements
- Packaging improvements
- Security hardening

### ❌ Not Accepted

- New protocols (UDP, SSH, HTTP CONNECT, etc.) — scope freeze
- Scanning/batch validation features — architectural violation
- Credential persistence — security violation
- Automatic validation — safety invariant violation
- GUI/web interface — scope creep
- Database backends — scope creep
- Cloud integrations — scope creep
- "Convenience" features that weaken semantic guarantees

## Security Considerations

All contributions are reviewed for:
- Credential leakage paths
- Network safety regressions
- Side-effect introduction
- Epistemic overclaiming
- Supply chain risks

## Release Process

Maintainers handle versioning and releases. Contributors do not bump versions or create tags.

## Questions?

Open a GitHub Discussion or check existing documentation:
- `PROJECT_ARCHITECTURE.md` — System architecture
- `PROJECT_OUTPUT.md` — Output contracts
- `PROTOCOL_SCOPE.md` — Protocol decisions
- `RELEASE_READINESS_FINAL.md` — Release standards

---

*This guide reflects the architectural standards that make PivotCheck trustworthy. All contributions are evaluated against these principles.*