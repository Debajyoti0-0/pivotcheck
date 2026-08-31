# Operator Validation — PivotCheck 2.0

Formal Stage-9 protocol for collecting, reproducing, and classifying operator
evidence about PivotCheck 2.0.0. This is an evidence-collection phase, not a
feature-development phase. Nothing in this document authorizes implementation.

## 1. Frozen Release Baseline

```text
version = 2.0.0
tag = v2.0.0
baseline_commit = f52e6b9
```

- The `v2.0.0` tag is the immutable production baseline; `f52e6b9` is the exact
  commit it references (verified via `git rev-list -n 1 v2.0.0`).
- Validation runs against the **public PyPI artifact** (`pip install pivotcheck`)
  and/or a clean checkout at the frozen tag — never against unreleased working
  state when judging released behavior.
- Application behavior must not be modified during validation. A defect must be
  classified and reproduced against the frozen release before any fix is proposed.

## 2. Validation Methodology

1. **Install the public artifact** in a fresh environment; verify `--version`,
   `--help`, and dependency-light installation.
2. **Run workflows, not isolated functions.** Follow the operator flow:
   discover → map → next → gaps → explain → check (one explicit target) →
   opsec → baseline → compare.
3. **Ask, per workflow:** what did the operator expect; what was shown; was the
   evidence/inference boundary obvious; was the next action obvious; was any
   output misleading; was evidence missing; was an external tool required; were
   steps unnecessary; was JSON automation-sufficient.
4. **Exercise edge paths:** missing/invalid arguments, unreachable targets,
   timeout conditions, unsupported credential modes, nonexistent baselines,
   overwrite/delete guards.
5. **Record every observation** in the feedback schema (Section 6) and classify
   it (Section 7). Never accept "this should be better" as evidence.

## 3. Environment Matrix

Record per validation run:

| Field | Example |
|---|---|
| pivotcheck_version | 2.0.0 (PyPI artifact) |
| python_version | 3.10 / 3.11 / 3.12 / 3.13 / 3.14 |
| platform | Linux / Windows / macOS |
| install_method | pip (user/venv), optional extras present/absent |
| network_position | single-homed / multi-homed / proxied |
| authorization | engagement scope reference (never secrets) |

Validated reference environment: Windows 11 (win32), Python 3.14.5, pip 26.2.1,
user-scheme install, PyPI artifact 2.0.0.

## 4. Command Matrix

| Surface | Semantics validated |
|---|---|
| `discover`, `discover --summary`, `--json` | passive collection; zero network I/O; observed/inferred labeling |
| `map`, `--focus`, `--show-pivots` | topology; pivot context explicitly "routing evidence, never confirmed" |
| `next` (text/JSON) | deterministic single candidate, or honest "none" |
| `gaps` | six-state evidence model: OBSERVED / NOT_PERFORMED / NOT_APPLICABLE / NOT_OBSERVED / NOT_COLLECTED / NEGATIVE_EVIDENCE |
| `explain` | evidence → inference → priority chain; "NOT ACTIVELY VALIDATED" |
| `check --protocol tcp` | one target/port/attempt; TIMEOUT→AMBIGUOUS; REFUSED distinct from filtered |
| `check --protocol ssh/smb/winrm` | one credential, env-only; verdict semantics; optional extras |
| `proxy-check` | one proxy CONNECT; NOT_VALIDATED verdict; proxy-side DNS |
| `baseline create/list/show/delete` | atomic persistence; `--yes` guard; name validation |
| `compare` | deterministic diff; `--output` + `--force` guard |
| `opsec` | predictive-only telemetry analysis; explicit limitation block |

Edge paths: invalid CIDR, CIDR targets, port ranges/lists, missing `--port`,
missing `--proxy`, unknown `--action`/`--platform`, missing credentials,
nonexistent baselines, existing `--output` without `--force`.

## 5. Expected Semantics (epistemic contract)

Every validated operator run must confirm these distinctions hold in output:

```text
AUTHENTICATED   ≠ shell access ≠ file access ≠ admin ≠ execution ≠ pivot capability
ROUTABLE_TO     ≠ reachable
TIMEOUT         ≠ host down
AUTH_FAILED     ≠ host unavailable
PRESENT         ≠ authentication validated
OBSERVED        ≠ INFERRED ≠ NEGATIVE ≠ UNKNOWN
PREDICTED OPSEC ≠ OBSERVED TELEMETRY
NOT_PERFORMED   ≠ NOT_APPLICABLE ≠ NOT_COLLECTED ≠ NEGATIVE_EVIDENCE
```

An operator run that produces output contradicting any line above is a
SEMANTIC_CONFUSION or FALSE_POSITIVE finding, regardless of technical correctness.

## 6. Feedback Schema

Every real-world observation is recorded with exactly these fields:

```text
validation_id             stable identifier (OPV-YYYYMMDD-NN)
pivotcheck_version        exact artifact version under test
platform                  OS + version
python_version            exact interpreter version
command                   exact command line, fully sanitized
sanitized_target_class    e.g. "loopback", "RFC1918 host", "public host"
                          — never the actual address unless authorized to publish
protocol                  tcp / ssh / smb / winrm / socks5 / passive
expected_result           what the operator expected, with ground-truth basis
observed_result           what PivotCheck actually output (verbatim, sanitized)
operator_interpretation   what the operator concluded from the output
actual_ground_truth       independently established reality (Section 7)
classification            one of the defect classes (Section 8)
severity                  one of the severity levels (Section 9)
reproducible              yes / no / intermittent (+ attempt counts)
evidence                  sanitized output excerpts, exit codes, timings
proposed_fix              optional; evidence-based, never speculative
```

**Never collect:** credentials, private keys, hashes, tokens, session cookies,
customer identifiers, internal hostnames, sensitive IP ranges/CIDRs, engagement
names, or any other secret. Evidence is sanitized **before** entering the
repository; when in doubt, generalize the target class and redact.

## 7. Ground-Truth Methodology

Observation alone is not evidence. Every finding must pair the observed result
with independently known ground truth:

```text
PivotCheck → AUTH_FAILED   + ground truth "credential intentionally invalid"   → CORRECT
PivotCheck → AUTH_FAILED   + ground truth "credential known valid"           → POTENTIAL BUG
PivotCheck → TIMEOUT       + ground truth "service running, no filter"       → POTENTIAL BUG
PivotCheck → TIMEOUT       + ground truth "firewall drops SYN"               → CORRECT (ambiguous)
```

Ground-truth techniques (all within authorized scope):

- **Positive control:** operator-controlled listener (e.g. local TCP socket) —
  validated SUCCESS must occur.
- **Negative control:** known-closed port — REFUSED expected.
- **Ambiguous control:** filtered/blackholed address — TIMEOUT must remain
  AMBIGUOUS and must not be framed as either state.
- **Local pre-flight controls:** invalid key material, absent optional extras,
  missing env variables — must fail locally, before network I/O, without
  fabricating a target-state verdict.
- **Credential controls:** intentionally invalid credentials — AUTH_FAILED
  expected; intentionally valid credentials — AUTHENTICATED expected, with no
  implied capability beyond authentication.

## 8. Defect Classification

Findings MUST be classified as exactly one of:

```text
BUG                 incorrect behavior (wrong result, crash, malformed JSON,
                    wrong exit code, nondeterminism, platform failure)
SECURITY            invariant violation or credential/secret exposure path
USABILITY           correct behavior but unreasonable operator effort
DOCUMENTATION       docs missing, wrong, stale, or misleading
SEMANTIC_CONFUSION  accurate output a competent operator could reasonably
                    misinterpret (priority over cosmetic items)
FALSE_POSITIVE      recommends/represents meaning the evidence does not justify
FALSE_NEGATIVE      fails to surface a relationship the evidence supports
PACKAGING           distribution/metadata defects (classifiers, extras, wheels)
INSTALLATION        install-time failures or environment conflicts
PERFORMANCE         unjustified resource/latency behavior
OTHER               anything else, with justification
```

## 9. Severity Model

```text
CRITICAL  Security-invariant violation; fabricated evidence; credential exposure.
          Release-blocking. Fix before any further release.
HIGH      Misleading or wrong evidence that could change an operator decision.
          Release-blocking for the affected artifact.
MEDIUM    Defect degrades correctness of workflow or breaks the CLI error
          contract without producing wrong evidence.
LOW       Friction, readability, documentation polish, metadata gaps.
NONE      Informational observation; no defect.
```

Reproducibility weighting: an unconfirmed intermittent defect stays LOW until
reproduced or corroborated by a second operator.

## 10. Security Regression Checklist (per validation cycle)

Confirm every line against the artifact under test:

```text
[ ] no mass scanning
[ ] no CIDR expansion
[ ] no port expansion
[ ] no retry loops
[ ] no credential fallback
[ ] no guest fallback
[ ] no command execution
[ ] no tunneling
[ ] no credential material in output
[ ] no secret persistence
[ ] no telemetry collection
[ ] no evasion guidance
```

Verification techniques: targeted source review of `pivotcheck/checks/`,
live rejection tests (CIDR target, port range, CLI credentials), ANSI scan of
non-TTY output, JSON artifact inspection for credential fields, and the
existing safety test suite (`tests/test_network_safety.py`,
`tests/test_credentials.py`, protocol CLI suites).

Any violation is a CRITICAL/SECURITY finding and release-blocking.

## 11. Documentation Usability Checklist

A new operator must be able to answer, within minutes, from README + docs:

```text
[ ] 1. What does PivotCheck discover?
[ ] 2. What does it actually validate?
[ ] 3. What does it explicitly NOT prove?
[ ] 4. Which protocols are supported?
[ ] 5. Which credentials are supported?
[ ] 6. What does each verdict mean?
[ ] 7. What does a timeout mean?
[ ] 8. What does negative evidence mean?
[ ] 9. Is OPSEC telemetry observed or predicted?
[ ] 10. How do I report a bug safely?
```

Status at v2.0.0 self-validation: 1–5 and 7–10 answerable from README and
SECURITY.md. Item 6 (a consolidated verdict glossary: VALIDATED, AUTH_FAILED,
TIMEOUT, REFUSED, DNS_ERROR, NOT_VALIDATED, NOT_OBSERVED, …) is spread across
command outputs and docs — recorded as a DOCUMENTATION observation for the
findings review. SECURITY.md's supported-versions table also lists only 1.0.x —
stale relative to 2.0.x and recorded for correction in a documentation-only
maintenance change.

## 12. Operator Acceptance Criteria

```text
[ ] v2.0.0 baseline frozen
[ ] clean installation verified
[ ] supported CLI surface exercised
[ ] TCP validation exercised (positive, negative, ambiguous controls)
[ ] SSH validation exercised (pre-flight + contract level; live auth pending
    an authorized target)
[ ] SMB validation exercised (contract level; live auth pending)
[ ] WinRM validation exercised (contract level; live auth pending)
[ ] discovery semantics validated
[ ] graph/correlation semantics reviewed (next/explain/pivot context)
[ ] OPSEC semantics reviewed (predictive ≠ observed confirmed in output)
[ ] ground-truth methodology established
[ ] sanitized evidence protocol established
[ ] feedback schema established
[ ] security regression checklist established
[ ] documentation usability checklist established
[ ] no secrets collected
[ ] no speculative features implemented
[ ] no v2.1 code changes
[ ] all existing tests remain green
```

## 13. Feedback Intake Rule

Operator requests for new capabilities (Kerberos, RDP, WMI/DCOM, SMB share
enumeration, execution, scanning, graph CLI, …) are **recorded, never
implemented** during Stage 9. Each recorded request must answer: is existing
capability incorrect; is evidence missing; is the result hard to interpret; is
the workflow inefficient; is the request genuinely required; does it preserve
PivotCheck's identity and security boundaries; does it add dependencies,
evidence states, or architectural change. Only evidence that survives these
questions may later become a v2.1 RFC.

Findings are recorded in [`operator-findings.md`](operator-findings.md).
Prior internal self-validation evidence (Stage 9, 2026-08-31) is preserved in
[`../STAGE9_EVIDENCE_REPORT.md`](../STAGE9_EVIDENCE_REPORT.md).


