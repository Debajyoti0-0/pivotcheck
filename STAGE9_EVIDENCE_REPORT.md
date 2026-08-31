# PivotCheck — Stage 9 Operator Validation Evidence Report

- Date: 2026-08-31
- Validation target: **public release artifact** (`pip install pivotcheck` → 2.0.0 from PyPI),
  cross-referenced against repository checkout (v2.0.0 tag `f52e6b9`, v2.0.1 tag `067524a`)
- Platform: Windows 11 (win32), Python 3.14.5, pip 26.2.1
- Mode: evidence collection only. No source code was modified. No protocols added.
  No features implemented. No refactoring. Working tree clean at close.

---

## 1. Phase 9.1 — Release Consumer Validation

### 1.1 Installation

| Step | Result |
|---|---|
| `pip install pivotcheck` | Installed 2.0.0 from PyPI (upgraded stale local 1.0.0) |
| `pivotcheck --version` | `pivotcheck 2.0.0`, exit 0 |
| `pivotcheck --help` | All 10 subcommands listed, exit 0 |
| `python -m pivotcheck --version` | Reports **2.0.1** from repo checkout (see F-02 publication gap) |
| Baseline storage | `%LOCALAPPDATA%\pivotcheck\*.json`, atomic write, no root required |

Environment note (F-07): user-scheme pip on Windows installs `pivotcheck.exe`
to `%APPDATA%\Python\Python314\Scripts`, which is not on PATH. This is a pip
environment condition, not a PivotCheck packaging defect.

### 1.2 Command surface results

| Command | Valid-path result | Invalid/edge results |
|---|---|---|
| `discover` | 7 interfaces, 18 neighbors, 119 connections; text + JSON; exit 0 | `--summary` honored; JSON artifact 78 KB, well-formed |
| `map` | Correct connected-coverage table, confidence labels | `map --summary` correctly rejected (exit 2) — see F-04; `--focus`, `--show-pivots` exit 0 |
| `next` | Honest `NO INVESTIGATION CANDIDATES` on single-homed host, exit 0 | JSON `candidate: null` + message — automation-safe |
| `gaps` | Correct OBSERVED / NOT_PERFORMED / NOT_APPLICABLE per evidence type | Missing arg exit 2 (clean); **invalid CIDR crashes with traceback, exit 1 (F-01)** |
| `explain` | Correct for observed networks; explicit "NOT ACTIVELY VALIDATED" | **Absent network classified `CURRENT_EVIDENCE` on public 2.0.0 (F-02); invalid CIDR traceback (F-01)** |
| `check` | TIMEOUT→AMBIGUOUS with explicit non-proof language; REFUSED classified honestly | CIDR target rejected exit 3 with explicit "one explicit host at a time"; port range/list rejected exit 2; missing `--port` exit 2 |
| `proxy-check` | Dead proxy → staged `REFUSED` at Stage 1, verdict `NOT_VALIDATED`, honest limitation block | Missing `--proxy` exit 2; port range rejected exit 2 |
| `baseline` | create/list/show/delete all functional; delete requires `--yes` | Missing baseline exit 3, clean message; create rejects positional name (F-05) |
| `compare` | Correct zero-diff summary; `--output` writes artifact; overwrite requires `--force` (clean exit-2 refusal) | Missing baseline exit 3 |
| `opsec` | Predictive-only language explicit, limitations block present | Unknown action/platform → clean exit 2 with valid-value list |

### 1.3 Flag/format coverage

- `--json` on discover/next/gaps/check/proxy-check/opsec/compare: well-formed,
  deterministic structure, `schema_version` present on every artifact (values vary, F-10).
- `--format {text,json}`: honored everywhere tested.
- `--no-color`: verified zero ANSI escape bytes in non-TTY output.
- Missing/invalid arguments: exit 2 with targeted messages (verified on 8 paths).
- Unreachable target: TIMEOUT, 3008 ms against 3 s budget, honest AMBIGUOUS wording.
- Unsupported credential mode: `--protocol ssh` without `--ssh-key-env` and
  `--protocol smb`/`winrm` without `--credential-env` → clean exit-2 refusals
  with explicit "command lines are observable" rationale.
- Timeout conditions: honored exactly (no retry, single attempt).

---

## 2. Phase 9.2 — Operator Workflow Validation

Workflow executed end-to-end as an operator: discover → map → next → gaps →
explain → check → opsec → baseline → compare.

| Workflow question | Evidence-based answer |
|---|---|
| What did the operator expect? | Perspective inventory, candidate ranking, one-target validation — all delivered in expected order |
| What did PivotCheck actually show? | Matches expectations; coverage/confidence classification matched OS reality (Wi-Fi, vEthernet, link-local) |
| Evidence vs inference obvious? | Yes — `evidence:` lines carry confidence; `--show-pivots` explicitly labels routing inference as "never confirmed"; gaps output distinguishes OBSERVED / NOT_PERFORMED / NOT_APPLICABLE |
| Next action obvious? | Yes — gaps output states the exact next command (`pivotcheck check <target> --port <port>`) |
| Output misleading? | One case: F-02 (absent network claimed as observed on 2.0.0) — the only misleading output found |
| Important evidence missing? | F-06 (`via None` degrades route readability); no decision-blocking gaps found |
| External tool needed? | No — discover/map/gaps/explain were self-sufficient for this workflow |
| Unnecessary CLI steps? | Minor: F-04, F-05 flag/argument asymmetries |
| JSON sufficient for automation? | Yes; statuses machine-readable; F-10 documents schema-version variance |

---

## 3. Phase 9.3 / 9.4 — Classified Findings

### F-02 — Public 2.0.0 claims unobserved networks are "observed" (RELEASE-BLOCKING on public artifact)
- **Category:** BUG / SEMANTIC_CONFUSION (epistemic-honesty violation)
- **Severity:** HIGH
- **PivotCheck version:** 2.0.0 (PyPI). **Fixed in repo v2.0.1 (tagged `067524a`) — NOT yet published to PyPI.**
- **Platform:** win32 (classification logic is platform-independent)
- **Operator workflow:** explain → verify a suspected-but-unseen subnet
- **Exact command:** `pivotcheck explain 10.99.99.0/24`
- **Expected:** classification such as NOT_OBSERVED ("Network not found in current discovery evidence")
- **Actual:** `Classification: CURRENT_EVIDENCE` / "Network observed in current discovery evidence" with `Origin: unavailable`
- **Evidence:** reproduced on installed 2.0.0 artifact; CHANGELOG 2.0.1 entry describes the identical defect and fix ("Found during Stage 9 operator-workflow validation")
- **Security/semantic impact:** fabricates an observation claim for a network never seen — direct violation of "PRESENT ≠ VALID" / observed-vs-inferred guarantees; could cause an operator to treat an unverified subnet as evidenced
- **Reproducibility:** 2/2 on 2.0.0; v2.0.1 changes classification to NOT_OBSERVED
- **Frequency:** every explain of an unobserved/mistyped network
- **Proposed improvement:** none needed in code — **publish v2.0.1 to PyPI** (already tagged, tests green)
- **Confidence:** HIGH

### F-01 — Raw traceback on invalid CIDR for `explain` / `gaps`
- **Category:** BUG
- **Severity:** MEDIUM
- **Version:** 2.0.0 (PyPI)
- **Exact commands:** `pivotcheck explain not-a-cidr` ; `pivotcheck gaps 999.999.1.0/24`
- **Expected:** clean usage-class error, exit 2 (consistent with `check`/`opsec` validation)
- **Actual:** uncaught `ValueError` traceback from `analysis/explanation.py:75` and `analysis/evidence_gaps.py:102` → `models/network.py:244`; exit 1
- **Evidence:** full tracebacks captured; no partial/incorrect evidence emitted before the crash
- **Security/semantic impact:** no wrong evidence, but a crash path on ordinary operator typos; breaks CLI error contract (other commands exit 2 cleanly)
- **Reproducibility:** 2/2
- **Frequency:** every malformed network argument to these two commands
- **Proposed improvement (v2.0.x candidate):** validate/normalize the network argument at CLI entry and emit the standard `[-]` error + exit 2. Requires no architectural change.
- **Confidence:** HIGH

### F-03 — One transient "baseline not found" immediately after create
- **Category:** BUG (nondeterministic behavior) — **UNCONFIRMED**
- **Severity:** LOW
- **Exact sequence:** `baseline create --name stage9-baseline` (ok) → `baseline list` (ok) → `compare stage9-baseline --summary` (ok) → `compare stage9-baseline --json --output …` → `[-] baseline not found` exit 3; all subsequent invocations (14+) succeeded
- **Storage:** `%LOCALAPPDATA%\pivotcheck` — atomic temp-file write; not OneDrive-synced
- **Impact:** spurious failure would break automation; no wrong evidence produced
- **Reproducibility:** 1 occurrence out of ~20 attempts; not reproduced since
- **Proposed improvement:** none yet — monitor for recurrence; only investigate as a defect if reproduced
- **Confidence:** LOW

### F-04 — `--summary` flag asymmetry across read commands
- **Category:** USABILITY
- **Severity:** LOW
- **Evidence:** `discover --summary` and `compare --summary` exist; `map --summary` exits 2 (`unrecognized arguments`)
- **Impact:** minor friction; operator muscle-memory from `discover` fails on `map`
- **Proposed improvement:** candidate for v2.1 only if operator demand accumulates; behavior is documented in `--help`
- **Confidence:** HIGH (behavior), LOW (priority)

### F-05 — `baseline create` rejects positional name
- **Category:** USABILITY
- **Severity:** LOW
- **Evidence:** `baseline create stage9-baseline` → exit 2 ("arguments are required: --name"); `baseline show/delete NAME` take positional names
- **Impact:** subcommand argument-style inconsistency within one noun
- **Proposed improvement:** accept positional name for `create`; purely additive UX fix, no semantic change
- **Confidence:** HIGH

### F-06 — Python `None` leaked into operator-facing route text
- **Category:** USABILITY
- **Severity:** LOW
- **Evidence:** `gaps 172.16.0.0/16` → "Route to 172.16.0.0/16 via None dev 172.16.1.239 metric 291" (also present in JSON `details`)
- **Impact:** readability; a directly-connected route has no gateway, and `None` reads like missing data rather than "no gateway (directly connected)"
- **Proposed improvement:** render "directly connected (no gateway)"; text-only change plus JSON wording
- **Confidence:** HIGH

### F-08 — PyPI metadata understates platform support
- **Category:** PACKAGING / DOCUMENTATION
- **Severity:** MEDIUM (for adoption, not correctness)
- **Evidence:** `pyproject.toml` classifiers list only `Operating System :: POSIX :: Linux`; validated Windows behavior (discover/map/next/gaps/explain/check/baseline/compare/opsec) works correctly on win32, and `baseline_store.default_data_dir()` has a maintained Windows path
- **Impact:** release consumers filtering by classifier may wrongly conclude Windows is unsupported; Kali submission doc is correctly Linux-scoped
- **Proposed improvement:** add `Operating System :: Microsoft :: Windows` (and `POSIX :: MacOS` if macOS is claimed) in the next release
- **Confidence:** HIGH

### F-09 — `check` exits 0 on TIMEOUT / REFUSED
- **Category:** SEMANTIC_CONFUSION
- **Severity:** LOW
- **Evidence:** text and JSON both exit 0 for TIMEOUT and REFUSED; status carried in JSON `results[].status`
- **Impact:** operators scripting on exit codes could read exit 0 as "reachable". The result-as-data contract is defensible (the check succeeded; the finding is data), but this is undocumented for operators
- **Proposed improvement:** document the exit-code contract (`0 = check completed`, `3 = target/DNS class`, `2 = usage`) in README/help; JSON already unambiguous
- **Confidence:** HIGH

### F-10 — JSON `schema_version` varies per command without a registry
- **Category:** MISSING_EVIDENCE (documentation)
- **What is missing:** a published mapping of schema_version → command → field set
- **Why needed / decision:** automation consumers need to know when an artifact format changed and what depends on it
- **Frequency:** every automated consumer
- **Existing architecture fit:** yes — versions already exist (1.0 and 1.1 observed); only documentation required
- **Confidence:** HIGH

### Kali submission status (Phase 9.7)
- `KALI_TOOLS_SUBMISSION.md` reviewed against observed behavior: all claims verified
  (stdlib-only runtime, one-target/one-attempt, env-only credentials, ANSI-free
  non-TTY output, XDG data dir, no retries/CIDR expansion/remote execution).
- **Submission to Kali itself has NOT been performed from this environment.**
  Status: READY / PENDING EXTERNAL SUBMISSION. No acceptance claimed.
- Kali feedback: none available yet (honest "no feedback" is recorded as valid data).

### Phase 9.8 — Public project validation
- No GitHub issue/Discussion feedback was collected or manufactured. Recorded as: no
  external feedback available at validation time. Stars/downloads deliberately not
  treated as evidence.

---

## 4. Phase 9.9 — Security Regression (against installed public artifact)

| Invariant | Method | Result |
|---|---|---|
| No retries / one attempt | Source review of installed `checks/tcp.py`, `proxy.py`, `ssh.py`, `smb.py`, `winrm.py`; grep for retry loops; `tests/test_network_safety.py` | PASS — single `connect` per invocation; "ONE attempt" enforced in code and tests |
| No CIDR / port-range / host expansion | Live: `check 10.0.0.0/8` → explicit rejection exit 3; `--port 443-445` rejected exit 2 (both commands) | PASS |
| No fallback authentication / spraying | Live: ssh/smb/winrm without env credentials → exit-2 refusals; source review of check modules | PASS |
| No credential leakage / persistence | `--credential-env`/`--ssh-key-env` required; redaction in proxy output; secret-stripping in smb/winrm modules; `tests/test_credentials.py` | PASS |
| No command execution / tunneling | ssh check sends only built-in `exit`; SOCKS5 engine: one CONNECT, no BIND/ASSOCIATE/chaining (source + `tests/test_proxy_check_cli.py::test_one_transaction_invariant`) | PASS |
| Telemetry prediction ≠ observed | `opsec` output carries explicit "predictive only / nothing was confirmed" limitation block; JSON equivalent | PASS |
| No scanning mass expansion | Only operator-specified target:port contacted | PASS |
| Destructive-action guards | `baseline delete` requires `--yes`; `compare --output` requires `--force` | PASS |

**No security regressions found. No release-blocking security findings.**

Regression suite: `pytest` fully green (all tests passed, 0 failures/errors); `ruff check` clean.

## 5. Stage 9 Exit Criteria

- [x] Public installation verified (PyPI 2.0.0)
- [x] All primary CLI workflows exercised (10/10 commands + flags)
- [x] Operator workflow testing completed (end-to-end, Section 2)
- [x] Findings classified (F-01…F-10 + Kali status)
- [x] Reproducible defects separated from feature requests (F-01, F-02 reproducible; F-03 unconfirmed; F-04/05/06 low-priority UX)
- [x] Semantic confusion documented (F-02, F-09)
- [x] False-positive/false-negative evidence documented (F-02 is the false-positive instance; no false negatives observed)
- [x] Missing-evidence requests documented (F-10; none decision-blocking)
- [x] Kali submission package verified ready — **actual Kali submission pending (external step)**
- [ ] Kali feedback recorded — none available (valid data state)
- [x] No fabricated operator feedback
- [x] No speculative feature implementation (working tree clean; no branches created)
- [x] Security invariants revalidated (Section 4)
- [~] Release-blocking defects: one exists **on the public artifact only** (F-02); the fix already exists in tagged v2.0.1 — resolution is publication, not new code
- [x] Regression suite remains green
- [x] Final Stage-9 report produced (this document)

---

## 6. Final Decision Gate

**Recommendation: A — MAINTENANCE RELEASE (v2.0.x), with one required action:**

1. **Publish the already-tagged v2.0.1 to PyPI.** The public 2.0.0 artifact contains
   F-02, a fabricated-observation defect violating PivotCheck's core epistemic
   guarantees ("observed in current discovery evidence" for a network never observed).
   No new code is required — the fix exists, is committed, tagged, and the suite is green.
2. Optionally fold F-01 (invalid-CIDR traceback) and F-08 (Windows classifier) into
   the same v2.0.x maintenance release; both are small, contained, and evidence-backed.

**Not justified at this time:** v2.1 feature release. The validation surfaced no
missing-evidence gap that the current architecture cannot represent honestly
(F-04/F-05/F-06/F-09/F-10 are UX/documentation refinements, not capability gaps).
No protocol admission-gate candidates were generated by operator evidence
(Kerberos/RDP/WMI/PTH/etc. remain rejected per Phase 9.6).

---

## 7. Stop Condition Compliance

Per the Stage 9 protocol, evidence collection stops here. No fixes were
implemented during this stage beyond what already exists in tagged v2.0.1.
No v2.1 branch, protocol branch, or speculative abstraction was created. The
next engineering phase is gated on: publishing v2.0.1, then continued evidence
collection per the decision above.

---

## 8. Stage 9 Closure — Corrective Release Record (2026-08-31)

Historical evidence above is preserved unchanged. Closure status:

```text
DEFECT-001 (explain CURRENT_EVIDENCE misclassification)
  Status:        FIXED / PUBLICLY VERIFIED
  Fixed in:      v2.0.1 (commit 067524a), published to PyPI 2026-08-31T11:50:07Z
  Reproduction:  pivotcheck explain 10.99.99.0/24 on public 2.0.0 →
                 "Classification: CURRENT_EVIDENCE / Network observed in
                 current discovery evidence" (fabricated observation)
  Verified:      public 2.0.1 artifact (fresh venv, neutral CWD) →
                 "Classification: NOT_OBSERVED / Network not found in current
                 discovery evidence"

DEFECT-002 (invalid-CIDR traceback in gaps/explain)
  Status:        FIXED / PUBLICLY VERIFIED
  Fixed in:      v2.0.2 (commit 4a10e74), published to PyPI 2026-08-31T13:18:24Z
  Reproduction:  pivotcheck gaps 999.999.1.0/24 on public 2.0.0 AND public
                 2.0.1 → uncaught ValueError traceback, exit 1
  Root cause:    raw operator input flowed unvalidated from the CLI into
                 Network(cidr=...) / ipaddress.ip_network()
  Minimal fix:   pure argument validation at the CLI boundary
                 (cli._validate_network_argument) before discovery; no
                 side effects on invalid input; original argument passed
                 through unchanged for valid input
  Verified:      public 2.0.2 artifact (fresh venv, neutral CWD) →
                 exit 2, clean "[-] Invalid network argument" message,
                 no traceback, empty stdout on JSON error paths
```

Process finding preserved for the record: the v2.0.1 tag was pushed and its
release pipeline succeeded mid-Stage-9 (11:48–11:50 UTC) with only DEFECT-001
corrected, so DEFECT-002 could not ship under the immutable 2.0.1 version
identifier. The corrective release therefore shipped as **v2.0.2** — still a
patch release correcting existing 2.0 capability defects, per the Stage 9
decision gate. Regression coverage added: 24 CLI-level tests
(tests/test_intelligence_cli.py::TestNetworkArgumentValidation), including
DEFECT-001 boundary assertions, JSON error paths, and a no-side-effects test
proving discovery never runs for invalid input. Release pipeline run #4
(v2.0.2): completed / success; CI matrix 3.10–3.14 green.




