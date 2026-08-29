# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅ Active development |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security issue in PivotCheck, please report it responsibly.

### Private Disclosure

**Preferred:** Report security vulnerabilities privately via email to the maintainers.

**Do NOT** create a public GitHub issue for security vulnerabilities.

### What to Include

When reporting a vulnerability, please include:

1. **Description** — Clear description of the vulnerability
2. **Impact** — What an attacker could achieve
3. **Reproduction** — Steps to reproduce (if applicable)
4. **Affected versions** — Which PivotCheck versions are affected
5. **Suggested fix** — If you have a proposed fix

### Response Timeline

- **Acknowledgement:** Within 72 hours
- **Initial assessment:** Within 7 days
- **Fix timeline:** Depends on severity; critical issues prioritized

### Scope

Security reports should focus on:

- **Credential leakage** — Accidental exposure of proxy credentials, passwords, tokens
- **Network safety violations** — Passive analysis performing unexpected network I/O
- **Input validation bypasses** — Malformed input causing crashes or unexpected behavior
- **Output integrity** — JSON/schema corruption, ANSI injection
- **Side effects** — Unexpected filesystem, environment, or network modifications
- **Supply chain** — Dependency vulnerabilities, packaging defects

### Out of Scope

- **Missing features** — UDP validation, SSH validation, etc. (these are documented as intentionally unsupported)
- **False positives in passive analysis** — Passive evidence is explicitly not validation
- **Operator misuse** — Using the tool outside authorized engagements
- **Environment-specific issues** — OS-level network configuration outside tool control

### Credential Handling

PivotCheck is designed with these security guarantees:

- **No credential persistence** — Credentials exist only in memory during invocation
- **CLI argument redaction** — `--proxy socks5://user:pass@host` redacted in all output
- **Environment variable support** — `--proxy-auth-env` keeps passwords out of process table
- **No logging of credentials** — Credentials never appear in logs, JSON, exceptions, or debug output

If you discover a credential leakage path, treat it as a security vulnerability.

### Network Safety Invariants

PivotCheck's architecture enforces these invariants:

1. **Passive analysis never performs network validation** — `discover`, `map`, `gaps`, `explain`, `compare`, `next` do zero network I/O
2. **Explicit validation is operator-controlled** — `check` and `proxy-check` require explicit target + port
3. **No automatic scanning** — No CIDR expansion, no port ranges, no host discovery
4. **Single transaction per invocation** — `proxy-check` does exactly one SOCKS5 CONNECT

Violations of these invariants are security bugs.

### Contact

For security reports, contact the maintainers through the GitHub repository's security advisory feature or the email listed in the repository metadata.

---

*This policy applies to PivotCheck v0.1.0 and subsequent versions unless superseded.*