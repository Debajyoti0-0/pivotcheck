# PivotCheck — Protocol Scope Decision

**Status:** Final decision record for validation protocol support.

**Date:** 2026-08-29

---

## 1. Executive Summary

PivotCheck implements **two validation protocols** at the transport layer:

| Protocol | Command | Scope |
|---|---|---|
| **TCP** | `check` | Explicit target + explicit port(s), single connection attempt per address:port |
| **SOCKS5 CONNECT** | `proxy-check` | Explicit proxy + explicit destination + explicit port, one three-stage transaction |

All other protocols are **explicitly out of scope** for the reasons documented below.

---

## 2. Decision Matrix

| Protocol | Decision | Rationale |
|---|---|---|
| **TCP** | ✅ IMPLEMENTED | Core validation primitive. Answers "can I reach this host:port via TCP?" |
| **SOCKS5 CONNECT** | ✅ IMPLEMENTED | Pivot validation primitive. Answers "can this SOCKS5 proxy relay to this destination?" |
| **UDP** | ❌ DEFERRED | Connectionless semantics require careful epistemic design. No response ≠ unreachable. Would need distinct evidence states (`NO_RESPONSE_OBSERVED`, `ICMP_UNREACHABLE_OBSERVED`, `UDP_RESPONSE_OBSERVED`) without claiming "port open". Low operator priority vs. implementation complexity. |
| **SSH** | ❌ REJECTED | Application-layer protocol. Transport check (TCP 22) already exists. Use `ssh -o BatchMode=yes`, `nmap -sV`, or dedicated SSH tooling. |
| **Telnet** | ❌ REJECTED | Obsolete application protocol. Transport check (TCP 23) exists. |
| **HTTP CONNECT** | ❌ REJECTED | Proxy protocol variant. Project scope is SOCKS5 only. |
| **SOCKS4/4a** | ❌ REJECTED | Legacy protocols. Scope creep without operator need. |
| **UDP ASSOCIATE** | ❌ REJECTED | SOCKS5 relay mode (not CONNECT). Not needed for pivot validation. |
| **BIND** | ❌ REJECTED | SOCKS5 inbound relay. Not needed. |
| **SMB** | ❌ REJECTED | Application-layer. Use `impacket`, `crackmapexec`, `smbclient`. |
| **WinRM** | ❌ REJECTED | Application-layer. Use `evil-winrm`, `crackmapexec`. |
| **LDAP** | ❌ REJECTED | Application-layer. Use `ldapsearch`, `nmap --script ldap-*`. |
| **RDP** | ❌ REJECTED | Application-layer. Use `xfreerdp`, `nmap --script rdp-*`. |
| **DNS** | ❌ REJECTED | Application-layer. `proxy-check` already sends hostnames to proxy (ATYP 0x03). |

---

## 3. Architecture Boundary: Transport vs. Application Validation

### What PivotCheck Validates (Transport Layer)

```
TCP CHECK:
  Local vantage → TCP SYN → Target:port → SYN/ACK/RST/timeout
  Result: Network path + TCP acceptance

SOCKS5 CONNECT:
  Local vantage → TCP → Proxy → SOCKS5 negotiation → CONNECT → Destination
  Result: Proxy path + CONNECT acceptance
```

### What PivotCheck Does NOT Validate (Application Layer)

```
SSH:     TCP 22 reachable  ≠  SSH banner / auth / key exchange / session
Telnet:  TCP 23 reachable  ≠  Telnet negotiation / login prompt / auth
HTTP:    TCP 80/443 reachable  ≠  HTTP response / auth / API
SMB:     TCP 445 reachable  ≠  SMB dialect / auth / share access
WinRM:   TCP 5985/5986 reachable  ≠  WS-Man / auth / PowerShell remoting
LDAP:    TCP 389/636 reachable  ≠  LDAP bind / search / directory ops
RDP:     TCP 3389 reachable  ≠  RDP security / auth / session
```

**Principle:** PivotCheck answers *"Is the network path open and does the transport layer accept the connection?"* It does not answer *"Does the service work correctly?"*

---

## 4. UDP Special Analysis (If Ever Reconsidered)

### Fundamental Semantic Problem

| TCP | UDP |
|---|---|
| Connection-oriented (SYN/ACK) | Connectionless (datagram) |
| `SUCCESS` = handshake completed | No handshake equivalent |
| `REFUSED` = RST received | ICMP Port Unreachable *may* arrive |
| `TIMEOUT` = ambiguous | `TIMEOUT` = even more ambiguous |
| State machine clear | No state machine |

### Required Evidence States (If Implemented)

```text
UDP_RESPONSE_OBSERVED          # Application-layer reply received
ICMP_PORT_UNREACHABLE_OBSERVED # ICMP Type 3 Code 3
ICMP_HOST_UNREACHABLE_OBSERVED # ICMP Type 3 Code 1
ICMP_NETWORK_UNREACHABLE_OBSERVED # ICMP Type 3 Code 0
TIMEOUT                        # No response (AMBIGUOUS)
LOCAL_ERROR                    # OS socket error
```

### Forbidden Output
```text
NEVER: "UDP PORT OPEN" (from silence alone)
NEVER: "UDP SERVICE RUNNING" (without application response)
```

### Implementation Constraints (If Pursued)
- Explicit target only (`pivotcheck udp-check 10.10.20.25 --port 53`)
- No CIDR expansion
- No port ranges
- Single attempt (configurable timeout)
- Bounded by architecture invariants

### Verdict
**Deferred indefinitely.** The epistemic gap between "no response" and "unreachable" is fundamental to UDP. Transport TCP validation + SOCKS5 CONNECT cover >95% of pivot validation needs. Operators can use `nmap -sU`, `nc -u`, or protocol-specific tools for UDP.

---

## 5. Why Not a Protocol Framework?

### Rejected: Generic `ValidationTransport` Abstraction

```python
# This would be scope creep:
class ValidationTransport:
    def validate(self, target: str, port: int) -> ValidationResult: ...
    
class TCPTransport(ValidationTransport): ...
class UDPTransport(ValidationTransport): ...
class SOCKS5Transport(ValidationTransport): ...
class SSTransport(ValidationTransport): ...  # SSH?
class HTTPConnectTransport(ValidationTransport): ...
```

### Why Rejected

1. **No operator need** — TCP + SOCKS5 CONNECT answer the actual pivot questions
2. **Maintenance burden** — Each protocol adds parser, state machine, error taxonomy
3. **Scope creep vector** — "Just add one more protocol" → becomes `nmap`
4. **Semantic dilution** — Application protocols have fundamentally different evidence models
5. **Existing tools do it better** — `nmap -sV`, `impacket`, `crackmapexec` are purpose-built

### Current Architecture (Deliberate)

```
checks/
├── tcp.py       # TCP validation (CheckStatus taxonomy)
├── proxy.py     # SOCKS5 CONNECT (ProxyStageStatus taxonomy)
└── resolver.py  # Shared target resolution
```

Two independent, focused validation engines. No shared abstraction because their semantics are intentionally different (direct vs. relay).

---

## 6. Future Protocol Criteria

A new validation protocol would be considered **only if**:

1. **Operator workflow gap** — Real red-team scenario where TCP/SOCKS5 cannot answer the question
2. **Transport-layer focus** — Validates network path + transport acceptance, not application logic
3. **Deterministic classification** — Finite, documented status taxonomy (like `CheckStatus`, `ProxyStageStatus`)
4. **Explicit target only** — No scanning, no discovery, no ranges
5. **Single transaction** — One attempt, bounded timeout, no retries
6. **No credential persistence** — Credentials passed per-invocation only
7. **Existing tooling insufficient** — Not already solved better by `nmap`, `impacket`, etc.

**No protocol currently meets all criteria.**

---

## 7. Related Architectural Decisions

| Decision | Document |
|---|---|
| No CIDR expansion in `check` | `PROJECT_PLAN.md` §4.5, `PROJECT_ARCHITECTURE.md` §14 |
| No port ranges in `check` | `PROJECT_PLAN.md` §4.5, CLI parser rejects |
| No automatic validation of `next` candidates | `PROJECT_ARCHITECTURE.md` §12, `PROJECT_PLAN.md` §16 |
| No credential persistence | `OPERATOR_GAP_REPORT.md` G1, `PROJECT_ARCHITECTURE.md` §14.1 |
| Single transaction invariant for `proxy-check` | `PROJECT_ARCHITECTURE.md` §14.1, `PROJECT_OUTPUT.md` §10A |

---

## 8. Change Control

Any protocol scope expansion requires:

1. **Operator workflow analysis** — Document the specific red-team scenario
2. **Architecture review** — Verify no invariant violations
3. **Threat model update** — Assess new attack surface
4. **Implementation plan** — Parser, state machine, taxonomy, tests
5. **Documentation update** — This file, `PROJECT_ARCHITECTURE.md`, `PROJECT_OUTPUT.md`

**No protocol additions without explicit approval through this process.**

---

*End of Protocol Scope Decision*