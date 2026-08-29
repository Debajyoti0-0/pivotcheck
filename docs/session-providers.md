# Session providers

PivotCheck observes network topology from a *vantage point*. A provider is
the transport that obtains raw observation data from that vantage point;
everything downstream (parsers, analysis, comparison, map view, rendering)
is provider-agnostic.

## Architecture

```text
LocalProvider                SSHProvider
(local subprocess)           (system OpenSSH client)
      |                            |
      +--------- executor --------+
                  |
                  v
   fixed collector commands -> existing parsers
                  |
                  v
        CollectedDiscoveryData
                  |
                  v
            run_discovery()  (analysis, unchanged)
```

The transport boundary is the collectors' optional `executor` callable
(default: local `run_command`). `SSHExecutor` implements the same callable.
No parser was duplicated; no analysis module knows a provider exists.

## SSH implementation choice

**System OpenSSH client** (`ssh` binary, fixed argv, no shell):

- stdlib-only native SSH: not feasible without reimplementing the protocol.
- Paramiko: rejected — large dependency, duplicates auth/host-key handling,
  weaker Kali packaging story than delegating to the audited system client.
- AsyncSSH: rejected — async complexity with no operator value here.

## Security contract

- **Host keys:** strict verification against `known_hosts` by default
  (`StrictHostKeyChecking=yes`). Verification can never be disabled. An
  explicit opt-in flag (`--ssh-accept-new-hostkeys`) enables trust-on-first-
  use only (`accept-new`); changed host keys are still rejected.
- **Authentication:** delegated to the operator's existing SSH setup
  (agent, key files via `-i` reference, `~/.ssh/config`). PivotCheck has no
  credential model, stores nothing, logs nothing, serializes nothing.
  `BatchMode=yes` prevents any interactive prompt from blocking or leaking.
- **Remote commands:** only the fixed collector command set (`ip`, `ss`,
  `netstat`, `cat /etc/resolv.conf`, `hostname`) is ever sent. There is no
  generic remote-execution API. Host/user inputs are validated
  (`SSHConfig`) and passed as fixed argv tokens with an end-of-options
  guard; no local shell interpolation occurs.
- **Timeouts:** bounded connect timeout (<=60s) and per-command timeout
  (<=120s); timeouts surface as classified provider errors.

## Identity

Remote identity represents the observation vantage point, not the
transport endpoint: `provider="ssh"`, display name prefers an operator
label, then the remote hostname (best-effort, degrades gracefully), then
the configured target host. Failure to obtain the remote hostname never
aborts discovery.

## CLI

```bash
pivotcheck discover --ssh HOST
pivotcheck discover --ssh-user USER@HOST --ssh-port 2222 --ssh-key ~/.ssh/id_ed25519
pivotcheck baseline create --name dmz --ssh HOST
pivotcheck map --baseline workstation --ssh HOST   # compare across vantage points
```

Local operation remains zero-friction: no provider flag is required.
Provider failure exits 1 (fatal) and is distinguishable from partial
collector degradation, which remains non-fatal warnings on the snapshot.