"""PivotCheck command-line interface.

The CLI orchestrates only: it parses arguments, invokes the discovery engine,
and hands the normalized snapshot to a renderer. It contains no discovery,
analysis, or presentation logic itself.

Exit codes (deliberate contract for shell automation):
    discover/map:
        0 — discovery completed successfully (warnings do NOT change this;
            partial collector degradation is reported in output and JSON)
        1 — fatal execution failure (discovery engine could not run)
        2 — invalid CLI usage or arguments
    check:
        0 — check executed normally, whatever the TCP outcome
            (SUCCESS / REFUSED / TIMEOUT are all DATA, not failures)
        1 — fatal internal/local execution failure
        2 — invalid command-line usage
        3 — target name could not be resolved (DNS_ERROR)
        3 — requested baseline not found (when --baseline is used)
        4 — requested baseline is invalid/unsupported (when --baseline is used)
    proxy-check:
        0 — validation executed; every staged outcome (proxy TCP result,
            SOCKS5 negotiation/auth result, CONNECT reply code, VALIDATED)
            is DATA, not a CLI failure
        1 — fatal internal/local execution failure
        2 — invalid command-line usage (proxy URL, target, port, timeout)
        3 — the PROXY endpoint name could not be resolved (DNS_ERROR);
            the destination is never resolved locally (proxy-side DNS)
"""

from __future__ import annotations

import argparse
import getpass
import ipaddress
import os
import re
import sys
from typing import NoReturn, TextIO

from pivotcheck import __version__
from pivotcheck.analysis.comparison import DiffReport, baseline_from_snapshot, compare
from pivotcheck.analysis.evidence_gaps import analyze_evidence_gaps
from pivotcheck.analysis.explanation import explain_network
from pivotcheck.analysis.gateway import assess_transit_evidence
from pivotcheck.analysis.map_view import build_map_view
from pivotcheck.analysis.next_step import select_next_investigation
from pivotcheck.analysis.query import (
    QueryOptions,
    filter_map_view,
    filter_report,
    filter_snapshot,
    resolve_focus_network,
)
from pivotcheck.analysis.recommendation import Recommendation, recommend
from pivotcheck.analysis.summary import (
    summarize_comparison,
    summarize_snapshot,
)
from pivotcheck.checks.context import (
    build_validation_context,
    context_from_snapshot,
)
from pivotcheck.checks.proxy import check_proxy, parse_proxy_url
from pivotcheck.checks.resolver import resolve_target, validate_target
from pivotcheck.checks.smb import validate_smb_auth
from pivotcheck.checks.ssh import validate_ssh_auth
from pivotcheck.checks.tcp import check_tcp, validate_port, validate_timeout
from pivotcheck.checks.winrm import validate_winrm_auth
from pivotcheck.discovery.engine import run_discovery
from pivotcheck.discovery.ssh import (
    HostKeyPolicy,
    SSHConfig,
    SSHConfigError,
    SSHProvider,
)
from pivotcheck.models.check import (
    CheckReport,
    CheckResult,
    CheckStatus,
)
from pivotcheck.models.credentials import CredentialType
from pivotcheck.models.proxy_check import (
    ProxyCheckReport,
    ProxyEndpoint,
    ProxyStageName,
    ProxyStageStatus,
)
from pivotcheck.models.result import DiscoverySnapshot
from pivotcheck.models.smb_check import (
    SMBCheckReport,
    SMBCheckStatus,
)
from pivotcheck.models.ssh_check import (
    SSHCheckReport,
    SSHCheckStatus,
)
from pivotcheck.models.winrm_check import (
    WinRMCheckReport,
    WinRMCheckStatus,
)
from pivotcheck.output.artifact import write_json_artifact
from pivotcheck.output.check_output import render_check, render_check_json
from pivotcheck.output.comparison import (
    comparison_to_dict,
    render_comparison,
)
from pivotcheck.output.evidence_gaps import render_gaps, render_gaps_json
from pivotcheck.output.intelligence import (
    render_explanation,
    render_recommendations,
    render_summary,
)
from pivotcheck.output.json import render_json
from pivotcheck.output.map_view import render_map_view, render_map_view_json
from pivotcheck.output.next_step import render_next_step, render_next_step_json
from pivotcheck.output.proxy_check import (
    render_proxy_check,
    render_proxy_check_json,
)
from pivotcheck.output.smb_check import render_smb_check, render_smb_check_json
from pivotcheck.output.ssh_check import render_ssh_check, render_ssh_check_json
from pivotcheck.output.terminal import render_detailed, should_use_color
from pivotcheck.output.winrm_check import render_winrm_check, render_winrm_check_json
from pivotcheck.output.writer import text_stream
from pivotcheck.storage.baseline_store import (
    BaselineExistsError,
    BaselineNameError,
    BaselineNotFoundError,
    BaselineSchemaError,
    BaselineStore,
)

EXIT_OK = 0
EXIT_FATAL = 1
EXIT_USAGE = 2
EXIT_RESOLVE = 3
EXIT_BASELINE_NOT_FOUND = 3
EXIT_BASELINE_SCHEMA = 4


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pivotcheck",
        description=(
            "Passive network discovery and pivot path validation for "
            "authorized security assessments."
        ),
        epilog=(
            "Example: pivotcheck discover\n"
            "         pivotcheck map\n"
            "         pivotcheck discover --format json > snapshot.json"
        ),
    )
    parser.add_argument(
        "--version", action="version", version=f"pivotcheck {__version__}"
    )
    parser.add_argument(
        "--data-dir",
        help="baseline storage directory (overrides PIVOTCHECK_DATA_DIR and platform default)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show diagnostic detail on stderr (collectors used, fallbacks)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="disable ANSI color even on a TTY",
    )

    sub = parser.add_subparsers(dest="command")

    discover = sub.add_parser(
        "discover",
        help="run passive discovery and show detailed results",
        description="Enumerate interfaces, routes, neighbors, DNS, and sockets,"
        " then classify reachable networks and potential pivot paths.",
    )
    _add_output_args(discover)
    _add_filter_args(discover)
    discover.add_argument(
        "--summary",
        action="store_true",
        help="show a concise operational summary instead of full detail",
    )
    _add_ssh_args(discover)

    # 'map' is a presentation mode over the same discovery result.
    mp = sub.add_parser(
        "map",
        help="topology-focused view of the same discovery data",
        description="Show interface/network relationships with confidence"
        " levels. Uses identical discovery data as 'discover'.",
    )
    _add_output_args(mp)
    _add_filter_args(mp, focus=True, changes_only=True, show_pivots=True)
    mp.add_argument(
        "--baseline",
        help="saved baseline to show as comparison-aware map context",
    )
    _add_ssh_args(mp)

    # Next-step decision support: select the highest-priority investigation candidate.
    next_cmd = sub.add_parser(
        "next",
        help="select the highest-priority investigation candidate from existing evidence",
        description="Analyze existing transit evidence and recommendations to identify "
        "the single highest-priority network/pivot investigation candidate. "
        "This is decision support only — no active validation is performed.",
    )
    next_cmd.add_argument(
        "--baseline",
        metavar="NAME",
        help="attach comparison context relative to a saved baseline "
        "(loads the baseline, performs one current discovery, and reports "
        "how the candidate's network relates to the saved perspective)",
    )
    _add_output_args(next_cmd)

    # Evidence gap analysis: identify what evidence is missing for a network.
    gaps_cmd = sub.add_parser(
        "gaps",
        help="analyze evidence gaps for a network candidate",
        description="Analyze what evidence is present vs. missing for a network "
        "candidate. This is passive analysis — no active validation is performed. "
        "Distinguishes OBSERVED, NOT_OBSERVED, NOT_COLLECTED, NEGATIVE_EVIDENCE, "
        "and NOT_APPLICABLE.",
    )
    gaps_cmd.add_argument(
        "network",
        help="network CIDR to analyze (e.g., 10.50.0.0/16)",
    )
    _add_output_args(gaps_cmd)
    _add_ssh_args(gaps_cmd)

    # Standalone network explanation: explain why a network is a candidate.
    explain_cmd = sub.add_parser(
        "explain",
        help="explain a network candidate from current evidence",
        description="Explain a network using current discovery evidence. "
        "Shows observed evidence, inferred context, transit assessment, "
        "priority, and limitations. Optionally attaches baseline comparison context.",
    )
    explain_cmd.add_argument(
        "network",
        help="network CIDR to explain (e.g., 10.50.0.0/16)",
    )
    explain_cmd.add_argument(
        "--baseline",
        metavar="NAME",
        help="attach comparison context relative to a saved baseline "
        "(loads the baseline, performs one current discovery, and reports "
        "how the network relates to the saved perspective)",
    )
    _add_output_args(explain_cmd)
    _add_ssh_args(explain_cmd)

    # Active reachability validation: one explicit target, explicit ports.
    check = sub.add_parser(
        "check",
        help="validate TCP reachability of one explicit target",
        description="Attempt a controlled TCP connection to an operator-"
        "selected host and classify the result precisely. This is NOT a "
        "scanner: ports must be listed explicitly and ranges are rejected.",
    )
    check.add_argument("target", help="IP address or hostname to validate")
    check.add_argument(
        "--port",
        required=True,
        help="explicit TCP port(s), comma-separated (e.g. 445 or 445,3389). "
        "Ranges are deliberately not supported.",
    )
    check.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="connection timeout in seconds (default: 3, max 30)",
    )
    check.add_argument(
        "--baseline",
        metavar="NAME",
        help="attach comparison context relative to a saved baseline "
        "(loads the baseline, performs one current discovery, and reports "
        "how the target's network relates to the saved perspective)",
    )
    check.add_argument(
        "--protocol",
        choices=["tcp", "ssh", "smb", "winrm"],
        default="tcp",
        help="validation protocol: tcp (default) performs one explicit "
        "TCP connection per listed port; ssh performs one public-key "
        "authentication attempt against one target:port using a "
        "credential supplied via --ssh-key-env; smb performs one NTLM "
        "session-setup attempt against one target:port using a "
        "credential supplied via --credential-env; winrm performs one "
        "WS-Man authentication attempt against one target:port using a "
        "credential supplied via --credential-env",
    )
    check.add_argument(
        "--winrm-user",
        help="WinRM username (winrm protocol only; defaults to the "
        "current OS user)",
    )
    check.add_argument(
        "--winrm-transport",
        choices=["http", "https"],
        default="http",
        help="WinRM transport scheme (winrm protocol only; default http). "
        "HTTPS verifies server certificates and never silently downgrades.",
    )
    check.add_argument(
        "--ssh-user",
        help="SSH username (SSH protocol only; defaults to the current "
        "OS user, matching ssh client behavior)",
    )
    check.add_argument(
        "--ssh-key-env",
        metavar="VARIABLE",
        help="environment variable holding SSH private-key material "
        "(SSH protocol only; required for --protocol ssh). The value is "
        "never printed, logged, or persisted.",
    )
    check.add_argument(
        "--credential-env",
        metavar="VARIABLE",
        help="environment variable holding SMB password material "
        "(SMB protocol only; required for --protocol smb). The value is "
        "never printed, logged, or persisted.",
    )
    check.add_argument(
        "--smb-user",
        help="SMB username (SMB protocol only; defaults to the current "
        "OS user)",
    )
    check.add_argument(
        "--ssh-accept-new-hostkeys",
        action="store_true",
        help="SSH protocol only: trust first-contact host keys "
        "(trust-on-first-use); changed keys are still rejected. "
        "Default: strict known_hosts verification.",
    )
    _add_output_args(check)

    # SOCKS5 proxy-path validation: one explicit proxy, one explicit
    # destination, single port (MVP contract — lists/ranges out of scope).
    proxy_check = sub.add_parser(
        "proxy-check",
        help="validate a SOCKS5 proxy path to one explicit destination",
        description="Attempt a controlled SOCKS5 CONNECT through an "
        "operator-supplied proxy to one operator-supplied destination "
        "host:port and classify each stage precisely. This is NOT a "
        "scanner and NOT proxy discovery: one proxy, one destination, "
        "one port, one attempt.",
    )
    proxy_check.add_argument(
        "--proxy",
        required=True,
        metavar="URL",
        help="SOCKS5 proxy endpoint, socks5://host:port or "
        "socks5://user:pass@host:port (credentials are redacted in all "
        "output)",
    )
    proxy_check.add_argument(
        "target",
        help="destination IP or hostname (hostnames are resolved by the "
        "proxy, not locally)",
    )
    proxy_check.add_argument(
        "--port",
        required=True,
        help="single explicit destination TCP port (e.g. 443). Ranges "
        "and lists are deliberately not supported.",
    )
    proxy_check.add_argument(
        "--timeout",
        type=float,
        default=3.0,
        help="connection timeout in seconds (default: 3, max 30)",
    )
    proxy_check.add_argument(
        "--proxy-auth-env",
        metavar="ENV_NAME",
        help="environment variable name containing the proxy password; "
        "username is taken from --proxy URL (socks5://user@host:port). "
        "Mutually exclusive with inline password in --proxy URL.",
    )
    _add_output_args(proxy_check)

    baseline = sub.add_parser("baseline", help="create and manage saved perspectives")
    baseline_sub = baseline.add_subparsers(dest="baseline_command")
    create = baseline_sub.add_parser("create", help="discover and save a baseline")
    create.add_argument("--name", required=True, help="baseline identifier")
    create.add_argument(
        "--force", action="store_true", help="atomically replace an existing baseline"
    )
    _add_ssh_args(create)
    listing = baseline_sub.add_parser("list", help="list saved baselines")
    _add_output_args(listing)
    show = baseline_sub.add_parser("show", help="show one saved baseline")
    show.add_argument("name")
    _add_output_args(show)
    delete = baseline_sub.add_parser("delete", help="delete one saved baseline")
    delete.add_argument("name")
    delete.add_argument("--yes", action="store_true", help="confirm deletion")

    comparison = sub.add_parser(
        "compare", help="compare current discovery with a saved baseline"
    )
    comparison.add_argument("baseline", help="saved baseline identifier")
    _add_output_args(comparison)
    _add_filter_args(comparison, changes_only=True, minimum_confidence=True)

    opsec_cmd = sub.add_parser(
        "opsec",
        help="describe the likely observability of an explicit validation action",
        description=(
            "Predictive OPSEC analysis: describes the telemetry an explicit "
            "validation action is reasonably expected to produce on a "
            "platform. This is NOT observed telemetry from a target and "
            "provides no evasion guidance."
        ),
    )
    opsec_cmd.add_argument(
        "--action",
        required=True,
        help="the action to analyze: ssh-auth, smb-auth, winrm-auth, "
        "tcp-connect, socks5-connect",
    )
    opsec_cmd.add_argument(
        "--platform",
        required=True,
        help="platform where telemetry is expected: windows, linux, macos",
    )
    _add_output_args(opsec_cmd)

    # Comparison views are deliberately mutually exclusive: each answers a
    # different operator question. Filters (--interface/--family/etc.)
    # compose with any view.
    views = comparison.add_mutually_exclusive_group()
    views.add_argument(
        "--summary",
        action="store_true",
        help="show a concise change summary instead of full detail",
    )
    views.add_argument(
        "--evidence",
        action="store_true",
        help="show the evidence behind every reported change",
    )
    views.add_argument(
        "--recommend",
        action="store_true",
        help="show deterministic rule-based next-step recommendations",
    )
    views.add_argument(
        "--explain",
        metavar="NETWORK",
        help="explain one network (CIDR or IP inside it) in full detail",
    )

    comparison.add_argument(
        "--output",
        metavar="PATH",
        help="write the JSON result artifact to PATH (requires JSON format)",
    )
    comparison.add_argument(
        "--force",
        action="store_true",
        help="allow --output to replace an existing file",
    )

    return parser


def _add_filter_args(
    sub_parser: argparse.ArgumentParser,
    *,
    focus: bool = False,
    changes_only: bool = False,
    show_pivots: bool = False,
    minimum_confidence: bool = False,
) -> None:
    """Attach presentation-only filters; they never alter discovery data."""
    sub_parser.add_argument(
        "--interface",
        metavar="IFACE",
        help="restrict output to evidence associated with this interface "
        "(entries without interface metadata are retained)",
    )
    sub_parser.add_argument(
        "--family",
        choices=["ipv4", "ipv6", "all"],
        default="all",
        help="address family filter (default: all)",
    )
    if focus:
        sub_parser.add_argument(
            "--focus",
            metavar="NETWORK",
            help="prioritize one network (CIDR, or an IP inside it)",
        )
    if changes_only:
        sub_parser.add_argument(
            "--changes-only",
            action="store_true",
            help="hide unchanged entries; show only differences",
        )
    if show_pivots:
        sub_parser.add_argument(
            "--show-pivots",
            action="store_true",
            help="show ONLY inferred pivot context (routing evidence, never confirmed)",
        )
    if minimum_confidence:
        sub_parser.add_argument(
            "--minimum-confidence",
            choices=["low", "medium", "high"],
            help="hide entries below this confidence level",
        )


def _add_ssh_args(sub_parser: argparse.ArgumentParser) -> None:
    """Explicit remote vantage-point selection; never required for local use."""
    ssh = sub_parser.add_mutually_exclusive_group()
    ssh.add_argument(
        "--ssh",
        metavar="HOST",
        help="collect discovery from a remote host over SSH instead of "
        "locally. Authentication uses your existing SSH agent/keys/config.",
    )
    ssh.add_argument(
        "--ssh-user",
        metavar="USER@HOST",
        help="like --ssh but with an explicit remote user",
    )
    sub_parser.add_argument("--ssh-port", type=int, help="remote SSH port")
    sub_parser.add_argument(
        "--ssh-key", help="path reference passed to ssh -i (never stored)"
    )
    sub_parser.add_argument(
        "--ssh-timeout",
        type=float,
        default=10.0,
        help="SSH connect timeout in seconds (default: 10, max 60)",
    )
    sub_parser.add_argument(
        "--ssh-accept-new-hostkeys",
        action="store_true",
        help="trust first-contact host keys (changed keys are still "
        "rejected). Default: strict verification against known_hosts.",
    )


def _ssh_provider(args: argparse.Namespace):
    """Build an SSHProvider from validated CLI input.

    Returns ``(provider, error_code)``: ``provider`` is None for local
    collection; ``error_code`` is non-zero when CLI input was invalid.
    """
    host = getattr(args, "ssh", None)
    user = None
    if not host:
        combined = getattr(args, "ssh_user", None)
        if not combined:
            return None, None
        if "@" not in combined:
            print("[-] --ssh-user requires USER@HOST form.", file=sys.stderr)
            return None, EXIT_USAGE
        user, _, host = combined.rpartition("@")
    try:
        config = SSHConfig(
            host=host,
            port=getattr(args, "ssh_port", None) or 22,
            user=user or None,
            connect_timeout=getattr(args, "ssh_timeout", 10.0),
            key_file=getattr(args, "ssh_key", None),
            host_key_policy=(
                HostKeyPolicy.ACCEPT_NEW
                if getattr(args, "ssh_accept_new_hostkeys", False)
                else HostKeyPolicy.STRICT
            ),
        )
    except SSHConfigError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return None, EXIT_USAGE
    return SSHProvider(config), None


def _run_discovery_for(
    args: argparse.Namespace,
) -> tuple[DiscoverySnapshot | None, int | None]:
    """Returns ``(snapshot, error_code)``; exactly one element is None."""
    provider, error = _ssh_provider(args)
    if error is not None:
        return None, error
    try:
        snapshot = run_discovery(provider) if provider else run_discovery()
    except Exception as exc:  # noqa: BLE001 - discovery error boundary
        print("[-] Unable to perform network discovery.", file=sys.stderr)
        print(f"    Reason: {exc}", file=sys.stderr)
        return None, EXIT_FATAL
    return snapshot, None


def _query_options(args: argparse.Namespace) -> QueryOptions:
    return QueryOptions(
        interface=getattr(args, "interface", None),
        family=getattr(args, "family", "all"),
        focus=getattr(args, "focus", None),
        changes_only=getattr(args, "changes_only", False),
        minimum_confidence=getattr(args, "minimum_confidence", None),
    )


def _has_filters(options: QueryOptions) -> bool:
    return (
        options.interface is not None
        or options.family != "all"
        or options.focus is not None
        or options.changes_only
        or options.minimum_confidence is not None
    )


def _add_output_args(sub_parser: argparse.ArgumentParser) -> None:
    group = sub_parser.add_mutually_exclusive_group()
    group.add_argument(
        "--format",
        choices=["text", "json"],
        # None (not "text") so that an explicit --format is always
        # distinguishable from the default: argparse's mutual-exclusion
        # check compares by identity against the default, and a shared
        # interned "text" string would make conflict detection depend on
        # the CPython version. main() normalizes None back to "text".
        default=None,
        help="output format (default: text)",
    )
    group.add_argument(
        "--json",
        action="store_true",
        help="shorthand for --format json",
    )


def _parse_ports(port_arg: str) -> list[int] | None:
    """Parse comma-separated explicit ports. Returns None on invalid input."""
    ports: list[int] = []
    for token in port_arg.split(","):
        token = token.strip()
        if not token.isdigit():
            return None  # rejects negatives, ranges ('445-446'), floats
        try:
            ports.append(validate_port(int(token)))
        except ValueError:
            return None
    if not ports or len(ports) > 16:
        return None  # hard cap keeps this far away from scanner territory
    return ports


def _load_baseline_for_check(args: argparse.Namespace):
    """Load the requested baseline for contextual check.

    Returns ``(stored, error_code)``; exactly one element is None.
    The baseline is loaded BEFORE any discovery or socket activity so a
    missing/invalid baseline fails explicitly rather than silently
    performing an uncontextualized check.
    """
    store = BaselineStore(args.data_dir)
    try:
        return store.load(args.baseline), None
    except BaselineNotFoundError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return None, EXIT_BASELINE_NOT_FOUND
    except BaselineSchemaError as exc:
        print(f"[-] Unsupported or invalid baseline: {exc}", file=sys.stderr)
        return None, EXIT_BASELINE_SCHEMA


def _run_check(args: argparse.Namespace) -> int:
    """Execute a controlled reachability check. Returns a process exit code."""
    if getattr(args, "protocol", "tcp") == "ssh":
        return _run_check_ssh(args)
    if getattr(args, "protocol", "tcp") == "smb":
        return _run_check_smb(args)
    if getattr(args, "protocol", "tcp") == "winrm":
        return _run_check_winrm(args)
    ports = _parse_ports(args.port)
    if ports is None:
        print("[-] Invalid --port value.", file=sys.stderr)
        print(
            "    Provide explicit port(s) only, e.g. --port 445 or --port 445,3389.",
            file=sys.stderr,
        )
        print(
            "    Ranges and service lists are deliberately not supported.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    try:
        timeout_s = validate_timeout(args.timeout)
    except ValueError as exc:
        print(f"[-] Invalid --timeout: {exc}", file=sys.stderr)
        return EXIT_USAGE

    # If the operator explicitly requested contextual baseline analysis,
    # load the baseline BEFORE any discovery or socket activity. A missing
    # or invalid baseline fails explicitly rather than silently performing
    # an uncontextualized check.
    stored = None
    if getattr(args, "baseline", None):
        stored, error = _load_baseline_for_check(args)
        if error is not None:
            return error

    resolved = resolve_target(args.target)
    if resolved.error is not None and not resolved.ok:
        status = (
            CheckStatus.INVALID_TARGET
            if "invalid" in resolved.error.lower()
            else CheckStatus.DNS_ERROR
        )
        report = CheckReport(
            target=args.target,
            resolved_addresses=(),
            ports=tuple(ports),
            timeout_s=timeout_s,
            results=(
                CheckResult(
                    target=args.target,
                    address=args.target,
                    port=ports[0],
                    status=status,
                    error=resolved.error,
                ),
            ),
        )
        stream: TextIO = sys.stdout
        if args.format == "json" or args.json:
            render_check_json(report, stream)
        else:
            color = should_use_color(sys.stdout, args.no_color)
            render_check(report, stream, color=color)
        return EXIT_RESOLVE

    # Route context comes from discovery evidence when available; absence of
    # evidence never blocks a check. When --baseline is used, the SAME
    # snapshot feeds route context, network relationship, comparison, and
    # priority association — no duplicate discovery.
    try:
        snapshot = run_discovery()
    except Exception:  # noqa: BLE001 - check degrades to no-context, never crashes
        snapshot = DiscoverySnapshot(hostname="", os_name="", networks=())

    # Build comparison + recommendations from the same snapshot when a
    # baseline was requested.
    comparison_report: DiffReport | None = None
    recommendations: tuple[Recommendation, ...] = ()
    if stored is not None:
        current = baseline_from_snapshot(snapshot)
        comparison_report = compare(stored.baseline, current)
        recommendations = recommend(snapshot, comparison_report)

    # The report carries ONE validation context, keyed to the primary
    # (first) resolved address — the same address whose route context the
    # renderer surfaces. Building it per-address inside the loop below would
    # let a multi-address (dual-stack) target silently overwrite it with the
    # LAST address's context, so it is computed exactly once here.
    validation_context = None
    if stored is not None and resolved.addresses:
        validation_context = build_validation_context(
            resolved.addresses[0],
            snapshot,
            report=comparison_report,
            baseline_name=stored.name,
            recommendations=recommendations,
        )

    results: list[CheckResult] = []
    for address in resolved.addresses:
        route_ctx = context_from_snapshot(address, snapshot)
        for port in ports:
            results.append(check_tcp(address, port, timeout_s, target=args.target))
            results[-1] = CheckResult(
                target=results[-1].target,
                address=results[-1].address,
                port=results[-1].port,
                protocol=results[-1].protocol,
                status=results[-1].status,
                elapsed_ms=results[-1].elapsed_ms,
                error=results[-1].error,
                route_context=route_ctx,
            )

    # Evidence provenance fields
    import socket as _socket
    import uuid
    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).isoformat()
    perspective_hostname = _socket.gethostname()
    perspective_session_id = uuid.uuid4().hex[:16]

    report_model = CheckReport(
        target=args.target,
        resolved_addresses=resolved.addresses,
        ports=tuple(ports),
        timeout_s=timeout_s,
        results=tuple(results),
        validation_context=validation_context,
        command="check",
        timestamp=timestamp,
        perspective_hostname=perspective_hostname,
        perspective_session_id=perspective_session_id,
    )
    stream = sys.stdout
    if args.format == "json" or args.json:
        render_check_json(report_model, stream)
    else:
        color = should_use_color(sys.stdout, args.no_color)
        render_check(report_model, stream, color=color)
    return EXIT_OK


def _parse_single_port(port_arg: str) -> int | None:
    """Parse exactly one explicit destination port.

    proxy-check MVP contract: one destination, one port. Lists and ranges
    are deliberately NOT routed through the ``check`` command's port-list
    parser — the MVP scope is a single CONNECT attempt.
    """
    token = port_arg.strip()
    if not token.isdigit():
        return None  # rejects negatives, ranges ('443-8443'), lists, floats
    try:
        return validate_port(int(token))
    except ValueError:
        return None


def _run_check_ssh(args: argparse.Namespace) -> int:
    """Execute ONE SSH public-key authentication validation.

    Exit codes mirror the documented check contract:
        0 — validation executed; AUTHENTICATED / AUTH_FAILED / TIMEOUT /
            HOST_KEY_UNVERIFIED are data, not CLI failures
        1 — fatal internal/local execution failure
        2 — invalid CLI usage (port, timeout, missing/invalid env var)
        3 — target could not be resolved
    """
    if getattr(args, "baseline", None):
        print(
            "[-] --baseline is not supported for --protocol ssh: baseline "
            "comparison is passive-topology context and does not apply to "
            "an active authentication attempt.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    port = _parse_single_port(args.port)
    if port is None:
        print("[-] Invalid --port value for SSH validation.", file=sys.stderr)
        print(
            "    SSH validation is one target, one port: --port 22 (or one "
            "explicit port). Lists and ranges are deliberately not supported.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    try:
        timeout_s = validate_timeout(args.timeout)
    except ValueError as exc:
        print(f"[-] Invalid --timeout: {exc}", file=sys.stderr)
        return EXIT_USAGE

    env_name = getattr(args, "ssh_key_env", None)
    if not env_name:
        print(
            "[-] --protocol ssh requires --ssh-key-env VARIABLE holding the "
            "private-key material (command-line key material is deliberately "
            "not accepted; command lines are observable to other users).",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if not _validate_env_var_name(env_name):
        print(f"[-] Invalid environment variable name: {env_name!r}", file=sys.stderr)
        return EXIT_USAGE

    from pivotcheck.utils.credential_loader import CredentialLoadError, load_credential

    username = args.ssh_user or getpass.getuser()
    try:
        credential = load_credential(CredentialType.SSH_PRIVATE_KEY, env_name, username=username)
    except CredentialLoadError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_USAGE

    host = args.target

    connect_timeout = min(timeout_s, 60.0)
    try:
        config = SSHConfig(
            host=host,
            port=port,
            user=username,
            connect_timeout=connect_timeout,
            command_timeout=timeout_s,
            host_key_policy=(
                HostKeyPolicy.ACCEPT_NEW if args.ssh_accept_new_hostkeys else HostKeyPolicy.STRICT
            ),
        )
    except SSHConfigError as exc:
        # Message carries the invalid host string, never credential material.
        print(f"[-] Invalid SSH target: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        result = validate_ssh_auth(config, credential)
    except ValueError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_USAGE

    import socket as _socket
    import uuid
    from datetime import datetime, timezone

    report = SSHCheckReport(
        target=config.host,
        port=port,
        timeout_s=timeout_s,
        results=(result,),
        command="check",
        timestamp=datetime.now(timezone.utc).isoformat(),
        perspective_hostname=_socket.gethostname(),
        perspective_session_id=uuid.uuid4().hex[:16],
    )
    stream = sys.stdout
    if args.format == "json" or args.json:
        render_ssh_check_json(report, stream)
    else:
        color = should_use_color(sys.stdout, args.no_color)
        render_ssh_check(report, stream, color=color)

    if result.status in (
        SSHCheckStatus.INVALID_TARGET,
        SSHCheckStatus.DNS_ERROR,
    ):
        return EXIT_RESOLVE
    if result.status is SSHCheckStatus.LOCAL_ERROR:
        return EXIT_FATAL
    return EXIT_OK


def _redact_credentials(text: str) -> str:
    """Redact URL userinfo passwords from error text (defense in depth).

    parse_proxy_url error messages may embed the operator-supplied URL.
    This keeps ``socks5://user:pass@host`` shaped messages from leaking
    the password into stderr. The single authoritative redacted form is
    ``user:***@`` (matches ProxyEndpoint.display_url).
    """
    return re.sub(r"(//[^:/@\s]+:)[^@/\s]*@", r"\1***@", text)


def _validate_env_var_name(name: str) -> bool:
    """Validate POSIX environment variable name: [A-Za-z_][A-Za-z0-9_]*"""
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name))


def _get_env_password(env_name: str) -> str | None:
    """Read password from environment variable.

    Returns the password string, or None if not set/empty (caller handles errors).
    """
    return os.environ.get(env_name)


def _run_check_smb(args: argparse.Namespace) -> int:
    """Execute ONE SMB session-setup authentication validation.

    Exit codes mirror the documented check contract:
        0 — validation executed; AUTHENTICATED / AUTH_FAILED / TIMEOUT /
            PROTOCOL_ERROR are data, not CLI failures
        1 — fatal internal/local execution failure (e.g. SMB backend absent)
        2 — invalid CLI usage (port, timeout, missing/invalid env var)
        3 — target could not be resolved
    """
    from pivotcheck.checks.smb import SmbBackendUnavailable
    from pivotcheck.utils.credential_loader import CredentialLoadError, load_credential

    if getattr(args, "baseline", None):
        print(
            "[-] --baseline is not supported for --protocol smb: baseline "
            "comparison is passive-topology context and does not apply to "
            "an active authentication attempt.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    port = _parse_single_port(args.port)
    if port is None:
        print("[-] Invalid --port value for SMB validation.", file=sys.stderr)
        print(
            "    SMB validation is one target, one port: --port 445 (or one "
            "explicit port). Lists and ranges are deliberately not supported.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    try:
        timeout_s = validate_timeout(args.timeout)
    except ValueError as exc:
        print(f"[-] Invalid --timeout: {exc}", file=sys.stderr)
        return EXIT_USAGE

    env_name = getattr(args, "credential_env", None)
    if not env_name:
        print(
            "[-] --protocol smb requires --credential-env VARIABLE holding the "
            "password material (command-line credential material is deliberately "
            "not accepted; command lines are observable to other users).",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if not _validate_env_var_name(env_name):
        print(f"[-] Invalid environment variable name: {env_name!r}", file=sys.stderr)
        return EXIT_USAGE

    username = args.smb_user or getpass.getuser()
    try:
        credential = load_credential(CredentialType.PASSWORD, env_name, username=username)
    except CredentialLoadError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_USAGE

    import socket as _socket
    import uuid
    from datetime import datetime, timezone

    try:
        result = validate_smb_auth(credential, args.target, port=port, timeout=timeout_s)
    except SmbBackendUnavailable as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_FATAL
    except ValueError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_USAGE

    report = SMBCheckReport(
        target=args.target,
        port=port,
        timeout_s=timeout_s,
        results=(result,),
        command="check",
        timestamp=datetime.now(timezone.utc).isoformat(),
        perspective_hostname=_socket.gethostname(),
        perspective_session_id=uuid.uuid4().hex[:16],
    )
    stream = sys.stdout
    if args.format == "json" or args.json:
        render_smb_check_json(report, stream)
    else:
        color = should_use_color(sys.stdout, args.no_color)
        render_smb_check(report, stream, color=color)

    if result.status in (
        SMBCheckStatus.INVALID_TARGET,
        SMBCheckStatus.DNS_ERROR,
    ):
        return EXIT_RESOLVE
    if result.status is SMBCheckStatus.LOCAL_ERROR:
        return EXIT_FATAL
    return EXIT_OK


def _run_check_winrm(args: argparse.Namespace) -> int:
    """Execute ONE WinRM WS-Man authentication validation.

    Exit codes mirror the documented check contract:
        0 — validation executed; AUTHENTICATED / AUTH_FAILED / TIMEOUT /
            TLS_FAILED / PROTOCOL_ERROR are data, not CLI failures
        1 — fatal internal/local execution failure (e.g. backend absent)
        2 — invalid CLI usage (port, timeout, missing/invalid env var)
        3 — target could not be resolved
    """
    from pivotcheck.checks.winrm import WinRMBackendUnavailable
    from pivotcheck.utils.credential_loader import CredentialLoadError, load_credential

    if getattr(args, "baseline", None):
        print(
            "[-] --baseline is not supported for --protocol winrm: baseline "
            "comparison is passive-topology context and does not apply to "
            "an active authentication attempt.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    port = _parse_single_port(args.port)
    if port is None:
        print("[-] Invalid --port value for WinRM validation.", file=sys.stderr)
        print(
            "    WinRM validation is one target, one port: --port 5985 (or "
            "one explicit port). Lists and ranges are deliberately not supported.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    try:
        timeout_s = validate_timeout(args.timeout)
    except ValueError as exc:
        print(f"[-] Invalid --timeout: {exc}", file=sys.stderr)
        return EXIT_USAGE

    env_name = getattr(args, "credential_env", None)
    if not env_name:
        print(
            "[-] --protocol winrm requires --credential-env VARIABLE holding "
            "the password material (command-line credential material is "
            "deliberately not accepted; command lines are observable to "
            "other users).",
            file=sys.stderr,
        )
        return EXIT_USAGE
    if not _validate_env_var_name(env_name):
        print(f"[-] Invalid environment variable name: {env_name!r}", file=sys.stderr)
        return EXIT_USAGE

    username = args.winrm_user or getpass.getuser()
    try:
        credential = load_credential(CredentialType.PASSWORD, env_name, username=username)
    except CredentialLoadError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_USAGE

    import socket as _socket
    import uuid
    from datetime import datetime, timezone

    try:
        result = validate_winrm_auth(
            credential,
            args.target,
            port=port,
            timeout=timeout_s,
            transport_scheme=args.winrm_transport,
        )
    except WinRMBackendUnavailable as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_FATAL
    except ValueError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_USAGE

    report = WinRMCheckReport(
        target=args.target,
        port=port,
        timeout_s=timeout_s,
        results=(result,),
        command="check",
        timestamp=datetime.now(timezone.utc).isoformat(),
        perspective_hostname=_socket.gethostname(),
        perspective_session_id=uuid.uuid4().hex[:16],
    )
    stream = sys.stdout
    if args.format == "json" or args.json:
        render_winrm_check_json(report, stream)
    else:
        color = should_use_color(sys.stdout, args.no_color)
        render_winrm_check(report, stream, color=color)

    if result.status in (
        WinRMCheckStatus.INVALID_TARGET,
        WinRMCheckStatus.DNS_ERROR,
    ):
        return EXIT_RESOLVE
    if result.status is WinRMCheckStatus.LOCAL_ERROR:
        return EXIT_FATAL
    return EXIT_OK


def _run_opsec(args: argparse.Namespace) -> int:
    """Execute predictive OPSEC analysis for one action/platform pair.

    Exit codes:
        0 — analysis produced (including UNKNOWN: that is an answer)
        2 — invalid CLI usage (unknown action/platform)
    """
    from pivotcheck.analysis.opsec import assess_opsec, parse_action, parse_platform
    from pivotcheck.output.opsec import render_opsec, render_opsec_json

    try:
        action = parse_action(args.action)
        platform = parse_platform(args.platform)
    except ValueError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_USAGE

    result = assess_opsec(action, platform)
    stream = sys.stdout
    if args.format == "json" or args.json:
        render_opsec_json(result, stream)
    else:
        color = should_use_color(sys.stdout, args.no_color)
        render_opsec(result, stream, color=color)
    return EXIT_OK


def _run_proxy_check(args: argparse.Namespace) -> int:
    """Execute one operator-controlled SOCKS5 proxy-path validation.

    Exit codes:
        0 — validation executed; every outcome (REFUSED, AUTH_FAILED,
            CONNECT failure codes, VALIDATED) is DATA, not a CLI failure
        1 — fatal internal/local execution failure
        2 — invalid command-line usage (proxy URL, target, port, timeout)
        3 — the PROXY endpoint name could not be resolved (DNS_ERROR),
            mirroring the ``check`` command's resolution contract

    The destination hostname is never resolved locally: it is validated
    syntactically here and sent to the proxy with ATYP 0x03 by the engine
    (proxy-side DNS semantics). Exactly one validation attempt is made —
    no retries, no scanning, no automatic targets.
    """
    # Parse proxy URL first to get username (if any) and check for inline password
    try:
        endpoint = parse_proxy_url(args.proxy)
    except ValueError as exc:
        print(
            f"[-] Invalid --proxy URL: {_redact_credentials(str(exc))}",
            file=sys.stderr,
        )
        return EXIT_USAGE

    # Handle --proxy-auth-env credential source
    inline_has_password = endpoint.password is not None
    env_name = getattr(args, "proxy_auth_env", None)

    if env_name is not None:
        # Validate environment variable name
        if not _validate_env_var_name(env_name):
            print(
                f"[-] Invalid --proxy-auth-env name: {env_name!r}. "
                "Must be a valid POSIX identifier (e.g. PIVOTCHECK_PROXY_PASSWORD).",
                file=sys.stderr,
            )
            return EXIT_USAGE

        # Mutual exclusion: cannot have both inline password and env password
        if inline_has_password:
            print(
                "[-] Cannot use both inline password in --proxy URL and "
                "--proxy-auth-env. Use one credential source.",
                file=sys.stderr,
            )
            return EXIT_USAGE

        # Read password from environment
        env_password = _get_env_password(env_name)
        if env_password is None:
            print(
                f"[-] Environment variable {env_name!r} is not set.",
                file=sys.stderr,
            )
            return EXIT_USAGE
        if env_password == "":
            print(
                f"[-] Environment variable {env_name!r} is empty.",
                file=sys.stderr,
            )
            return EXIT_USAGE

        # Reconstruct endpoint with username from URL and password from env
        endpoint = ProxyEndpoint(
            host=endpoint.host,
            port=endpoint.port,
            username=endpoint.username,
            password=env_password,
        )

    try:
        target = validate_target(args.target)
    except ValueError as exc:
        print(f"[-] Invalid target: {exc}", file=sys.stderr)
        return EXIT_USAGE

    port = _parse_single_port(args.port)
    if port is None:
        print("[-] Invalid --port value.", file=sys.stderr)
        print(
            "    Provide exactly one explicit port, e.g. --port 443.",
            file=sys.stderr,
        )
        print(
            "    Port lists and ranges are deliberately not supported.",
            file=sys.stderr,
        )
        return EXIT_USAGE

    try:
        timeout_s = validate_timeout(args.timeout)
    except ValueError as exc:
        print(f"[-] Invalid --timeout: {exc}", file=sys.stderr)
        return EXIT_USAGE

    # One operator request -> one controlled validation attempt.
    try:
        report = check_proxy(endpoint, target, port, timeout_s)
    except ValueError as exc:
        # Defensive: all operator input is validated above, so a ValueError
        # here is a program defect (impossible model state), not a usage
        # error — hence EXIT_FATAL, not EXIT_USAGE.
        print(f"[-] proxy-check failed: {exc}", file=sys.stderr)
        return EXIT_FATAL

    # Evidence provenance fields
    import socket as _socket
    import uuid
    from datetime import datetime, timezone
    timestamp = datetime.now(timezone.utc).isoformat()
    perspective_hostname = _socket.gethostname()
    perspective_session_id = uuid.uuid4().hex[:16]

    # Reconstruct report with provenance fields (dataclass is frozen, so create new)
    report = ProxyCheckReport(
        proxy=report.proxy,
        target=report.target,
        port=report.port,
        timeout_s=report.timeout_s,
        stages=report.stages,
        verdict=report.verdict,
        timestamp=timestamp,
        perspective_hostname=perspective_hostname,
        perspective_session_id=perspective_session_id,
    )

    stream: TextIO = sys.stdout
    if args.format == "json" or args.json:
        render_proxy_check_json(report, stream)
    else:
        color = should_use_color(sys.stdout, args.no_color)
        render_proxy_check(report, stream, color=color)

    # Proxy-endpoint resolution failure mirrors `check`: exit 3. Every
    # other outcome — REFUSED, TIMEOUT, AUTH_FAILED, ruleset denial,
    # CONNECT refusal — is validation evidence, not a CLI failure.
    first = report.stages[0]
    if (
        first.stage is ProxyStageName.PROXY_TCP
        and first.status is ProxyStageStatus.DNS_ERROR
    ):
        return EXIT_RESOLVE
    return EXIT_OK


def _use_json(args: argparse.Namespace) -> bool:
    return getattr(args, "format", "text") == "json" or getattr(args, "json", False)


def _render_baseline(stored, stream: TextIO, as_json: bool) -> None:
    if as_json:
        import json

        json.dump({"name": stored.name, **stored.baseline.to_dict()}, stream, indent=2)
        stream.write("\n")
        return
    baseline = stored.baseline
    print(f"Baseline: {stored.name}", file=stream)
    print(f"Schema version: {baseline.schema_version}", file=stream)
    print(f"Created: {baseline.created_at}", file=stream)
    print(
        f"Vantage point: {baseline.vantage_point.display_name if baseline.vantage_point else 'unknown'}",
        file=stream,
    )
    print(f"Networks: {len(baseline.networks)}", file=stream)
    for network in baseline.networks:
        print(
            f"- {network.network} ({network.origin.value}, {network.confidence.value})",
            file=stream,
        )


def _run_baseline(args: argparse.Namespace) -> int:
    store = BaselineStore(args.data_dir)
    command = args.baseline_command
    if command is None:
        print("[-] Choose baseline create, list, show, or delete.", file=sys.stderr)
        return EXIT_USAGE
    try:
        if command == "create":
            snapshot, discovery_error = _run_discovery_for(args)
            if discovery_error is not None:
                return discovery_error
            assert snapshot is not None  # contract: exactly one element set
            stored = store.create(
                args.name, baseline_from_snapshot(snapshot), force=args.force
            )
            print(f"[+] Saved baseline: {stored.name}")
        elif command == "list":
            entries = store.list()
            if _use_json(args):
                import json

                json.dump(
                    {
                        "baselines": [
                            {
                                "name": item.name,
                                "created_at": item.baseline.created_at,
                                "vantage_point": item.baseline.vantage_point.to_dict()
                                if item.baseline.vantage_point
                                else None,
                            }
                            for item in entries
                        ]
                    },
                    sys.stdout,
                    indent=2,
                )
                print()
            else:
                for item in entries:
                    label = (
                        item.baseline.vantage_point.display_name
                        if item.baseline.vantage_point
                        else "unknown"
                    )
                    print(f"{item.name}\t{label}\t{item.baseline.created_at}")
        elif command == "show":
            _render_baseline(store.load(args.name), sys.stdout, _use_json(args))
        else:
            if not args.yes:
                print("[-] Refusing deletion without --yes.", file=sys.stderr)
                return EXIT_USAGE
            store.delete(args.name)
            print(f"[+] Deleted baseline: {args.name}")
    except BaselineNotFoundError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_BASELINE_NOT_FOUND
    except BaselineSchemaError as exc:
        print(f"[-] Unsupported or invalid baseline: {exc}", file=sys.stderr)
        return EXIT_BASELINE_SCHEMA
    except (BaselineNameError, BaselineExistsError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:  # noqa: BLE001 - CLI error boundary
        print(f"[-] Baseline operation failed: {exc}", file=sys.stderr)
        return EXIT_FATAL
    return EXIT_OK


def _run_compare(args: argparse.Namespace) -> int:
    store = BaselineStore(args.data_dir)
    try:
        stored = store.load(args.baseline)
    except BaselineNotFoundError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_BASELINE_NOT_FOUND
    except BaselineSchemaError as exc:
        print(f"[-] Unsupported or invalid baseline: {exc}", file=sys.stderr)
        return EXIT_BASELINE_SCHEMA

    options = _query_options(args)  # validates family/confidence/focus values
    try:
        snapshot = run_discovery()
    except Exception as exc:  # noqa: BLE001 - discovery error boundary
        print(f"[-] Unable to collect current perspective: {exc}", file=sys.stderr)
        return EXIT_FATAL
    current = baseline_from_snapshot(snapshot)
    report = compare(stored.baseline, current)

    # Presentation filtering happens after comparison; comparison semantics
    # themselves are never altered by query options.
    if _has_filters(options):
        report = filter_report(report, snapshot, options)
        snapshot = filter_snapshot(snapshot, options)

    if _use_json(args):
        document = comparison_to_dict(stored, current, report)
        if getattr(args, "evidence", False):
            document["evidence"] = _evidence_entries(report, snapshot, stored.baseline)
        if getattr(args, "recommend", False):
            document["recommendations"] = [
                item.to_dict() for item in recommend(snapshot, report)
            ]
        if getattr(args, "summary", False):
            document["summary"] = summarize_comparison(report).to_dict()
        payload = _json_text(document)
        if args.output:
            return _write_output(args, payload)
        sys.stdout.write(payload)
        return EXIT_OK

    stream: TextIO = sys.stdout
    if args.summary:
        render_summary(summarize_comparison(report), stream)
    elif args.evidence:
        _render_evidence(report, snapshot, stored.baseline, stream)
    elif args.recommend:
        render_recommendations(recommend(snapshot, report), stream)
    elif args.explain:
        return _render_explain(args.explain, snapshot, report, stored, stream)
    else:
        render_comparison(stored, current, report, stream, verbose=args.verbose)
    return EXIT_OK


def _evidence_entries(report, snapshot, baseline):
    entries = []
    seen: set[str] = set()
    for group in (
        report.new_networks,
        report.coverage_changes,
        report.specificity_changes,
        report.context_changes,
    ):
        for finding in group:
            if finding.network in seen:
                continue
            seen.add(finding.network)
            explanation = explain_network(finding.network, snapshot, report, baseline)
            entry = explanation.to_dict()
            entry["classification"] = finding.classification
            entries.append(entry)
    return entries


def _render_evidence(report, snapshot, baseline, stream) -> None:
    groups = (
        ("NEW COVERAGE OBSERVED", report.new_networks),
        (
            "COVERAGE CHANGES",
            tuple(
                item
                for item in report.coverage_changes
                if item.classification == "EXPANDED_REACHABILITY"
            ),
        ),
        (
            "REDUCED COVERAGE",
            tuple(
                item
                for item in report.coverage_changes
                if item.classification == "REDUCED_COVERAGE"
            ),
        ),
        ("MORE-SPECIFIC TOPOLOGY EVIDENCE", report.specificity_changes),
        ("ROUTE CONTEXT CHANGES", report.context_changes),
    )
    printed = False
    for title, findings in groups:
        for finding in findings:
            printed = True
            print(f"\n[+] {title}", file=stream)
            explanation = explain_network(finding.network, snapshot, report, baseline)
            render_explanation(explanation, stream)
    if not printed:
        print("NO CHANGE EVIDENCE - perspectives are equivalent.", file=stream)


def _render_explain(network_input, snapshot, report, stored, stream) -> int:
    known = [network.cidr for network in snapshot.networks]
    known += [finding.network for group in (
        report.new_networks, report.coverage_changes,
        report.specificity_changes, report.context_changes,
        report.unchanged_networks,
    ) for finding in group]
    try:
        canonical = resolve_focus_network(network_input, known)
    except ValueError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_USAGE
    explanation = explain_network(canonical, snapshot, report, stored.baseline)
    render_explanation(explanation, stream)
    return EXIT_OK


def _json_text(document: object) -> str:
    import json

    return json.dumps(document, indent=2) + "\n"


def _write_output(args: argparse.Namespace, payload: str) -> int:
    try:
        write_json_artifact(args.output, payload, force=args.force)
    except FileExistsError as exc:
        print(f"[-] {exc} (use --force to replace)", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print(f"[-] Could not write output file: {exc}", file=sys.stderr)
        return EXIT_FATAL
    print(f"[+] Result artifact written: {args.output}", file=sys.stderr)
    return EXIT_OK


def _run_map_with_baseline(args: argparse.Namespace) -> int:
    """Load comparison context, collect once, then render a map view."""
    store = BaselineStore(args.data_dir)
    try:
        stored = store.load(args.baseline)
    except BaselineNotFoundError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return EXIT_BASELINE_NOT_FOUND
    except BaselineSchemaError as exc:
        print(f"[-] Unsupported or invalid baseline: {exc}", file=sys.stderr)
        return EXIT_BASELINE_SCHEMA
    current_snapshot, discovery_error = _run_discovery_for(args)
    if discovery_error is not None:
        return discovery_error
    assert current_snapshot is not None  # contract: exactly one element set
    current = baseline_from_snapshot(current_snapshot)
    view = build_map_view(
        current_snapshot,
        baseline=stored.baseline,
        baseline_name=stored.name,
        report=compare(stored.baseline, current),
    )
    view = filter_map_view(
        view, _query_options(args), show_pivots=getattr(args, "show_pivots", False)
    )
    if _use_json(args):
        render_map_view_json(view, sys.stdout)
    else:
        render_map_view(
            view, sys.stdout, color=should_use_color(sys.stdout, args.no_color)
        )
    return EXIT_OK


def _run_next(args: argparse.Namespace) -> int:
    """Execute next-step decision support."""
    # If the operator explicitly requested contextual baseline analysis,
    # load the baseline BEFORE any discovery or socket activity. A missing
    # or invalid baseline fails explicitly rather than silently performing
    # an uncontextualized check.
    stored = None
    if getattr(args, "baseline", None):
        stored, error = _load_baseline_for_check(args)
        if error is not None:
            return error

    # Run discovery once
    try:
        snapshot = run_discovery()
    except Exception as exc:  # noqa: BLE001 - discovery error boundary
        print("[-] Unable to perform network discovery.", file=sys.stderr)
        print(f"    Reason: {exc}", file=sys.stderr)
        return EXIT_FATAL

    # Build comparison + recommendations from the same snapshot when a
    # baseline was requested.
    report: DiffReport | None = None
    recommendations: tuple[Recommendation, ...] = ()
    if stored is not None:
        current = baseline_from_snapshot(snapshot)
        report = compare(stored.baseline, current)
        recommendations = recommend(snapshot, report)

    # Get transit evidence
    transit_evidence = assess_transit_evidence(snapshot)

    # Select next investigation
    next_report = select_next_investigation(
        snapshot,
        transit_evidence=transit_evidence,
        recommendations=recommendations,
        comparison_report=report,
        baseline_name=stored.name if stored else None,
    )

    # Render output
    stream = sys.stdout
    if args.format == "json" or args.json:
        render_next_step_json(next_report, stream)
    else:
        color = should_use_color(sys.stdout, args.no_color)
        render_next_step(next_report, stream, color=color)

    return EXIT_OK


def _validate_network_argument(network: str) -> int | None:
    """Validate a network CLI argument against the canonical CIDR model.

    Returns ``None`` when the argument is valid, otherwise ``EXIT_USAGE``
    after printing the standard operator error. Validation is pure: invalid
    input fails before discovery (no filesystem, network, or subprocess
    side effects), and the original argument is passed through to analysis
    unchanged, so valid-path behavior is byte-identical.
    """
    try:
        ipaddress.ip_network(network, strict=False)
    except ValueError:
        print(f"[-] Invalid network argument: {network!r}.", file=sys.stderr)
        print(
            "    Provide a CIDR network (e.g. 10.50.0.0/16) or an IP address.",
            file=sys.stderr,
        )
        return EXIT_USAGE
    return None


def _run_gaps(args: argparse.Namespace) -> int:
    """Execute evidence gap analysis."""
    error = _validate_network_argument(args.network)
    if error is not None:
        return error

    # Run discovery once
    try:
        snapshot = run_discovery()
    except Exception as exc:  # noqa: BLE001 - discovery error boundary
        print("[-] Unable to perform network discovery.", file=sys.stderr)
        print(f"    Reason: {exc}", file=sys.stderr)
        return EXIT_FATAL

    # Analyze evidence gaps for the specified network
    gaps_report = analyze_evidence_gaps(snapshot, args.network)

    # Render output
    stream = sys.stdout
    if args.format == "json" or args.json:
        render_gaps_json(gaps_report, stream)
    else:
        color = should_use_color(sys.stdout, args.no_color)
        render_gaps(gaps_report, stream, color=color)

    return EXIT_OK


def _run_explain(args: argparse.Namespace) -> int:
    """Execute standalone network explanation."""
    error = _validate_network_argument(args.network)
    if error is not None:
        return error

    # If the operator explicitly requested contextual baseline analysis,
    # load the baseline BEFORE any discovery or socket activity. A missing
    # or invalid baseline fails explicitly rather than silently performing
    # an uncontextualized check.
    stored = None
    if getattr(args, "baseline", None):
        stored, error = _load_baseline_for_check(args)
        if error is not None:
            return error

    # Run discovery once
    try:
        snapshot = run_discovery()
    except Exception as exc:  # noqa: BLE001 - discovery error boundary
        print("[-] Unable to perform network discovery.", file=sys.stderr)
        print(f"    Reason: {exc}", file=sys.stderr)
        return EXIT_FATAL

    # Build comparison report if baseline was requested
    report: DiffReport | None = None
    if stored is not None:
        current = baseline_from_snapshot(snapshot)
        report = compare(stored.baseline, current)

    # Explain the network
    explanation = explain_network(
        args.network,
        snapshot,
        report=report,
        baseline=stored.baseline if stored else None,
    )

    # Render output
    stream = sys.stdout
    if args.format == "json" or args.json:
        import json
        json.dump(explanation.to_dict(), stream, indent=2)
        stream.write("\n")
    else:
        # Use the existing explanation renderer
        from pivotcheck.output.intelligence import render_explanation
        render_explanation(explanation, stream)

    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Normalize the --format sentinel (see _add_output_args): no explicit
    # --format means text. Done before any handler so downstream code sees
    # the documented default regardless of how parsing behaved.
    if getattr(args, "format", None) is None:
        args.format = "text"

    # Centralized encoding boundary (G3): operator-facing streams never
    # crash merely because the destination encoding cannot represent
    # decoration characters. UTF-8 streams are returned unchanged; JSON is
    # ASCII-safe and passes through byte-identically.
    sys.stdout = text_stream(sys.stdout)
    sys.stderr = text_stream(sys.stderr)

    if args.command is None:
        parser.print_help(sys.stderr)
        return EXIT_USAGE

    if args.command == "check":
        return _run_check(args)

    if args.command == "proxy-check":
        return _run_proxy_check(args)

    if args.command == "opsec":
        return _run_opsec(args)

    if args.command == "baseline":
        return _run_baseline(args)

    if args.command == "compare":
        return _run_compare(args)

    if args.command == "map" and args.baseline:
        return _run_map_with_baseline(args)

    if args.command == "next":
        return _run_next(args)

    if args.command == "gaps":
        return _run_gaps(args)

    if args.command == "explain":
        return _run_explain(args)

    use_json = _use_json(args)
    color = should_use_color(sys.stdout, args.no_color) and not use_json

    if args.verbose:
        import logging

        logging.basicConfig(
            stream=sys.stderr, level=logging.DEBUG, format="[%(levelname)s] %(message)s"
        )

    snapshot, discovery_error = _run_discovery_for(args)
    if discovery_error is not None:
        return discovery_error
    assert snapshot is not None  # contract: exactly one element set

    stream: TextIO = sys.stdout
    if args.command == "map":
        view = build_map_view(snapshot)
        view = filter_map_view(
            view, _query_options(args), show_pivots=getattr(args, "show_pivots", False)
        )
        if use_json:
            render_map_view_json(view, stream)
        else:
            render_map_view(view, stream, color=color)
    elif getattr(args, "summary", False):
        render_summary(summarize_snapshot(snapshot), stream)
    elif use_json:
        render_json(snapshot, stream)
    else:
        filtered = filter_snapshot(snapshot, _query_options(args))
        render_detailed(filtered, stream, color=color)

    return EXIT_OK


def entry_point() -> NoReturn:
    """Console-script wrapper that maps the return value to an exit code."""
    sys.exit(main())


if __name__ == "__main__":
    entry_point()