"""Active reachability checks.

Controlled, explicit validation of operator-selected targets. This package
deliberately excludes scanning behavior: one target, explicitly chosen ports,
no ranges, no sweeps.
"""

from pivotcheck.checks.context import (
    build_route_context,
    build_validation_context,
    context_from_snapshot,
    resolve_comparison_context,
    resolve_network_match,
    resolve_priority_context,
)
from pivotcheck.checks.resolver import resolve_target, validate_target
from pivotcheck.checks.ssh import validate_ssh_auth
from pivotcheck.checks.tcp import check_tcp, classify_socket_error

__all__ = [
    "build_route_context",
    "build_validation_context",
    "check_tcp",
    "classify_socket_error",
    "context_from_snapshot",
    "resolve_comparison_context",
    "resolve_network_match",
    "resolve_priority_context",
    "resolve_target",
    "validate_ssh_auth",
    "validate_target",
]