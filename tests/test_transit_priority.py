"""Unit tests for transit priority assessment."""

from dataclasses import FrozenInstanceError

import pytest

from pivotcheck.analysis.transit_priority import (
    TransitPriority,
    assess_transit_priority,
)
from pivotcheck.models.check import (
    TransitEvidence,
    TransitEvidenceAssessment,
)


def make_evidence(
    assessment: TransitEvidenceAssessment,
    **kwargs
) -> TransitEvidence:
    """Create a TransitEvidence with the given assessment and optional overrides.
    
    Note: The TransitEvidence model validates that the assessment matches the evidence fields.
    This helper creates evidence that is consistent with the given assessment.
    """
    # Base defaults that are valid for ROUTING_ONLY
    defaults = {
        "source_interface": "eth0",
        "gateway": "10.10.10.1",
        "destination_network": "10.50.0.0/16",
        "address_family": 4,
        "route_present": True,
        "route_metric": 100,
        "route_type": "static",
        "neighbor_observed": False,
        "neighbor_state": None,
        "neighbor_mac": None,
        "tcp_connections_to_gateway": 0,
        "tcp_connection_states": (),
        "udp_flows_to_gateway": 0,
        "has_listen_on_gateway": False,
        "has_loopback_to_gateway": False,
        "assessment": TransitEvidenceAssessment.ROUTING_ONLY,
    }
    
    # Override with assessment-specific evidence
    if assessment == TransitEvidenceAssessment.ROUTING_ONLY:
        pass  # Use defaults
    elif assessment == TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE:
        defaults.update({
            "neighbor_observed": True,
            "neighbor_state": "REACHABLE",
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_TCP_EVIDENCE:
        defaults.update({
            "tcp_connections_to_gateway": 1,
            "tcp_connection_states": ("ESTABLISHED",),
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_UDP_EVIDENCE:
        defaults.update({
            "udp_flows_to_gateway": 1,
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE:
        defaults.update({
            "tcp_connections_to_gateway": 0,
            "tcp_connection_states": ("TIME_WAIT",),
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS:
        defaults.update({
            "neighbor_observed": True,
            "neighbor_state": "REACHABLE",
            "tcp_connections_to_gateway": 1,
            "tcp_connection_states": ("ESTABLISHED",),
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS_STALE_L2:
        defaults.update({
            "neighbor_observed": True,
            "neighbor_state": "STALE",
            "tcp_connections_to_gateway": 1,
            "tcp_connection_states": ("ESTABLISHED",),
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.ROUTING_WITH_NEGATIVE_L2_EVIDENCE:
        defaults.update({
            "neighbor_observed": True,
            "neighbor_state": "FAILED",
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.CONTRADICTORY_EVIDENCE:
        defaults.update({
            "neighbor_observed": True,
            "neighbor_state": "FAILED",
            "tcp_connections_to_gateway": 1,
            "tcp_connection_states": ("ESTABLISHED",),
            "assessment": assessment,
        })
    elif assessment == TransitEvidenceAssessment.INSUFFICIENT_EVIDENCE:
        # This assessment is for when there's no route evidence at all
        defaults.update({
            "route_present": False,
            "assessment": assessment,
        })
    else:
        # For any other assessment, use ROUTING_ONLY as base
        pass
    
    defaults.update(kwargs)
    return TransitEvidence(**defaults)


class TestTransitPriorityAssessment:
    """Test the transit priority assessment function."""

    def test_routing_only_is_low(self):
        """ROUTING_ONLY should be LOW priority."""
        evidence = make_evidence(TransitEvidenceAssessment.ROUTING_ONLY)
        result = assess_transit_priority(evidence)
        assert result.priority == "LOW"
        assert "routing or historical evidence" in result.reason.lower()

    def test_routing_plus_historical_tcp_is_low(self):
        """ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE should be LOW priority."""
        evidence = make_evidence(TransitEvidenceAssessment.ROUTING_PLUS_HISTORICAL_TCP_EVIDENCE)
        result = assess_transit_priority(evidence)
        assert result.priority == "LOW"

    def test_routing_plus_l2_evidence_is_medium(self):
        """ROUTING_PLUS_L2_EVIDENCE should be MEDIUM priority."""
        evidence = make_evidence(TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE)
        result = assess_transit_priority(evidence)
        assert result.priority == "MEDIUM"
        assert "single strong evidence type" in result.reason.lower()

    def test_routing_plus_active_tcp_is_medium(self):
        """ROUTING_PLUS_ACTIVE_TCP_EVIDENCE should be MEDIUM priority."""
        evidence = make_evidence(TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_TCP_EVIDENCE)
        result = assess_transit_priority(evidence)
        assert result.priority == "MEDIUM"

    def test_routing_plus_active_udp_is_medium(self):
        """ROUTING_PLUS_ACTIVE_UDP_EVIDENCE should be MEDIUM priority."""
        evidence = make_evidence(TransitEvidenceAssessment.ROUTING_PLUS_ACTIVE_UDP_EVIDENCE)
        result = assess_transit_priority(evidence)
        assert result.priority == "MEDIUM"

    def test_multiple_supporting_signals_is_high(self):
        """MULTIPLE_SUPPORTING_SIGNALS should be HIGH priority."""
        evidence = make_evidence(TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS)
        result = assess_transit_priority(evidence)
        assert result.priority == "HIGH"
        assert "multiple independent observations" in result.reason.lower()

    def test_multiple_supporting_signals_stale_l2_is_high(self):
        """MULTIPLE_SUPPORTING_SIGNALS_STALE_L2 should be HIGH priority."""
        evidence = make_evidence(TransitEvidenceAssessment.MULTIPLE_SUPPORTING_SIGNALS_STALE_L2)
        result = assess_transit_priority(evidence)
        assert result.priority == "HIGH"

    def test_routing_with_negative_l2_evidence_is_none(self):
        """ROUTING_WITH_NEGATIVE_L2_EVIDENCE should be NONE priority."""
        evidence = make_evidence(TransitEvidenceAssessment.ROUTING_WITH_NEGATIVE_L2_EVIDENCE)
        result = assess_transit_priority(evidence)
        assert result.priority == "NONE"
        assert "negative or contradictory" in result.reason.lower()

    def test_contradictory_evidence_is_none(self):
        """CONTRADICTORY_EVIDENCE should be NONE priority."""
        evidence = make_evidence(TransitEvidenceAssessment.CONTRADICTORY_EVIDENCE)
        result = assess_transit_priority(evidence)
        assert result.priority == "NONE"

    def test_insufficient_evidence_is_none(self):
        """INSUFFICIENT_EVIDENCE should be NONE priority."""
        evidence = make_evidence(TransitEvidenceAssessment.INSUFFICIENT_EVIDENCE)
        result = assess_transit_priority(evidence)
        assert result.priority == "NONE"

    def test_evidence_summary_included(self):
        """Evidence summary should be included in result."""
        evidence = make_evidence(
            TransitEvidenceAssessment.ROUTING_PLUS_L2_EVIDENCE,
            neighbor_observed=True,
            neighbor_state="REACHABLE",
            tcp_connections_to_gateway=1,
        )
        result = assess_transit_priority(evidence)
        assert "neighbor:REACHABLE" in result.evidence_summary
        assert "tcp:1" in result.evidence_summary
        assert "route" in result.evidence_summary

    def test_evidence_summary_empty_when_none(self):
        """Evidence summary should be 'none' when no evidence present."""
        # INSUFFICIENT_EVIDENCE has route_present=False, so no evidence
        evidence = make_evidence(TransitEvidenceAssessment.INSUFFICIENT_EVIDENCE)
        result = assess_transit_priority(evidence)
        assert result.evidence_summary == "none"

    def test_priority_enum_values(self):
        """TransitPriority enum should have expected values."""
        assert TransitPriority.HIGH == "HIGH"
        assert TransitPriority.MEDIUM == "MEDIUM"
        assert TransitPriority.LOW == "LOW"
        assert TransitPriority.NONE == "NONE"

    def test_result_immutability(self):
        """TransitPriorityResult should be immutable."""
        evidence = make_evidence(TransitEvidenceAssessment.ROUTING_ONLY)
        result = assess_transit_priority(evidence)
        # Should not be able to modify frozen dataclass. setattr keeps the
        # assignment dynamic so Pylance does not flag read-only attributes.
        with pytest.raises(FrozenInstanceError):
            setattr(result, "priority", TransitPriority.HIGH)  # noqa: B010 - deliberate setattr; direct assignment trips Pylance on frozen dataclasses