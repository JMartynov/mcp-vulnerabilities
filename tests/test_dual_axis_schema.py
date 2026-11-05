import pytest
from mcp_vulnerabilities.analyzers.models import (
    DualAxisSecurityAssessment,
    ProtocolTrustAssessment,
    SupplyChainHygieneAssessment,
    ProtocolTrustStatus,
    SupplyChainStatus,
    ReachabilityStatus,
)
from mcp_vulnerabilities.catalog import VersionSecurityRecord, UnifiedMcpSecurityRecord
from mcp_vulnerabilities.validator import DualAxisValidator, DualAxisValidationError

def test_dual_axis_serialization_deserialization():
    pt = ProtocolTrustAssessment(
        status=ProtocolTrustStatus.VERIFIED,
        tool_capabilities=["filesystem_read", "shell_execution"],
        prompt_injection_guard="SHIELDED",
        parameter_sanitization=True,
        findings=[{"issue": "test"}]
    )
    sc = SupplyChainHygieneAssessment(
        status=SupplyChainStatus.CLEAN,
        trivy_scanned=True,
        scan_timestamp="2023-10-01T12:00:00Z",
        vulnerability_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
        affected_packages=[{"pkg": "test"}],
        reachability=ReachabilityStatus.UNREACHABLE_TRANSITIVE,
        recommended_safe_version="1.0.1"
    )
    da = DualAxisSecurityAssessment(protocol_trust=pt, supply_chain_hygiene=sc)
    
    da_dict = da.to_dict()
    assert da_dict["protocol_trust"]["status"] == "VERIFIED"
    assert da_dict["protocol_trust"]["tool_capabilities"] == ["filesystem_read", "shell_execution"]
    assert da_dict["protocol_trust"]["prompt_injection_guard"] == "SHIELDED"
    assert da_dict["protocol_trust"]["parameter_sanitization"] is True
    assert da_dict["protocol_trust"]["findings"] == [{"issue": "test"}]

    assert da_dict["supply_chain_hygiene"]["status"] == "CLEAN"
    assert da_dict["supply_chain_hygiene"]["trivy_scanned"] is True
    assert da_dict["supply_chain_hygiene"]["scan_timestamp"] == "2023-10-01T12:00:00Z"
    assert da_dict["supply_chain_hygiene"]["vulnerability_counts"] == {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    assert da_dict["supply_chain_hygiene"]["affected_packages"] == [{"pkg": "test"}]
    assert da_dict["supply_chain_hygiene"]["reachability"] == "UNREACHABLE_TRANSITIVE"
    assert da_dict["supply_chain_hygiene"]["recommended_safe_version"] == "1.0.1"

    da_reconstructed = DualAxisSecurityAssessment.from_dict(da_dict)
    assert da_reconstructed.protocol_trust.status == ProtocolTrustStatus.VERIFIED
    assert da_reconstructed.supply_chain_hygiene.status == SupplyChainStatus.CLEAN
    assert da_reconstructed.supply_chain_hygiene.reachability == ReachabilityStatus.UNREACHABLE_TRANSITIVE

def test_default_instantiations():
    da = DualAxisSecurityAssessment()
    assert da.protocol_trust.status == ProtocolTrustStatus.VERIFIED
    assert da.protocol_trust.prompt_injection_guard == "UNGUARDED"
    assert da.protocol_trust.parameter_sanitization is False
    assert da.supply_chain_hygiene.status == SupplyChainStatus.CLEAN
    assert da.supply_chain_hygiene.trivy_scanned is False
    assert da.supply_chain_hygiene.vulnerability_counts == {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    assert da.supply_chain_hygiene.reachability == ReachabilityStatus.UNKNOWN
    
def test_enum_transitions_and_validator():
    # Valid
    da = DualAxisSecurityAssessment()
    da.protocol_trust.prompt_injection_guard = "PARTIAL"
    da.supply_chain_hygiene.status = SupplyChainStatus.CRITICAL_ATTACK_SURFACE
    assert len(DualAxisValidator.validate(da)) == 0

    # Invalid
    da_invalid = da.to_dict()
    da_invalid["protocol_trust"]["status"] = "NOT_A_REAL_STATUS"
    
    errors = DualAxisValidator.validate(da_invalid)
    assert len(errors) > 0
    assert any("not a valid ProtocolTrustStatus" in e or "Invalid ProtocolTrustStatus" in e for e in errors)
    
    with pytest.raises(DualAxisValidationError):
        DualAxisValidator.assert_valid(da_invalid)

def test_catalog_backward_compatibility():
    # Test without dual_axis_security
    v_dict = {
        "version": "1.0.0",
        "is_vulnerable": False
    }
    v = VersionSecurityRecord.from_dict(v_dict)
    assert v.dual_axis_security is None
    
    # Test with dual_axis_security
    da = DualAxisSecurityAssessment()
    v_dict["dual_axis_security"] = da.to_dict()
    v2 = VersionSecurityRecord.from_dict(v_dict)
    assert v2.dual_axis_security is not None
    assert v2.dual_axis_security.protocol_trust.status == ProtocolTrustStatus.VERIFIED

    u_dict = {
        "package_name": "test-pkg",
        "ecosystem": "npm",
        "versions": [v_dict]
    }
    u = UnifiedMcpSecurityRecord.from_dict(u_dict)
    assert u.dual_axis_security is None
    
    # Test legacy property
    u.static_risk_score = 42.0
    assert u.mcp_trust_score == 42.0

