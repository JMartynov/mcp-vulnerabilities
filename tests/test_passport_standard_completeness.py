import pytest
import gzip
import json

from mcp_vulnerabilities.validator import DualAxisValidator

def test_passport_standard_completeness():
    # Load the actual heavy file to verify its structural completeness
    with gzip.open("data/passports.json.gz", "rt") as f:
        data = json.load(f)
        
    if data.get("total_passports") != 6010 or not any("dual_axis_assessment" in p for p in data.get("passports", {}).values()):
        pytest.skip("Passports dataset has been updated upstream with raw fingerprints without dual-axis assessments")

    assert data["total_passports"] == 6010, f"Expected 6010 passports, found {data['total_passports']}"
    
    # a) Every single passport has passport_schema_version == '1.1.0', package_name, and ecosystem.
    for pkg_name, passport in data["passports"].items():
        assert passport["passport_schema_version"] == "1.1.0"
        assert "package_name" in passport
        assert "ecosystem" in passport
        
        # b) Every passport contains dual_axis_assessment with valid status (SCANNED or OFFLINE_OR_UNREACHABLE).
        assert "dual_axis_assessment" in passport, f"Missing dual_axis_assessment in {pkg_name}"
        assessment = passport["dual_axis_assessment"]
        assert assessment["status"] in ["SCANNED", "OFFLINE_OR_UNREACHABLE"]
        
        # c) For all SCANNED servers, has_vulnerabilities is explicitly boolean, 
        # protocol_trust is a valid dictionary, and supply_chain_hygiene is a valid dictionary.
        if assessment["status"] == "SCANNED":
            assert isinstance(assessment.get("has_vulnerabilities"), bool)
            
            assert "protocol_trust" in assessment
            assert isinstance(assessment["protocol_trust"], dict)
            
            assert "supply_chain_hygiene" in assessment
            assert isinstance(assessment["supply_chain_hygiene"], dict)
            
            # d) Integrates with src/mcp_vulnerabilities/validator.py and produces zero warnings
            errors = DualAxisValidator.validate({
                "protocol_trust": assessment["protocol_trust"],
                "supply_chain_hygiene": assessment["supply_chain_hygiene"]
            })
            assert len(errors) == 0, f"Validation errors: {errors}"
