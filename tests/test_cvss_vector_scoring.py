import pytest
from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher
from mcp_vulnerabilities.dedup.fusion import AdvisoryFusionEngine
from mcp_vulnerabilities.models import OsvVulnerability, SeveritySpec, DatabaseSpecificMcp

def test_extract_severity_info_vector_only():
    adv1 = {
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            }
        ]
    }
    sev, score = VulnerabilityMatcher._extract_severity_info(adv1)
    assert sev == "CRITICAL"
    assert score == 9.8

    adv2 = {
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"
            }
        ]
    }
    sev, score = VulnerabilityMatcher._extract_severity_info(adv2)
    assert sev == "MEDIUM"
    assert score == 6.8

    adv3 = {
        "severity": [
            {
                "type": "CVSS_V3",
                "score": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
            }
        ]
    }
    sev, score = VulnerabilityMatcher._extract_severity_info(adv3)
    assert sev == "MEDIUM"
    assert score == 5.5

def test_extract_severity_info_unknown_vector():
    adv = {
        "severity": [
            {
                "type": "CVSS_V4",
                "score": "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/VC:L/VI:L/VA:L"
            }
        ]
    }
    sev, score = VulnerabilityMatcher._extract_severity_info(adv)
    assert sev == "MEDIUM"

def test_extract_severity_info_unknown_format_extraction():
    adv = {
        "severity": [
            {
                "type": "CVSS_V4",
                "score": "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MPR:X/MUI:X/MS:X/MC:X/MI:X/MA:X"
            }
        ]
    }
    sev, score = VulnerabilityMatcher._extract_severity_info(adv)
    # The requirement: If vector parsing encounters an unknown/extended format, extract nominal severity based on metric indicators or conservative mapping.
    assert sev == "CRITICAL" # Assuming C:H/I:H/A:H mapped to CRITICAL

