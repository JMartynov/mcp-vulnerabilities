"""Unit tests for OSV Validator multi-aspect checking."""

from __future__ import annotations

import pytest

from mcp_vulnerabilities.models import (
    AffectedPackage,
    DatabaseSpecificMcp,
    EventSpec,
    OsvVulnerability,
    PackageSpec,
    RangeSpec,
    RangeType,
    ReferenceSpec,
    ReferenceType,
)
from mcp_vulnerabilities.validator import OsvValidationError, OsvValidator


def test_validator_valid_vulnerability() -> None:
    vuln = OsvVulnerability(
        id="CVE-2025-10193",
        summary="Cypher Injection in mcp-neo4j-cypher",
        details="Detailed vulnerability analysis...",
        published="2025-01-10T12:00:00Z",
        modified="2025-01-11T12:00:00Z",
        affected=(
            AffectedPackage(
                package=PackageSpec(
                    name="mcp-neo4j-cypher",
                    ecosystem="PyPI",
                    purl="pkg:pypi/mcp-neo4j-cypher@0.1.0",
                ),
                ranges=(
                    RangeSpec(
                        type=RangeType.SEMVER,
                        events=(EventSpec(introduced="0.0.0", fixed="0.2.0"),),
                    ),
                ),
                database_specific=DatabaseSpecificMcp(
                    vulnerable_tools=("cypher_query",),
                    cwe_ids=("CWE-346",),
                    cvss_score=7.4,
                    cvss_v3_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    epss_score=0.45,
                ),
            ),
        ),
        references=(
            ReferenceSpec(
                type=ReferenceType.ADVISORY,
                url="https://github.com/ivanmartynov3t/mcp-cve-project/blob/main/cves/CVE-2025-10193.md",
            ),
        ),
    )
    errors = OsvValidator.validate(vuln)
    assert not errors
    OsvValidator.assert_valid(vuln)


def test_validator_missing_required_fields() -> None:
    vuln_dict = {
        "id": "",
        "summary": "",
        "details": "",
        "affected": [],
    }
    errors = OsvValidator.validate(vuln_dict)
    assert errors
    assert any("Failed to parse OSV dict" in e or "missing required" in e for e in errors)

    with pytest.raises(OsvValidationError):
        OsvValidator.assert_valid(vuln_dict)


def test_validator_timestamp_ordering_anomaly() -> None:
    vuln = OsvVulnerability(
        id="CVE-2025-99999",
        summary="Test vulnerability",
        details="Test details",
        published="2025-06-01T12:00:00Z",
        modified="2025-01-01T12:00:00Z",  # Published after modified!
        affected=(
            AffectedPackage(
                package=PackageSpec(name="test-pkg", ecosystem="npm"),
                ranges=(
                    RangeSpec(
                        type=RangeType.SEMVER,
                        events=(EventSpec(introduced="0.0.0"),),
                    ),
                ),
            ),
        ),
    )
    errors = OsvValidator.validate(vuln)
    assert any("Timestamp anomaly" in e for e in errors)


def test_validator_invalid_cvss_and_cwe_and_purl() -> None:
    vuln = OsvVulnerability(
        id="CVE-2025-88888",
        summary="Bad vector test",
        details="Details",
        affected=(
            AffectedPackage(
                package=PackageSpec(name="test-pkg", ecosystem="npm", purl="invalid-purl-string"),
                ranges=(
                    RangeSpec(
                        type=RangeType.SEMVER,
                        events=(EventSpec(introduced="0.0.0"),),
                    ),
                ),
                database_specific=DatabaseSpecificMcp(
                    cvss_score=15.0,  # Out of range
                    epss_score=2.0,  # Out of range
                    cvss_v3_vector="INVALID:CVSS:VECTOR",
                    cwe_ids=("cwe-346", "346"),  # Missing CWE- prefix
                ),
            ),
        ),
        references=(ReferenceSpec(type=ReferenceType.ADVISORY, url="gopher://invalid-scheme.com"),),
    )
    errors = OsvValidator.validate(vuln)
    assert any("invalid PURL format" in e for e in errors)
    assert any("cvss_score" in e for e in errors)
    assert any("epss_score" in e for e in errors)
    assert any("invalid CVSS v3 vector format" in e for e in errors)
    assert any("invalid format (expected CWE-\\d+)" in e for e in errors)
    assert any("invalid protocol" in e for e in errors)
