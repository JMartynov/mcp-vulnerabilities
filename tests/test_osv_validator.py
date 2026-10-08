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

def test_deduplicator_merge_range_integrity() -> None:
    from mcp_vulnerabilities.deduplicator import OsvDeduplicator
    
    v1 = OsvVulnerability(
        id="CVE-2026-0001",
        summary="Test 1",
        details="Details 1",
        published="2026-01-01T00:00:00Z",
        modified="2026-01-01T00:00:00Z",
        affected=(
            AffectedPackage(
                package=PackageSpec(name="pkg", ecosystem="npm"),
                ranges=(
                    RangeSpec(
                        type=RangeType.SEMVER,
                        events=(
                            EventSpec(introduced="1.0.0", fixed="2.0.0"),
                        ),
                    ),
                ),
            ),
        ),
    )
    
    v2 = OsvVulnerability(
        id="CVE-2026-0002",
        summary="Test 2",
        aliases=("CVE-2026-0001",),
        details="Details 2",
        published="2026-01-01T00:00:00Z",
        modified="2026-01-01T00:00:00Z",
        affected=(
            AffectedPackage(
                package=PackageSpec(name="pkg", ecosystem="npm"),
                ranges=(
                    RangeSpec(
                        type=RangeType.SEMVER,
                        events=(
                            EventSpec(introduced="1.0.0", fixed="2.1.0"),
                        ),
                    ),
                ),
            ),
        ),
    )
    
    merged = OsvDeduplicator.deduplicate_and_merge([v1, v2])
    assert len(merged) == 1
    m = merged[0]
    
    # Validation should pass
    errors = OsvValidator.validate(m)
    assert not errors
    
    # We should have two distinct RangeSpecs or a valid OSV sequence
    aff = m.affected[0]
    assert len(aff.ranges) == 2
    
    events_list = []
    for r in aff.ranges:
        evs = [ (e.introduced, e.fixed, e.last_affected) for e in r.events ]
        events_list.append(evs)
    
    # One range will have [(1.0.0, None, None), (None, 2.0.0, None)]
    # The other will have [(1.0.0, None, None), (None, 2.1.0, None)]
    assert [('1.0.0', None, None), (None, '2.0.0', None)] in events_list
    assert [('1.0.0', None, None), (None, '2.1.0', None)] in events_list

