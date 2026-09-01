"""Unit tests for OSV v1.6.0 models, PURL utilities, and MCP security extensions."""

from __future__ import annotations

import json

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
    SeveritySpec,
    SeverityType,
    build_purl,
    parse_purl,
)


def test_osv_model_minimal_valid() -> None:
    vuln = OsvVulnerability(
        id="MCP-2025-10193",
        summary="DNS rebinding in Neo4j Cypher MCP server",
        details="Missing origin validation allows unauthorized Cypher queries.",
        affected=(
            AffectedPackage(
                package=PackageSpec(
                    name="mcp-neo4j-cypher",
                    ecosystem="PyPI",
                    purl="pkg:pypi/mcp-neo4j-cypher",
                ),
                ranges=(
                    RangeSpec(
                        type=RangeType.SEMVER,
                        events=(
                            EventSpec(introduced="0.2.2"),
                            EventSpec(fixed="0.4.0"),
                        ),
                    ),
                ),
                database_specific=DatabaseSpecificMcp(
                    cwe_ids=("CWE-346",),
                    owasp_mcp_category="MCP07 - Insufficient Authentication & Authorization",
                    epss_score=0.00032,
                    cvss_score=7.4,
                    severity="HIGH",
                    vulnerable_tools=("cypher_query",),
                    remediation_guidance="Upgrade to v0.4.0 or run in stdio mode.",
                ),
            ),
        ),
        references=(
            ReferenceSpec(
                type=ReferenceType.ADVISORY, url="https://nvd.nist.gov/vuln/detail/CVE-2025-10193"
            ),
            ReferenceSpec(type=ReferenceType.WEB, url="https://neo4j.com/security/cve-2025-10193"),
        ),
    )

    data = vuln.to_dict()
    assert data["schema_version"] == "1.6.0"
    assert data["id"] == "MCP-2025-10193"
    assert len(data["affected"]) == 1
    assert data["affected"][0]["package"]["name"] == "mcp-neo4j-cypher"
    assert data["affected"][0]["database_specific"]["cwe_ids"] == ["CWE-346"]
    assert data["affected"][0]["database_specific"]["severity"] == "HIGH"
    assert data["affected"][0]["database_specific"]["epss_score"] == 0.00032
    assert data["affected"][0]["database_specific"]["vulnerable_tools"] == ["cypher_query"]

    # Canonical JSON roundtrip
    json_str = vuln.to_json()
    loaded = json.loads(json_str)
    assert loaded["id"] == "MCP-2025-10193"
    reconstructed = OsvVulnerability.from_dict(loaded)
    assert reconstructed.id == vuln.id
    assert reconstructed.summary == vuln.summary
    assert reconstructed.affected[0].database_specific.cwe_ids == ("CWE-346",)


def test_osv_model_requires_mandatory_fields() -> None:
    with pytest.raises(ValueError):
        OsvVulnerability(id="", summary="S", details="D")
    with pytest.raises(ValueError):
        OsvVulnerability(id="MCP-1", summary="", details="D")
    with pytest.raises(ValueError):
        OsvVulnerability(id="MCP-1", summary="S", details="")


def test_purl_utilities() -> None:
    # npm scoped package
    purl = build_purl("npm", "@modelcontextprotocol/server-postgres", "0.6.1")
    assert purl == "pkg:npm/%40modelcontextprotocol/server-postgres@0.6.1"
    eco, name, ver = parse_purl(purl)
    assert eco == "npm"
    assert name == "@modelcontextprotocol/server-postgres"
    assert ver == "0.6.1"

    # PyPI package
    purl_pypi = build_purl("pypi", "mcp-server-sqlite", "0.1.2")
    assert purl_pypi == "pkg:pypi/mcp-server-sqlite@0.1.2"
    eco2, name2, ver2 = parse_purl(purl_pypi)
    assert eco2 == "pypi"
    assert name2 == "mcp-server-sqlite"
    assert ver2 == "0.1.2"

    # PackageSpec canonical purl generation
    pkg = PackageSpec(name="@modelcontextprotocol/server-filesystem", ecosystem="npm")
    assert pkg.canonical_purl() == "pkg:npm/%40modelcontextprotocol/server-filesystem"


def test_severity_and_database_specific_extensions() -> None:
    sev = SeveritySpec(
        type=SeverityType.CVSS_V3,
        score="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H",
    )
    assert sev.score.startswith("CVSS:3.1")

    db_mcp = DatabaseSpecificMcp(
        vulnerable_tools=("execute_query", "delete_records"),
        cwe_ids=("CWE-89", "CWE-862"),
        cvss_score=9.8,
        severity="CRITICAL",
        verity_condition_id="LITE-MONGO-TENANT-001",
    )
    assert db_mcp.severity == "CRITICAL"
    assert "execute_query" in db_mcp.vulnerable_tools
    assert db_mcp.verity_condition_id == "LITE-MONGO-TENANT-001"
