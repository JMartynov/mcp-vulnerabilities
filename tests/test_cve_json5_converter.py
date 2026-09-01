"""Unit tests for official CVE JSON 5.x (cvelistV5) converter."""

from __future__ import annotations

import json
from pathlib import Path

from mcp_vulnerabilities.converters.cve_json5 import CveJson5Converter
from mcp_vulnerabilities.models import RangeType, SeverityType
from mcp_vulnerabilities.validator import OsvValidator

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "osv" / "cve_json5"


def test_convert_cve_json5_neo4j() -> None:
    data = json.loads((FIXTURES_DIR / "CVE-2025-10193.json").read_text(encoding="utf-8"))
    vuln = CveJson5Converter.from_dict(data)

    assert vuln.id == "CVE-2025-10193"
    assert "DNS rebinding" in vuln.summary
    assert "cypher_query" in vuln.details
    assert vuln.published == "2025-09-11T14:05:30.592Z"
    assert vuln.modified == "2026-02-26T17:48:41.293Z"

    # Severities
    assert len(vuln.severity) == 1
    assert vuln.severity[0].type == SeverityType.CVSS_V3
    assert vuln.severity[0].score == "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N"

    # Affected
    assert len(vuln.affected) == 1
    aff = vuln.affected[0]
    assert aff.package.name == "mcp-neo4j-cypher"
    assert aff.package.ecosystem == "PyPI"
    assert aff.package.purl == "pkg:pypi/mcp-neo4j-cypher"

    assert len(aff.ranges) == 1
    assert aff.ranges[0].type == RangeType.SEMVER
    events = aff.ranges[0].events
    assert len(events) == 1
    assert events[0].introduced == "0.2.2"
    assert events[0].last_affected == "0.3.1"

    # Database specific MCP extensions
    db = aff.database_specific
    assert db.cvss_score == 7.4
    assert db.severity == "HIGH"
    assert "CWE-346" in db.cwe_ids
    assert "cypher_query" in db.vulnerable_tools

    # Zero data loss: raw container preserved
    assert vuln.database_specific["source"] == "cvelistV5"
    assert vuln.database_specific["assigner"] == "Neo4j"
    assert "raw_cve_json5" in vuln.database_specific
    assert (
        vuln.database_specific["raw_cve_json5"]["affected"][0]["product"]
        == "neo4j-cypher MCP server"
    )

    # Validator checks
    OsvValidator.assert_valid(vuln)


def test_convert_cve_json5_mcp_remote() -> None:
    data = json.loads((FIXTURES_DIR / "CVE-2025-6514.json").read_text(encoding="utf-8"))
    vuln = CveJson5Converter.from_dict(data)

    assert vuln.id == "CVE-2025-6514"
    assert "command injection" in vuln.summary.lower()
    assert len(vuln.affected) == 1
    aff = vuln.affected[0]
    assert aff.package.name == "mcp-remote"
    assert aff.package.ecosystem == "npm"
    assert aff.package.purl == "pkg:npm/mcp-remote"
    assert aff.database_specific.cvss_score == 9.6
    assert aff.database_specific.severity == "CRITICAL"
    assert "CWE-78" in aff.database_specific.cwe_ids

    # References
    assert len(vuln.references) >= 2
    assert any("github.com" in r.url for r in vuln.references)

    OsvValidator.assert_valid(vuln)
