"""Unit tests for all OSV multi-format converters against real upstream source fixtures."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import pytest

from mcp_vulnerabilities.converters.ghsa import GhsaConverter
from mcp_vulnerabilities.converters.markdown_cve import MarkdownAdvisoryConverter
from mcp_vulnerabilities.converters.nvd import NvdConverter
from mcp_vulnerabilities.converters.osv_dev import OsvDevConverter
from mcp_vulnerabilities.converters.verity import HAVE_VERITY_CATALOG, VerityCatalogConverter

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "osv"


def test_markdown_advisory_converter_cve_2025_10193() -> None:
    path = FIXTURES_DIR / "markdown" / "CVE-2025-10193.md"
    assert path.is_file(), f"Fixture missing: {path}"

    osv = MarkdownAdvisoryConverter.from_file(path)

    assert osv.id == "CVE-2025-10193"
    assert "GHSA-vcqx-v2mg-7chx" in osv.aliases
    assert len(osv.affected) == 1

    aff = osv.affected[0]
    assert aff.package.name == "mcp-neo4j-cypher"
    assert aff.package.ecosystem == "PyPI"
    assert aff.package.purl == "pkg:pypi/mcp-neo4j-cypher"
    assert len(aff.ranges) == 1
    events = aff.ranges[0].events
    assert any(e.introduced == "0.2.2" for e in events)
    assert any(e.fixed == "0.4.0" for e in events)
    assert any(e.last_affected == "0.3.1" for e in events)

    db_mcp = aff.database_specific
    assert "CWE-346" in db_mcp.cwe_ids
    assert db_mcp.owasp_mcp_category == "MCP07 — Insufficient Authentication & Authorization"
    assert db_mcp.epss_score == pytest.approx(0.00032)
    assert db_mcp.cvss_score == pytest.approx(7.4)
    assert db_mcp.severity == "HIGH"
    assert "cypher" in db_mcp.vulnerable_tools or "cypher_query" in db_mcp.vulnerable_tools
    assert "stdio mode" in (db_mcp.remediation_guidance or "").lower()

    # Serialization validation
    json_str = osv.to_json()
    assert "CVE-2025-10193" in json_str


def test_markdown_advisory_converter_all_markdown_fixtures() -> None:
    md_dir = FIXTURES_DIR / "markdown"
    for md_file in md_dir.glob("*.md"):
        osv = MarkdownAdvisoryConverter.from_file(md_file)
        assert osv.id.startswith("CVE-")
        assert len(osv.affected) >= 1
        assert osv.affected[0].package.name
        assert osv.details


def test_ghsa_converter_mcp_remote() -> None:
    path = FIXTURES_DIR / "ghsa" / "GHSA-6xpm-ggf7-wc3p.json"
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))

    osv = GhsaConverter.from_dict(data)

    assert osv.id == "GHSA-6xpm-ggf7-wc3p"
    assert "CVE-2025-6514" in osv.aliases
    assert len(osv.affected) == 1

    aff = osv.affected[0]
    assert aff.package.name == "mcp-remote"
    assert aff.package.ecosystem == "npm"
    assert aff.package.purl == "pkg:npm/mcp-remote"

    events = aff.ranges[0].events
    assert any(e.introduced == "0.0.5" for e in events)
    assert any(e.fixed == "0.1.16" for e in events)
    assert "CWE-78" in aff.database_specific.cwe_ids
    assert aff.database_specific.severity == "CRITICAL"


def test_ghsa_converter_neo4j() -> None:
    path = FIXTURES_DIR / "ghsa" / "GHSA-vcqx-v2mg-7chx.json"
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))

    osv = GhsaConverter.from_dict(data)
    assert osv.id == "GHSA-vcqx-v2mg-7chx"
    assert len(osv.affected) >= 1
    assert "mcp-neo4j" in osv.affected[0].package.name or "mcp" in osv.affected[0].package.name


def test_nvd_converter_cve_2025_6514() -> None:
    path = FIXTURES_DIR / "nvd" / "CVE-2025-6514.json"
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))

    osv = NvdConverter.from_dict(data)

    assert osv.id == "CVE-2025-6514"
    assert len(osv.affected) >= 1
    aff = osv.affected[0]
    assert aff.package.name == "mcp-remote"
    assert "CWE-78" in aff.database_specific.cwe_ids
    assert aff.database_specific.cvss_score == pytest.approx(9.6)
    assert aff.database_specific.severity == "CRITICAL"


def test_osv_dev_converter() -> None:
    path = FIXTURES_DIR / "osv_dev" / "PYSEC-2026-3482.json"
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))

    osv = OsvDevConverter.from_dict(data)

    assert osv.id == "PYSEC-2026-3482"
    assert len(osv.affected) == 1
    aff = osv.affected[0]
    assert aff.package.name == "mcp"
    assert aff.package.ecosystem == "PyPI"
    assert any(e.fixed == "1.27.2" for e in aff.ranges[0].events)
    assert aff.database_specific.remediation_guidance


def test_verity_catalog_converter() -> None:
    @dataclass(frozen=True)
    class MockCondition:
        condition_id: str
        name: str
        category: str
        cwe_id: str
        description: str
        target_tool: str
        vulnerable_behavior: str
        secure_mitigation: str

    @dataclass(frozen=True)
    class MockServerSpec:
        server_id: str
        name: str
        domain: str
        vulnerabilities: tuple[MockCondition, ...]

    cond = MockCondition(
        condition_id="TEST-001",
        name="Test Vulnerability",
        category="Injection",
        cwe_id="CWE-89",
        description="Test desc",
        target_tool="test_query",
        vulnerable_behavior="Exploitable",
        secure_mitigation="Sanitize inputs",
    )
    spec = MockServerSpec(
        server_id="test-server",
        name="Test Server",
        domain="testing",
        vulnerabilities=(cond,),
    )

    vuln = VerityCatalogConverter.convert_condition(spec, cond)
    assert vuln.id == "VERITY-TEST-001"
    assert "TEST-001" in vuln.aliases
    assert len(vuln.affected) == 1
    assert vuln.affected[0].database_specific.vulnerable_tools == ("test_query",)
    assert "CWE-89" in vuln.affected[0].database_specific.cwe_ids
