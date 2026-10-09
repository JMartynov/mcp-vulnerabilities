import pytest
from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher, SearchResult
from mcp_vulnerabilities.models import OsvVulnerability

@pytest.fixture
def sample_advisories():
    return [
        {
            "id": "GHSA-1234",
            "aliases": ["CVE-2024-0001"],
            "summary": "SQL Injection in Postgres",
            "details": "A detail string",
            "severity": [{"type": "CVSS_V3", "score": "8.5"}],
            "affected": [
                {
                    "package": {"name": "postgres-mcp", "ecosystem": "PyPI"},
                    "database_specific": {"vulnerable_tools": ["query_db"]}
                }
            ]
        },
        {
            "id": "GHSA-5678",
            "summary": "XSS in frontend",
            "details": "Another detail string",
            "severity": [{"type": "CVSS_V3", "score": "5.5"}],
            "affected": [
                {
                    "package": {"name": "express", "ecosystem": "npm"},
                    "database_specific": {"vulnerable_tools": []}
                }
            ]
        }
    ]

@pytest.fixture
def matcher(sample_advisories):
    return VulnerabilityMatcher(sample_advisories)

def test_get_advisory_by_id(matcher):
    adv = matcher.get_advisory("GHSA-1234")
    assert adv is not None
    assert adv.id == "GHSA-1234"

def test_get_advisory_by_alias(matcher):
    adv = matcher.get_advisory("CVE-2024-0001")
    assert adv is not None
    assert adv.id == "GHSA-1234"

def test_get_advisory_not_found(matcher):
    adv = matcher.get_advisory("CVE-9999-9999")
    assert adv is None

def test_search_by_keyword(matcher):
    results = matcher.search("SQL")
    assert len(results) == 1
    assert results[0].advisory.id == "GHSA-1234"
    assert "Summary match" in results[0].matched_on

def test_search_by_tool_name(matcher):
    results = matcher.search("query_db")
    assert len(results) == 1
    assert results[0].advisory.id == "GHSA-1234"
    assert "Vulnerable tool match" in results[0].matched_on

def test_search_by_package(matcher):
    results = matcher.search("express")
    assert len(results) == 1
    assert results[0].advisory.id == "GHSA-5678"
    assert "Package match" in results[0].matched_on

def test_search_filter_by_severity(matcher):
    # GHSA-1234 is HIGH (8.5), GHSA-5678 is MEDIUM (5.5)
    results = matcher.search("in", min_severity="HIGH")
    assert len(results) == 1
    assert results[0].advisory.id == "GHSA-1234"

def test_search_filter_by_ecosystem(matcher):
    results = matcher.search("in", ecosystem="npm")
    assert len(results) == 1
    assert results[0].advisory.id == "GHSA-5678"

def test_search_no_results(matcher):
    results = matcher.search("nonexistent")
    assert len(results) == 0

