import pytest
from mcp_vulnerabilities.provenance import resolve_provenance_urls

def test_resolve_provenance_urls_none():
    result = resolve_provenance_urls("GHSA-1234", aliases=None)
    assert result["osv"] == "https://osv.dev/vulnerability/GHSA-1234"
    assert result["ghsa"] == "https://github.com/advisories/GHSA-1234"
    assert "cve" not in result

def test_resolve_provenance_urls_empty_list():
    result = resolve_provenance_urls("GHSA-1234", aliases=[])
    assert result["osv"] == "https://osv.dev/vulnerability/GHSA-1234"
    assert result["ghsa"] == "https://github.com/advisories/GHSA-1234"
    assert "cve" not in result

def test_resolve_provenance_urls_list():
    result = resolve_provenance_urls("GHSA-1234", aliases=["CVE-2024-1234"])
    assert result["osv"] == "https://osv.dev/vulnerability/GHSA-1234"
    assert result["ghsa"] == "https://github.com/advisories/GHSA-1234"
    assert result["cve"] == "https://www.cve.org/CVERecord?id=CVE-2024-1234"
    assert result["nvd"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"

def test_resolve_provenance_urls_tuple():
    result = resolve_provenance_urls("GHSA-1234", aliases=("CVE-2024-1234",))
    assert result["osv"] == "https://osv.dev/vulnerability/GHSA-1234"
    assert result["ghsa"] == "https://github.com/advisories/GHSA-1234"
    assert result["cve"] == "https://www.cve.org/CVERecord?id=CVE-2024-1234"
    assert result["nvd"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-1234"
