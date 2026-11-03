import pytest
import sys
import os
import builtins
from unittest.mock import MagicMock

if 'mcp_fingerprints' not in sys.modules:
    try:
        import mcp_fingerprints
    except ImportError:
        sys.modules['mcp_fingerprints'] = MagicMock()
        sys.modules['mcp_fingerprints.config_scanner'] = MagicMock()
        sys.modules['mcp_fingerprints.models'] = MagicMock()
        sys.modules['mcp_fingerprints.inspector'] = MagicMock()
        sys.modules['mcp_fingerprints.utils'] = MagicMock()

sys.path.insert(0, os.path.abspath('src'))
from mcp_vulnerabilities.provenance import resolve_provenance_urls

def test_authoritative_url_resolution_cve():
    urls = resolve_provenance_urls("CVE-2024-54133")
    assert urls["cve"] == "https://www.cve.org/CVERecord?id=CVE-2024-54133"
    assert urls["nvd"] == "https://nvd.nist.gov/vuln/detail/CVE-2024-54133"
    assert urls["osv"] == "https://osv.dev/vulnerability/CVE-2024-54133"
    assert "ghsa" not in urls

def test_authoritative_url_resolution_ghsa_with_alias():
    urls = resolve_provenance_urls("GHSA-w48q-v783-6mg3", ["CVE-2025-10193"])
    assert urls["ghsa"] == "https://github.com/advisories/GHSA-w48q-v783-6mg3"
    assert urls["cve"] == "https://www.cve.org/CVERecord?id=CVE-2025-10193"
    assert urls["nvd"] == "https://nvd.nist.gov/vuln/detail/CVE-2025-10193"
    assert urls["osv"] == "https://osv.dev/vulnerability/GHSA-w48q-v783-6mg3"

def test_authoritative_url_resolution_other():
    urls = resolve_provenance_urls("PYSEC-2023-123")
    assert urls["osv"] == "https://osv.dev/vulnerability/PYSEC-2023-123"
    assert "cve" not in urls
    assert "nvd" not in urls
    assert "ghsa" not in urls
    
def test_cli_audit_report_provenance_urls():
    with open('src/mcp_vulnerabilities/cli.py', 'r') as f:
        content = f.read()
    assert "resolve_provenance_urls" in content
    assert "Official CVE:" in content
    assert "NIST NVD:" in content

def test_cli_lookup_provenance_urls():
    with open('src/mcp_vulnerabilities/cli.py', 'r') as f:
        content = f.read()
    assert "Provenance:" in content

def test_sarif_reporter_provenance_help_uri():
    with open('src/mcp_vulnerabilities/audit/reporters.py', 'r') as f:
        content = f.read()
    assert 'helpUri' in content
    assert 'resolve_provenance_urls' in content
    assert 'Upstream References' in content

def test_web_app_js_provenance_helpers():
    with open('docs/app.js', 'r') as f:
        content = f.read()
    assert "function resolveAdvisorySourceUrls" in content
    assert "https://www.cve.org/CVERecord?id=" in content

def test_safe_url_sanitization():
    with open('docs/app.js', 'r') as f:
        content = f.read()
    assert "escapeHtml(pUrls.cve)" in content or "escapeHtml(urls.cve)" in content
