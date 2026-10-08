"""Unit tests for Atom and JSON Feed generators."""

import json
from pathlib import Path
import xml.etree.ElementTree as ET

from mcp_vulnerabilities.feed import AdvisoryFeedBuilder


def test_generate_atom_and_json_feed(tmp_path: Path):
    mock_advisories = [
        {
            "id": "GHSA-test-0001",
            "summary": "Mock RCE in MCP Server",
            "details": "A critical vulnerability allowing arbitrary code execution.",
            "published": "2026-10-01T12:00:00Z",
            "modified": "2026-10-02T12:00:00Z",
            "affected": [
                {
                    "package": {"name": "vulnerable-mcp-pkg", "ecosystem": "npm"},
                    "database_specific": {"severity": "CRITICAL", "cvss_score": 9.8}
                }
            ],
            "references": [
                {"type": "ADVISORY", "url": "https://github.com/example/security/advisories/GHSA-test-0001"}
            ]
        },
        {
            "id": "CVE-2026-99999",
            "summary": "Mock SSRF in Gateway",
            "details": "Server side request forgery via unvalidated tool inputs.",
            "published": "2026-09-15T08:00:00Z",
            "affected": [
                {
                    "package": {"name": "mcp-gateway", "ecosystem": "PyPI"},
                    "database_specific": {"severity": "HIGH", "cvss_score": 7.5}
                }
            ],
            "references": [
                {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-99999"}
            ]
        }
    ]

    atom_file = tmp_path / "feed.atom"
    json_file = tmp_path / "feed.json"

    # Test Atom Generation
    AdvisoryFeedBuilder.generate_atom_feed(mock_advisories, atom_file)
    assert atom_file.exists()
    assert atom_file.stat().st_size > 0

    # Parse XML to verify conformance
    tree = ET.parse(atom_file)
    root = tree.getroot()
    assert "feed" in root.tag
    entries = root.findall("{http://www.w3.org/2005/Atom}entry")
    assert len(entries) == 2
    # Verify descending sort (latest first)
    assert "GHSA-test-0001" in entries[0].find("{http://www.w3.org/2005/Atom}id").text

    # Test JSON Feed Generation
    AdvisoryFeedBuilder.generate_json_feed(mock_advisories, json_file)
    assert json_file.exists()
    feed_data = json.loads(json_file.read_text(encoding="utf-8"))
    assert feed_data["version"] == "https://jsonfeed.org/version/1.1"
    assert len(feed_data["items"]) == 2
    assert feed_data["items"][0]["id"] == "urn:mcp:vulnerability:GHSA-test-0001"
    assert "CRITICAL" in feed_data["items"][0]["tags"]
