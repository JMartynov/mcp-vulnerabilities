"""Unit test for static site builder."""

import json
from pathlib import Path

from mcp_vulnerabilities.site_builder import build_site_data


def test_build_site_data(tmp_path: Path):
    vuln_dir = tmp_path / "vulnerabilities"
    vuln_dir.mkdir()

    # Create dummy OSV JSON
    test_adv = {
        "id": "GHSA-test-site-001",
        "summary": "Test web explorer advisory",
        "affected": [
            {
                "package": {"name": "test-pkg"},
                "database_specific": {
                    "vulnerable_tools": ["cypher_query"],
                    "owasp_mcp_category": "MCP01 - Tool Poisoning",
                    "remediation_guidance": "Fix it",
                },
            }
        ],
    }
    (vuln_dir / "GHSA-test-site-001.json").write_text(
        json.dumps(test_adv), encoding="utf-8"
    )

    out_dir = tmp_path / "docs_data"
    result_file = build_site_data(data_dir=vuln_dir, output_dir=out_dir)

    assert result_file.exists()
    loaded = json.loads(result_file.read_text(encoding="utf-8"))
    assert len(loaded) == 1
    assert loaded[0]["id"] == "GHSA-test-site-001"

    # Assert database_specific MCP extensions are preserved
    db_specific = loaded[0]["affected"][0]["database_specific"]
    assert db_specific["vulnerable_tools"] == ["cypher_query"]
    assert db_specific["owasp_mcp_category"] == "MCP01 - Tool Poisoning"
    assert db_specific["remediation_guidance"] == "Fix it"

    analytics_file = out_dir / "analytics.json"
    assert analytics_file.exists()
    
    analytics_data = json.loads(analytics_file.read_text(encoding="utf-8"))
    assert "top_tools" in analytics_data
    assert "owasp_breakdown" in analytics_data
    assert "ecosystems" in analytics_data
    
    # Check top tools
    top_tools = analytics_data["top_tools"]
    assert len(top_tools) == 1
    assert top_tools[0]["tool"] == "cypher_query"
    assert top_tools[0]["count"] == 1
    
    # Check OWASP breakdown
    owasp = analytics_data["owasp_breakdown"]
    assert len(owasp) == 1
    assert owasp[0]["category"] == "MCP01 - Tool Poisoning"
    assert owasp[0]["count"] == 1
    assert owasp[0]["percentage"] == 100.0
