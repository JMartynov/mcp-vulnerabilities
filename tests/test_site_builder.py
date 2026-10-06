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
        "affected": [{"package": {"name": "test-pkg"}}]
    }
    (vuln_dir / "GHSA-test-site-001.json").write_text(json.dumps(test_adv), encoding="utf-8")

    out_dir = tmp_path / "docs_data"
    result_file = build_site_data(data_dir=vuln_dir, output_dir=out_dir)

    assert result_file.exists()
    loaded = json.loads(result_file.read_text(encoding="utf-8"))
    assert len(loaded) == 1
    assert loaded[0]["id"] == "GHSA-test-site-001"
