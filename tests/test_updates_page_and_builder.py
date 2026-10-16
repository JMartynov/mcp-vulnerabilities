"""Tests for updates_builder.py, docs/updates.html, and docs/updates.js."""

import json
from pathlib import Path
import pytest

from mcp_vulnerabilities.updates_builder import build_updates_data


def test_updates_builder_execution(tmp_path: Path):
    vuln_dir = tmp_path / "vulnerabilities"
    vuln_dir.mkdir()

    # Create dummy advisory
    adv = {
        "id": "GHSA-test-update-001",
        "summary": "Update delta advisory",
        "details": "Details of update advisory",
        "modified": "2026-10-16T00:00:00Z",
        "affected": [
            {
                "package": {"name": "updated-server", "ecosystem": "PyPI"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "2.0.0"}]}],
                "versions": ["1.0.0"],
                "database_specific": {
                    "vulnerable_tools": ["file_read"],
                    "owasp_mcp_category": "MCP01 - Tool Poisoning",
                    "severity": "HIGH",
                },
            }
        ],
    }
    (vuln_dir / "GHSA-test-update-001.json").write_text(json.dumps(adv), encoding="utf-8")

    out_dir = tmp_path / "updates_data"
    result = build_updates_data(
        output_dir=out_dir,
        version="1.0.1",
        vulnerabilities_dir=vuln_dir,
        passports_path=None,
    )

    assert result["latest"].exists()
    assert result["versioned"].exists()
    assert result["history"].exists()

    latest = json.loads(result["latest"].read_text(encoding="utf-8"))
    assert latest["release_version"] == "1.0.1"
    assert "summary_counts" in latest
    assert "updated_servers" in latest
    assert len(latest["updated_servers"]) >= 1
    assert latest["updated_servers"][0]["package_name"] == "updated-server"
    assert "change_type" in latest["updated_servers"][0]

    history = json.loads(result["history"].read_text(encoding="utf-8"))
    assert len(history) >= 1
    assert history[0]["release_version"] == "1.0.1"


def test_live_updates_data_generated():
    """Verify live repository updates data files conform to VC-43V.1."""
    latest_file = Path("docs/data/updates/latest_update.json")
    history_file = Path("docs/data/updates/updates_history.json")

    assert latest_file.exists(), "latest_update.json must exist"
    assert history_file.exists(), "updates_history.json must exist"

    latest_data = json.loads(latest_file.read_text(encoding="utf-8"))
    assert "release_version" in latest_data
    assert "summary_counts" in latest_data
    assert "updated_servers" in latest_data
    assert "updated_advisories" in latest_data

    # Check updated_servers have version-separated data and change_type
    if latest_data["updated_servers"]:
        sample = latest_data["updated_servers"][0]
        assert "change_type" in sample
        assert "versions" in sample

    history_data = json.loads(history_file.read_text(encoding="utf-8"))
    assert isinstance(history_data, list)
    assert len(history_data) >= 1


def test_updates_html_structure():
    """Verify docs/updates.html conforms to VC-43V.2."""
    html_file = Path("docs/updates.html")
    assert html_file.exists(), "docs/updates.html must exist"
    content = html_file.read_text(encoding="utf-8")

    # 1. Release selector dropdown
    assert 'id="release-select"' in content, "Missing release-select dropdown"

    # 2. Server cards container
    assert 'id="servers-container"' in content, "Missing servers container"

    # 3. Identical server deep-dive modal
    assert 'id="server-modal"' in content, "Missing server-modal"
    assert 'id="modal-version-pills"' in content, "Missing version selector pills container"
    assert 'id="selected-version-vuln-container"' in content, "Missing version vulnerability matrix container"
    assert 'id="modal-tools-container"' in content, "Missing tools container"

    # 4. Config exporters
    assert 'data-client="claude"' in content
    assert 'data-client="cursor"' in content
    assert 'data-client="cline"' in content
    assert 'data-client="zed"' in content

    # 5. Script include
    assert 'src="updates.js"' in content


def test_updates_js_implementation():
    """Verify docs/updates.js conforms to VC-43V.2."""
    js_file = Path("docs/updates.js")
    assert js_file.exists(), "docs/updates.js must exist"
    content = js_file.read_text(encoding="utf-8")

    # 1. Loads history and latest updates
    assert "data/updates/updates_history.json" in content
    assert "data/updates/" in content or "latest_update.json" in content

    # 2. Release dropdown change handler
    assert "releaseSelect" in content

    # 3. Card rendering with change_type
    assert "change_type" in content or "changeTypeLabel" in content

    # 4. Full parameter schema table
    for col in ["Name", "Type", "Required", "Default", "Enum", "Description"]:
        assert f"<th>{col}</th>" in content, f"Missing parameter schema column header: {col}"

    # 5. Config exporters
    assert "exportConfig" in content
    assert "claude" in content and "cursor" in content and "cline" in content and "zed" in content
