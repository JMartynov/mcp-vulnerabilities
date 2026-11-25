"""ATDD unit tests for AC-105.2: Fixer Quarantine Semantics."""

import json
from unittest.mock import MagicMock, patch

from mcp_vulnerabilities.audit.fixer import ClientConfigFixer
from mcp_vulnerabilities.audit.matcher import AuditReport
from mcp_vulnerabilities.converters.openssf_malware import MaliciousPackageRecord


def _collect_strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _collect_strings(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from _collect_strings(item)


def test_quarantine_disables_without_comment_injection(tmp_path):
    """AC-105.2: Malicious package sets disabled=true & metadata without comment injection."""
    mal_record = MaliciousPackageRecord(
        id="MAL-2026-9999",
        ecosystem="npm",
        package_name="evil-mcp-pkg",
        summary="Malicious stealer",
        details="Exfiltrates keys",
        published="2026-01-01T00:00:00Z",
        modified="2026-01-01T00:00:00Z",
        source_origin="openssf",
        affected_versions=["1.0.0"],
        ranges=[],
        aliases=[],
    )
    mock_sync = MagicMock()
    mock_sync.get_malicious_record.side_effect = (
        lambda eco, pkg, ver=None: mal_record if pkg == "evil-mcp-pkg" else None
    )

    mock_matcher = MagicMock()
    mock_matcher.audit_servers.return_value = AuditReport(findings=[], scanned_servers=[])

    cfg_path = tmp_path / "claude_desktop_config.json"
    cfg_data = {
        "mcpServers": {
            "evil_srv": {
                "command": "npx",
                "args": ["-y", "evil-mcp-pkg@1.0.0"],
            }
        }
    }
    cfg_path.write_text(json.dumps(cfg_data, indent=2), encoding="utf-8")

    fixer = ClientConfigFixer(matcher=mock_matcher)
    with patch(
        "mcp_vulnerabilities.threat_intel.openssf_malicious.OpenSsfMaliciousSync",
        return_value=mock_sync,
    ):
        res = fixer.fix_config(cfg_path, dry_run=False)

    assert res["status"] == "success"
    assert len(res["changes"]) == 1
    assert res["changes"][0]["new_version"] == "QUARANTINED"

    patched_text = cfg_path.read_text(encoding="utf-8")
    assert "# QUARANTINED:" not in patched_text

    parsed = json.loads(patched_text)
    entry = parsed["mcpServers"]["evil_srv"]
    assert entry.get("disabled") is True
    assert "_quarantined_reason" in entry
    assert "evil-mcp-pkg" in entry["_quarantined_reason"]
    assert "MAL-2026-9999" in entry["_quarantined_reason"]
    assert entry["args"] == ["-y", "evil-mcp-pkg@1.0.0"]
    assert all("# QUARANTINED:" not in s for s in _collect_strings(parsed))


def test_non_malicious_package_unchanged(tmp_path):
    """AC-105.2 paired benign control: clean package config remains unmodified."""
    mock_sync = MagicMock()
    mock_sync.get_malicious_record.return_value = None

    mock_matcher = MagicMock()
    mock_matcher.audit_servers.return_value = AuditReport(findings=[], scanned_servers=[])

    cfg_path = tmp_path / "claude_desktop_config.json"
    original_text = json.dumps(
        {
            "mcpServers": {
                "clean_srv": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0"],
                }
            }
        },
        indent=2,
    )
    cfg_path.write_text(original_text, encoding="utf-8")

    fixer = ClientConfigFixer(matcher=mock_matcher)
    with patch(
        "mcp_vulnerabilities.threat_intel.openssf_malicious.OpenSsfMaliciousSync",
        return_value=mock_sync,
    ):
        res = fixer.fix_config(cfg_path, dry_run=False)

    assert res["status"] == "no_changes_needed"
    assert res["changes"] == []
    assert cfg_path.read_text(encoding="utf-8") == original_text
