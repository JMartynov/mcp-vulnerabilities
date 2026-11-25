"""ATDD unit tests for AC-105.3: PR Builder Real Hashes."""

import hashlib
import json
import re
from pathlib import Path

from mcp_vulnerabilities.audit.matcher import AuditFinding, AuditReport
from mcp_vulnerabilities.bot.pr_builder import PRBuilder
from mcp_vulnerabilities.bot.scanner import RemediationPlan


def _extract_delta_hashes(body: str) -> tuple[str, str]:
    match = re.search(r"`([^`\s]+)`\s*➔\s*`([^`\s]+)`", body)
    assert match is not None, f"Could not find fingerprint delta line in PR body:\n{body}"
    return match.group(1), match.group(2)


def test_real_config_hashes(tmp_path):
    """AC-105.3: PR body emits real SHA-256 digests of canonical JSON, never placeholders."""
    old_cfg = {"mcpServers": {"srv": {"command": "npx", "args": ["-y", "pkg@1.0.0"]}}}
    new_cfg = {"mcpServers": {"srv": {"command": "npx", "args": ["-y", "pkg@1.0.1"]}}}

    plan = RemediationPlan(
        config_path=Path("claude_desktop_config.json"),
        original_text=json.dumps(old_cfg, indent=2),
        patched_text=json.dumps(new_cfg, indent=2),
        diff_text="-1.0.0\n+1.0.1",
        changes=[
            {
                "server_name": "srv",
                "package_name": "pkg",
                "old_version": "1.0.0",
                "new_version": "1.0.1",
            }
        ],
        report=AuditReport(
            findings=[
                AuditFinding(
                    server_name="srv",
                    package_name="pkg",
                    vulnerability_id="CVE-2026-0001",
                    severity_level="HIGH",
                    cvss_score=7.5,
                    installed_version="1.0.0",
                    fixed_version="1.0.1",
                    affected_range="<1.0.1",
                    summary="Test vuln",
                    is_confirmed=True,
                    references=["https://example.com/CVE-2026-0001"],
                )
            ],
            scanned_servers=[],
        ),
    )

    body = PRBuilder(tmp_path).format_pr_body(plan)
    assert "old_hash" not in body
    assert "new_hash" not in body

    old_digest, new_digest = _extract_delta_hashes(body)
    assert re.fullmatch(r"[0-9a-f]{64}", old_digest)
    assert re.fullmatch(r"[0-9a-f]{64}", new_digest)
    assert old_digest != new_digest

    expected_old = hashlib.sha256(
        json.dumps(old_cfg, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    expected_new = hashlib.sha256(
        json.dumps(new_cfg, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    assert old_digest == expected_old
    assert new_digest == expected_new


def test_noop_change_equal_hashes(tmp_path):
    """AC-105.3 paired benign control: identical configs produce identical 64-hex digests."""
    cfg_text = json.dumps({"mcpServers": {"srv": {"command": "npx", "args": ["-y", "pkg@1.0.1"]}}})
    plan = RemediationPlan(
        config_path=Path("mcp.json"),
        original_text=cfg_text,
        patched_text=cfg_text,
        diff_text="",
        changes=[],
        report=AuditReport(findings=[], scanned_servers=[]),
    )

    body = PRBuilder(tmp_path).format_pr_body(plan)
    old_digest, new_digest = _extract_delta_hashes(body)
    assert re.fullmatch(r"[0-9a-f]{64}", old_digest)
    assert re.fullmatch(r"[0-9a-f]{64}", new_digest)
    assert old_digest == new_digest
