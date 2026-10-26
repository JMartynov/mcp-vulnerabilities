import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from mcp_vulnerabilities.bot.scanner import RepositoryScanner, RemediationPlan
from mcp_vulnerabilities.bot.pr_builder import PRBuilder
from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher, AuditReport, AuditFinding


@pytest.fixture
def mock_matcher():
    matcher = MagicMock(spec=VulnerabilityMatcher)
    return matcher

def test_repository_scanner_discovery(tmp_path, mock_matcher):
    # Setup mock repo structure
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "mcp.json").write_text("{}")
    
    (tmp_path / ".cursor").mkdir()
    cursor_config = tmp_path / ".cursor" / "mcp.json"
    cursor_config.write_text('{"mcpServers": {"test": {"command": "node", "args": ["test@1.0.0"]}}}')
    
    root_config = tmp_path / "claude_desktop_config.json"
    root_config.write_text('{"mcpServers": {"test": {"command": "npx", "args": ["-y", "test@1.0.0"]}}}')

    scanner = RepositoryScanner(tmp_path, mock_matcher)
    configs = scanner.discover_configs()

    assert len(configs) == 2
    assert set(configs) == {cursor_config, root_config}

@patch("mcp_vulnerabilities.audit.fixer.ClientConfigFixer.fix_config")
def test_scanner_generate_plans(mock_fix_config, tmp_path, mock_matcher):
    root_config = tmp_path / "claude_desktop_config.json"
    root_config.write_text('{"mcpServers": {"test": {"command": "npx", "args": ["-y", "test@1.0.0"]}}}')

    mock_finding = AuditFinding(
        server_name="test",
        package_name="test",
        vulnerability_id="CVE-2024-1234",
        severity_level="HIGH",
        installed_version="1.0.0",
        fixed_version="1.0.1",
        affected_range="<1.0.1",
        summary="Test vulnerability",
        is_confirmed=True,
        cvss_score=None,
        references=[]
    )

    mock_report = AuditReport(
        findings=[mock_finding],
        scanned_servers=[]
    )

    mock_matcher.audit_servers.return_value = mock_report

    mock_fix_config.return_value = {
        "status": "dry_run",
        "changes": [{"server_name": "test", "package_name": "test", "old_version": "1.0.0", "new_version": "1.0.1"}],
        "diff": "--- a/claude_desktop_config.json\n+++ b/claude_desktop_config.json\n@@ -1,1 +1,1 @@\n-1.0.0\n+1.0.1\n"
    }

    scanner = RepositoryScanner(tmp_path, mock_matcher)
    plans = scanner.generate_plans()

    assert len(plans) == 1
    assert plans[0].config_path == root_config
    assert "test@1.0.1" in plans[0].patched_text

def test_pr_builder_format_body():
    plan = RemediationPlan(
        config_path=Path("claude_desktop_config.json"),
        original_text="",
        patched_text="",
        diff_text="--- diff ---",
        changes=[{"server_name": "test_server", "package_name": "test_pkg", "old_version": "1.0.0", "new_version": "2.0.0"}],
        report=AuditReport(
            findings=[AuditFinding(
                server_name="test_server",
                package_name="test_pkg",
                vulnerability_id="CVE-2024-0001",
                severity_level="CRITICAL",
                cvss_score=9.8,
                installed_version="1.0.0",
                fixed_version="2.0.0",
                affected_range="<2.0.0",
                summary="Remote Code Execution",
                is_confirmed=True,
                references=["https://github.com/advisories/CVE-2024-0001"]
            )],
            scanned_servers=[]
        )
    )

    builder = PRBuilder(Path("."))
    body = builder.format_pr_body(plan)

    assert "test_pkg" in body
    assert "1.0.0" in body
    assert "2.0.0" in body
    assert "CVE-2024-0001" in body
    assert "Severity-CRITICAL-red" in body
    assert "9.8" in body
    assert "Remote Code Execution" in body
    assert "--- diff ---" in body
    assert "Cryptographic Toolset Fingerprint Delta" in body

@patch("subprocess.run")
def test_pr_builder_dry_run(mock_run, capsys):
    plan = RemediationPlan(
        config_path=Path("mcp.json"),
        original_text="",
        patched_text="",
        diff_text="",
        changes=[{"server_name": "test", "package_name": "test", "old_version": "1.0.0", "new_version": "1.0.1"}],
        report=AuditReport([], [])
    )

    builder = PRBuilder(Path("."), dry_run=True)
    builder.create_or_update_pr(plan)

    captured = capsys.readouterr()
    assert "[DRY-RUN] Planned PR Title" in captured.out
    
    # Check that subprocess.run was not called with mutating git commands
    for call in mock_run.call_args_list:
        args = call.args[0]
        assert args[0] not in ("git", "gh") or args[1] in ("status", "diff", "branch", "rev-parse", "checkout")

@patch("mcp_vulnerabilities.bot.pr_builder.PRBuilder._run_cmd")
@patch("mcp_vulnerabilities.bot.pr_builder.PRBuilder._get_existing_prs")
def test_pr_builder_idempotency(mock_get_prs, mock_run_cmd):
    plan = RemediationPlan(
        config_path=Path("mcp.json"),
        original_text="",
        patched_text="",
        diff_text="",
        changes=[{"server_name": "test", "package_name": "test", "old_version": "1.0.0", "new_version": "1.0.1"}],
        report=AuditReport([], [])
    )

    mock_get_prs.return_value = [{"headRefName": "mcp-vuln/fix-test-123", "url": "http://github.com/pr/1"}]

    builder = PRBuilder(Path("."), dry_run=False)
    builder.create_or_update_pr(plan)

    # Should have called git branch and commit, but skipped `gh pr create` since PR exists
    run_cmds = [call.args[0][0:3] for call in mock_run_cmd.call_args_list]
    assert ["git", "checkout", "mcp"] in run_cmds or ["git", "checkout", "-b"] in run_cmds
    assert ["git", "commit", "-m"] in run_cmds
    
    gh_pr_creates = [call for call in run_cmds if call[:3] == ["gh", "pr", "create"]]
    assert len(gh_pr_creates) == 0

