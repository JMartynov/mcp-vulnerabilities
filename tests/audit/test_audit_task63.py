from pathlib import Path
from unittest.mock import patch, MagicMock
import pytest

from mcp_vulnerabilities.audit.fixer import ClientConfigFixer
from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher, AuditFinding, AuditReport
from mcp_vulnerabilities.fingerprints.models import (
    CorrelatedTimeline,
    VersionVulnerabilityState,
)


@pytest.fixture
def mock_matcher():
    matcher = MagicMock(spec=VulnerabilityMatcher)
    # Return a mocked report when audit_servers is called
    finding = AuditFinding(
        server_name="vuln-server",
        package_name="vuln-package",
        installed_version="1.0.0",
        vulnerability_id="CVE-123",
        summary="Test vulnerability",
        severity_level="HIGH",
        cvss_score=8.5,
        fixed_version="1.1.0",
        affected_range="<1.1.0",
        references=[],
        is_confirmed=True,
    )
    from mcp_vulnerabilities.audit.parsers import DiscoveredClientServer
    server = DiscoveredClientServer(
        server_name="vuln-server",
        package_name="vuln-package",
        version="1.0.0",
        ecosystem="npm",
        command="npx",
        args=["vuln-package@1.0.0"]
    )
    report = AuditReport(
        findings=[finding],
        scanned_servers=[server],
    )
    matcher.audit_servers.return_value = report
    return matcher


def test_fixer_preserves_zed_format_and_creates_backup(tmp_path, mock_matcher):
    """Scenario 1: Multi-Client In-Place Config Remediation Invariant"""
    config_path = tmp_path / "settings.json"
    original_content = '''{
        // This is a user comment
        "context_servers": {
            "vuln-server": {
                "command": "npx",
                "args": ["-y", "vuln-package@1.0.0"]
            }
        }
    }'''
    config_path.write_text(original_content, encoding="utf-8")

    fixer = ClientConfigFixer(matcher=mock_matcher)
    result = fixer.fix_config(config_path)

    # Invariant 1B: Atomic Backup Creation
    assert result["status"] == "success"
    assert "backup_path" in result
    backup_path = Path(result["backup_path"])
    assert backup_path.exists()
    assert backup_path.read_text(encoding="utf-8") == original_content

    # Invariant 1A: Native Schema Preservation (comments preserved)
    new_content = config_path.read_text(encoding="utf-8")
    assert "// This is a user comment" in new_content
    assert "vuln-package@1.1.0" in new_content
    assert "vuln-package@1.0.0" not in new_content


def test_fixer_rollback_on_write_failure(tmp_path, mock_matcher):
    """Scenario 2: Rollback on Disk Write Failure Invariant"""
    config_path = tmp_path / "settings.json"
    original_content = '{"servers": {"vuln-server": {"command": "npx", "args": ["vuln-package@1.0.0"]}}}'
    config_path.write_text(original_content, encoding="utf-8")

    fixer = ClientConfigFixer(matcher=mock_matcher)
    
    # Mock os.replace to raise an exception
    with patch("os.replace", side_effect=PermissionError("Simulated write failure")):
        with pytest.raises(SystemExit) as exc_info:
            fixer.fix_config(config_path)
            
        # Invariant 2B: Non-Zero Exit
        assert exc_info.value.code == 1

    # Invariant 2A: Clean Atomic Rollback
    # Backup was created, temporary file removed, and original file restored
    assert config_path.read_text(encoding="utf-8") == original_content
    assert not config_path.with_name(f"{config_path.name}.tmp").exists()


def test_polyglot_monotonic_upgrade_and_no_fix():
    """Scenario 3: Polyglot Upgrade Target Resolution Invariant"""
    
    # Create a timeline with fixes
    timeline_with_fix = CorrelatedTimeline(
        package_name="test-package",
        timeline=[
            VersionVulnerabilityState(version="1.0.0", is_vulnerable=True),
            VersionVulnerabilityState(version="1.1.0", is_vulnerable=False),
            VersionVulnerabilityState(version="2.0.0", is_vulnerable=False),
        ]
    )

    # Invariant 3A: Monotonic Upgrade Target
    safe_ver, no_fix = timeline_with_fix.get_remediation_for_version("1.0.0")
    assert safe_ver == "1.1.0"  # Lowest safe version strictly greater than current
    assert no_fix is False

    # Current version is already safe
    safe_ver, no_fix = timeline_with_fix.get_remediation_for_version("2.0.0")
    assert safe_ver is None
    assert no_fix is False

    # Create a timeline with no fixes for the latest branch
    timeline_no_fix = CorrelatedTimeline(
        package_name="zero-day-package",
        timeline=[
            VersionVulnerabilityState(version="1.0.0", is_vulnerable=True),
            VersionVulnerabilityState(version="2.0.0", is_vulnerable=True),
        ]
    )

    # Invariant 3B: No-Fix Available Explicit Flag
    safe_ver, no_fix = timeline_no_fix.get_remediation_for_version("2.0.0")
    assert safe_ver is None
    assert no_fix is True

