import json
import os
import sys

import pytest

from mcp_vulnerabilities.audit.fixer import ClientConfigFixer
from mcp_vulnerabilities.audit.matcher import AuditFinding, AuditReport

class MockMatcher:
    def audit_servers(self, servers):
        findings = []
        for s in servers:
            if s.server_name == "fs":
                findings.append(AuditFinding(
                    server_name=s.server_name,
                    package_name=s.package_name,
                    installed_version=s.version,
                    vulnerability_id="CVE-1",
                    summary="Test",
                    severity_level="HIGH",
                    cvss_score=9.8,
                    fixed_version="0.6.2",
                    affected_range="<0.6.2",
                    is_confirmed=True,
                    references=[],
                ))
            elif s.package_name == "my-pkg":
                findings.append(AuditFinding(
                    server_name=s.server_name,
                    package_name=s.package_name,
                    installed_version=s.version,
                    vulnerability_id="CVE-1",
                    summary="Test",
                    severity_level="HIGH",
                    cvss_score=9.8,
                    fixed_version="2.0.0",
                    affected_range="<2.0.0",
                    is_confirmed=True,
                    references=[],
                ))
        return AuditReport(findings=findings, scanned_servers=servers)

@pytest.fixture
def mock_matcher():
    return MockMatcher()

def test_scenario_1_multiclient_inplace_config_remediation(tmp_path, mock_matcher, monkeypatch):
    """
    Scenario 1: Multi-Client In-Place Config Remediation Invariant
    Test Steps: Run mcp-vuln fix --all-clients --write
    """
    # Preconditions: Create vulnerable server entries across 3 distinct client configs
    claude_dir = tmp_path / "Library/Application Support/Claude"
    claude_dir.mkdir(parents=True)
    claude_config = claude_dir / "claude_desktop_config.json"
    claude_config.write_text(json.dumps({
        "mcpServers": {
            "fs": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.0", "/Users/admin/Desktop"]
            }
        }
    }))
    
    zed_dir = tmp_path / ".config/zed"
    zed_dir.mkdir(parents=True)
    zed_config = zed_dir / "settings.json"
    zed_config.write_text("""// Zed settings file
{
  "context_servers": {
    "fs": {
      "command": {
        "path": "npx",
        "args": ["@modelcontextprotocol/server-filesystem@0.6.0", "/dev"]
      }
    }
  },
  "theme": "dark",
  "font_size": 14
}""")
    
    windsurf_dir = tmp_path / ".codeium/windsurf"
    windsurf_dir.mkdir(parents=True)
    windsurf_config = windsurf_dir / "mcp_config.json"
    windsurf_config.write_text(json.dumps({
        "mcpServers": {
            "my_python_tool": {
                "command": "uvx",
                "args": ["my-pkg==1.0.0"]
            }
        }
    }))
    
    monkeypatch.setattr("mcp_vulnerabilities.audit.parsers.UniversalClientConfigScanner.get_client_paths", 
                        lambda self, c: {
                            "claude": [claude_config],
                            "zed": [zed_config],
                            "windsurf": [windsurf_config]
                        }.get(c.lower(), []))
    
    fixer = ClientConfigFixer(mock_matcher)
    
    # INVARIANT 1A & 1D (Version Pinning & Atomic Backups)
    results = fixer.fix_all_clients(dry_run=False)
    
    assert len(results) == 3
    for r in results:
        assert r["status"] == "success"
        assert "backup_path" in r
        assert os.path.exists(r["backup_path"])
        
    claude_data = json.loads(claude_config.read_text())
    assert claude_data["mcpServers"]["fs"]["args"][1] == "@modelcontextprotocol/server-filesystem@0.6.2"
    
    windsurf_data = json.loads(windsurf_config.read_text())
    assert windsurf_data["mcpServers"]["my_python_tool"]["args"][0] == "my-pkg==2.0.0"
    
    # INVARIANT 1B & 1C (Format Integrity & Preservation of Non-MCP Fields)
    zed_text = zed_config.read_text()
    assert "// Zed settings file" in zed_text
    assert '"theme": "dark"' in zed_text
    assert '"font_size": 14' in zed_text
    assert "@modelcontextprotocol/server-filesystem@0.6.2" in zed_text

def test_scenario_2_dry_run_diff_preview(tmp_path, mock_matcher, monkeypatch, capsys):
    """
    Scenario 2: Dry-Run Diff Preview Invariant
    Test Steps: Run mcp-vuln fix --all-clients --dry-run
    """
    claude_dir = tmp_path / "Library/Application Support/Claude"
    claude_dir.mkdir(parents=True)
    claude_config = claude_dir / "claude_desktop_config.json"
    original_content = json.dumps({
        "mcpServers": {
            "fs": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.0", "/test"]
            }
        }
    }, indent=2)
    claude_config.write_text(original_content)
    
    monkeypatch.setattr("mcp_vulnerabilities.audit.parsers.UniversalClientConfigScanner.get_client_paths", 
                        lambda self, c: [claude_config] if c.lower() == "claude" else [])
                        
    fixer = ClientConfigFixer(mock_matcher)
    
    # INVARIANT 2A (No Write)
    results = fixer.fix_all_clients(dry_run=True)
    
    assert len(results) == 1
    assert results[0]["status"] == "dry_run"
    assert "backup_path" not in results[0]
    
    backups = list(claude_dir.glob("*.bak.*"))
    assert len(backups) == 0
    
    assert claude_config.read_text() == original_content
    
    # INVARIANT 2B (Unified Diff Output)
    diff = results[0]["diff"]
    assert "--- a/claude_desktop_config.json" in diff
    assert "+++ b/claude_desktop_config.json" in diff
    assert "-        \"@modelcontextprotocol/server-filesystem@0.6.0\"," in diff
    assert "+        \"@modelcontextprotocol/server-filesystem@0.6.2\"," in diff

def test_scenario_3_non_interactive_fallback(monkeypatch, capsys):
    """
    Scenario 3: Non-Interactive / CI Headless Fallback Invariant
    Preconditions: isatty() == False
    """
    monkeypatch.setattr(sys.stdout, "isatty", lambda: False)
    
    from mcp_vulnerabilities.hub import run_hub
    
    # INVARIANT 3A & 3B (No Freeze & Graceful Exit)
    with pytest.raises(SystemExit) as excinfo:
        run_hub()
    
    assert excinfo.value.code == 1
    out, err = capsys.readouterr()
    assert "Interactive hub requires an interactive TTY terminal. Use headless CLI commands in CI/CD." in out

def test_scenario_4_interactive_hub_menu_navigation(monkeypatch, capsys):
    """
    Scenario 4: Interactive Hub Menu Navigation Invariant
    Preconditions: Interactive TTY terminal session.
    """
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    
    inputs = iter(["1", "0"])
    monkeypatch.setattr('builtins.input', lambda prompt: next(inputs))
    
    def fake_cli_main():
        print(f"MOCK_CLI_RUN: {sys.argv}")
        
    
    # Since cli_main is imported inside the function, we have to mock sys.modules or just let it run
    # actually better to just patch sys.argv and mcp_vulnerabilities.cli.main
    monkeypatch.setattr("mcp_vulnerabilities.cli.main", fake_cli_main)

    
    from mcp_vulnerabilities.hub import run_hub
    
    # INVARIANT 4A & 4B
    run_hub()
    
    out, err = capsys.readouterr()
    assert "MCP SECURITY COMMAND HUB" in out
    assert "MOCK_CLI_RUN: ['mcp-vuln', 'audit']" in out
    assert "Launching Universal Audit..." in out
    
