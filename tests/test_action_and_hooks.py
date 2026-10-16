import re
from pathlib import Path


def test_pre_commit_hooks_structure():
    hooks_path = Path(__file__).parent.parent / ".pre-commit-hooks.yaml"
    assert hooks_path.exists(), ".pre-commit-hooks.yaml must exist at repository root"

    content = hooks_path.read_text(encoding="utf-8")
    assert "id: mcp-vuln-audit" in content
    assert "id: mcp-audit-config" in content
    assert "entry: mcp-vuln audit" in content
    assert "entry: mcp-vuln audit-config" in content
    assert "language: python" in content

    # Test regex patterns against sample files
    vuln_pattern = r"(?i)(.*mcp.*\.json|claude_desktop_config\.json|cursor_settings\.json|uv\.lock|package\.json|pyproject\.toml|requirements\.txt)$"
    assert re.search(vuln_pattern, "claude_desktop_config.json")
    assert re.search(vuln_pattern, "cursor_settings.json")
    assert re.search(vuln_pattern, "uv.lock")
    assert re.search(vuln_pattern, "package.json")
    assert re.search(vuln_pattern, "pyproject.toml")
    assert re.search(vuln_pattern, "requirements.txt")
    assert re.search(vuln_pattern, "my_mcp_server.json")
    assert not re.search(vuln_pattern, "script.py")

    config_pattern = r"(?i)(.*mcp.*\.json|claude_desktop_config\.json|cursor_settings\.json)$"
    assert re.search(config_pattern, "claude_desktop_config.json")
    assert re.search(config_pattern, "cursor_settings.json")
    assert re.search(config_pattern, "my_mcp_server.json")
    assert not re.search(config_pattern, "uv.lock")
    assert not re.search(config_pattern, "package.json")


def test_action_yml_structure():
    action_path = Path(__file__).parent.parent / "action.yml"
    assert action_path.exists(), "action.yml must exist at repository root"

    content = action_path.read_text(encoding="utf-8")
    assert "name: \"Audit MCP Vulnerabilities\"" in content or "name: 'Audit MCP Vulnerabilities'" in content or "name: Audit MCP Vulnerabilities" in content
    assert "config-path:" in content
    assert "config-file:" in content
    assert "CONFIG_PATH=\"${INPUT_CONFIG_PATH:-$INPUT_CONFIG_FILE}\"" in content
    assert "findings-count:" in content
    assert "has-critical-or-high:" in content
