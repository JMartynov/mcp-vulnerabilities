import json
import pytest
import os
import shutil
import sys
from pathlib import Path
from mcp_vulnerabilities.audit.parsers import ClientConfigParser, UniversalClientConfigScanner

def test_scenario1_jsonc_parsing(tmp_path):
    config_content = """// Main config file
{
  "mcpServers": {
    "test_server": {
      "command": "node",
      "args": ["dist/index.js", ],
      "env": {
        "API_KEY": "secret",
        "URL": "http://example.com/api" // comment with url
      }
    }
  }
}
"""
    config_file = tmp_path / "claude_desktop_config.json"
    
    # write with BOM
    with open(config_file, "w", encoding="utf-8-sig") as f:
        f.write(config_content)
        
    servers = ClientConfigParser.parse_file(config_file, "claude")
    assert len(servers) == 1
    assert servers[0].server_name == "test_server"
    assert servers[0].command == "node"
    assert servers[0].args == ["dist/index.js"]
    # Verify environment redaction happened
    assert servers[0].env.get("API_KEY") == "***REDACTED***"
    assert servers[0].env.get("URL") == "http://example.com/api"

def test_scenario2_symlinks(tmp_path, monkeypatch):
    from mcp_fingerprints.config_scanner import NpmGlobalScanner

    # We need to simulate the npm global scanner hitting a symlink cycle
    nm_dir = tmp_path / "node_modules"
    nm_dir.mkdir()
    
    pkg_dir = nm_dir / "my-mcp-server"
    pkg_dir.mkdir()
    
    with open(pkg_dir / "package.json", "w") as f:
        json.dump({
            "name": "my-mcp-server",
            "version": "1.0.0",
            "dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"}
        }, f)
        
    # Create symlink cycle
    cycle_dir = nm_dir / "cycle"
    os.symlink(str(nm_dir), str(cycle_dir), target_is_directory=True)

    # Monkeypatch to force NpmGlobalScanner to scan our fake node_modules
    scanner = NpmGlobalScanner()
    
    def fake_subprocess_run(*args, **kwargs):
        class FakeResult:
            stdout = str(nm_dir) + "\n"
        return FakeResult()
        
    import subprocess
    monkeypatch.setattr(subprocess, "run", fake_subprocess_run)

    # Should not hang in infinite loop!
    servers = scanner.scan_global_npm()
    assert any(s["name"] == "my-mcp-server" for s in servers)
    
def test_scenario3_paths_and_env_vars():
    # Test path normalization and env var expansion directly
    # E.g. _parse_server_entry should normalize paths and expand vars
    os.environ["MY_TEST_VAR"] = "testval"
    
    # We can invoke _parse_server_entry directly
    conf = {
        "command": "C:\\Windows\\System32\\node.exe",
        "args": ["${MY_TEST_VAR}/app.js", "$MY_TEST_VAR/app2.js"],
        "env": {
            "SECRET_TOKEN": "mysecret",
            "NORMAL_VAR": "value"
        }
    }
    
    server = ClientConfigParser._parse_server_entry("test3", conf)
    assert server is not None
    
    # Normalized command path
    assert server.command == "C:/Windows/System32/node.exe"
    
    # Env var expansion
    assert server.args[0] == "testval/app.js"
    assert server.args[1] == "testval/app2.js"
    
    # Env var redaction
    assert server.env["SECRET_TOKEN"] == "***REDACTED***"
    assert server.env["NORMAL_VAR"] == "value"
