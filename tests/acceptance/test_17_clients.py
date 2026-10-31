import pytest
from pathlib import Path
import json
import logging
from dataclasses import asdict

from mcp_vulnerabilities.audit.parsers import UniversalClientConfigScanner, DiscoveredClientServer

@pytest.fixture
def synthetic_17_client_tree(tmp_path: Path) -> Path:
    # 1. Claude Desktop
    cd_dir = tmp_path / "Library/Application Support/Claude"
    cd_dir.mkdir(parents=True, exist_ok=True)
    (cd_dir / "claude_desktop_config.json").write_text(json.dumps({
        "mcpServers": {
            "cd_server": {"command": "npx", "args": ["cd-server"], "env": {"OPENAI_API_KEY": "sk-live-supersecret12345"}}
        }
    }))
    
    # 2. Claude Code
    (tmp_path / ".claude.json").write_text(json.dumps({
        "mcpServers": {
            "cc_server": {"command": "uvx", "args": ["cc-server"], "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_supersecret67890"}}
        }
    }))

    # 3. Cursor
    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir(parents=True, exist_ok=True)
    (cursor_dir / "mcp.json").write_text(json.dumps({
        "mcpServers": {
            "cursor_server": {"command": "python", "args": ["-m", "cursor-server"], "env": {"DATABASE_URL": "postgres://admin:topsecretpw@localhost/db"}}
        }
    }))

    # 4. Windsurf
    ws_dir = tmp_path / ".codeium/windsurf"
    ws_dir.mkdir(parents=True, exist_ok=True)
    (ws_dir / "mcp_config.json").write_text(json.dumps({
        "mcpServers": {
            "ws_server": {"command": "node", "args": ["ws-server"]}
        }
    }))

    # 5. Zed
    zed_dir = tmp_path / ".config/zed"
    zed_dir.mkdir(parents=True, exist_ok=True)
    (zed_dir / "settings.json").write_text(json.dumps({
        "context_servers": {
            "zed_server": {"command": "npx", "args": ["zed-server"]}
        }
    }))

    # 6. Cline
    cline_dir = tmp_path / "Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings"
    cline_dir.mkdir(parents=True, exist_ok=True)
    (cline_dir / "cline_mcp_settings.json").write_text(json.dumps({
        "mcpServers": {
            "cline_server": {"command": "npx", "args": ["cline-server"]}
        }
    }))
    
    # 7. Roo Code
    roo_dir = tmp_path / "Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings"
    roo_dir.mkdir(parents=True, exist_ok=True)
    (roo_dir / "cline_mcp_settings.json").write_text(json.dumps({
        "mcpServers": {
            "roo_server": {"command": "npx", "args": ["roo-server"]}
        }
    }))

    # 8. Goose
    goose_dir = tmp_path / ".config/goose"
    goose_dir.mkdir(parents=True, exist_ok=True)
    (goose_dir / "config.yaml").write_text("""
extensions:
  goose_server:
    cmd: npx
    args: [goose-server]
""")

    # 9. Continue
    continue_dir = tmp_path / ".continue"
    continue_dir.mkdir(parents=True, exist_ok=True)
    (continue_dir / "config.json").write_text(json.dumps({
        "experimental": {
            "modelContextProtocolServers": [
                {
                    "name": "continue_server",
                    "transport": {
                        "type": "stdio",
                        "command": "npx",
                        "args": ["continue-server"]
                    }
                }
            ]
        }
    }))
    
    # 10. JetBrains Junie
    jb_dir = tmp_path / "Library/Application Support/JetBrains/Junie"
    jb_dir.mkdir(parents=True, exist_ok=True)
    (jb_dir / "mcp.json").write_text(json.dumps({
        "servers": [
            {
                "name": "junie_server",
                "command": "npx",
                "args": ["junie-server"]
            }
        ]
    }))

    # 11. VS Code
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir(parents=True, exist_ok=True)
    (vscode_dir / "mcp.json").write_text(json.dumps({
        "mcpServers": {
            "vscode_server": {"url": "http://localhost:8080/mcp"}
        }
    }))

    # 12. Antigravity
    ag_dir = tmp_path / ".gemini/antigravity"
    ag_dir.mkdir(parents=True, exist_ok=True)
    (ag_dir / "mcp_config.json").write_text(json.dumps({
        "mcpServers": {
            "ag_server": {"command": "npx", "args": ["ag-server"]}
        }
    }))

    # 13. OpenHands
    oh_dir = tmp_path / ".openhands"
    oh_dir.mkdir(parents=True, exist_ok=True)
    (oh_dir / "mcp.json").write_text(json.dumps({
        "mcp": {
            "servers": {
                "oh_server": {"command": "npx", "args": ["oh-server"]}
            }
        }
    }))

    # 14. Trae
    trae_dir = tmp_path / ".trae"
    trae_dir.mkdir(parents=True, exist_ok=True)
    (trae_dir / "mcp.json").write_text(json.dumps({
        "mcpServers": {
            "trae_server": {"command": "npx", "args": ["trae-server"]}
        }
    }))

    # 15. LM Studio
    lms_dir = tmp_path / ".cache/lm-studio/mcp"
    lms_dir.mkdir(parents=True, exist_ok=True)
    (lms_dir / "config.json").write_text(json.dumps({
        "mcpServers": {
            "lms_server": {"command": "npx", "args": ["lms-server"]}
        }
    }))

    # 16. LibreChat
    lc_dir = tmp_path / ".librechat"
    lc_dir.mkdir(parents=True, exist_ok=True)
    (lc_dir / "librechat.yaml").write_text("""
mcpServers:
  lc_server:
    type: stdio
    command: npx
    args:
      - lc-server
""")

    # 17. OpenWebUI
    owui_dir = tmp_path / ".openwebui"
    owui_dir.mkdir(parents=True, exist_ok=True)
    (owui_dir / "config.json").write_text(json.dumps({
        "mcp_servers": [
            {
                "name": "owui_server",
                "url": "http://127.0.0.1:8000/sse"
            }
        ]
    }))

    return tmp_path

def test_unified_17_client_scan(synthetic_17_client_tree):
    scanner = UniversalClientConfigScanner(root=synthetic_17_client_tree)
    servers = scanner.scan_all_clients()
    
    server_names = {s.server_name for s in servers}
    
    expected_servers = {
        "cd_server", "cc_server", "cursor_server", "ws_server", 
        "zed_server", "cline_server", "roo_server", "goose_server", 
        "continue_server", "junie_server", "vscode_server", "ag_server", 
        "oh_server", "trae_server", "lms_server", "lc_server", "owui_server"
    }
    
    assert expected_servers.issubset(server_names)
    assert len(server_names) >= 17
    
    # Check transports
    owui_server = next((s for s in servers if s.server_name == "owui_server"), None)
    assert owui_server is not None
    assert owui_server.url == "http://127.0.0.1:8000/sse"
    assert owui_server.transport == "sse"

    vscode_server = next((s for s in servers if s.server_name == "vscode_server"), None)
    assert vscode_server is not None
    assert vscode_server.url == "http://localhost:8080/mcp"
    assert vscode_server.transport == "streamable-http"
    
def test_individual_client_discovery(synthetic_17_client_tree):
    scanner = UniversalClientConfigScanner(root=synthetic_17_client_tree)
    
    clients = {
        "claude_desktop": "cd_server",
        "claude_code": "cc_server",
        "cursor": "cursor_server",
        "windsurf": "ws_server",
        "zed": "zed_server",
        "cline": "cline_server",
        "roo_code": "roo_server",
        "goose": "goose_server",
        "continue": "continue_server",
        "jetbrains_junie": "junie_server",
        "vscode": "vscode_server",
        "antigravity": "ag_server",
        "openhands": "oh_server",
        "trae": "trae_server",
        "lm_studio": "lms_server",
        "librechat": "lc_server",
        "openwebui": "owui_server",
    }
    
    for client, expected_server in clients.items():
        servers = scanner.scan_client(client)
        assert any(s.server_name == expected_server for s in servers), f"Client {client} failed to parse {expected_server}"

def test_secret_token_redaction_invariant(synthetic_17_client_tree):
    scanner = UniversalClientConfigScanner(root=synthetic_17_client_tree)
    servers = scanner.scan_all_clients()
    
    json_repr = str([asdict(s) for s in servers])
    
    assert "supersecret" not in json_repr
    assert "topsecret" not in json_repr
    
    cd_server = next((s for s in servers if s.server_name == "cd_server"), None)
    assert cd_server is not None
    assert cd_server.env.get("OPENAI_API_KEY") == "***REDACTED***"
    
def test_relaxed_json_syntax_resilience(synthetic_17_client_tree):
    scanner = UniversalClientConfigScanner(root=synthetic_17_client_tree)
    
    # 1. Claude Desktop
    cd_dir = synthetic_17_client_tree / "Library/Application Support/Claude"
    cd_dir.mkdir(parents=True, exist_ok=True)
    (cd_dir / "claude_desktop_config.json").write_text("""
    {
        // This is a comment
        "mcpServers": {
            "cd_server": {
                "command": "npx",
                "args": ["cd-server"], /* inline comment */
            }, // Trailing comma
        }
    }
    """)
    
    servers = scanner.scan_client("claude_desktop")
    assert any(s.server_name == "cd_server" for s in servers)

def test_missing_and_corrupt_files(synthetic_17_client_tree):
    scanner = UniversalClientConfigScanner(root=synthetic_17_client_tree)
    
    # Write garbage file
    cd_dir = synthetic_17_client_tree / "Library/Application Support/Claude"
    cd_dir.mkdir(parents=True, exist_ok=True)
    (cd_dir / "claude_desktop_config.json").write_text("THIS IS NOT JSON")
    
    servers = scanner.scan_client("claude_desktop")
        
    assert len(servers) == 0

    all_servers = scanner.scan_all_clients()
    assert len(all_servers) >= 16

