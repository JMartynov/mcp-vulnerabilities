"""Tests for Task 51: Universal 9-Client Audit and Global Package Discovery."""

import json
from pathlib import Path
import pytest

from mcp_vulnerabilities.audit.parsers import (
    ClientConfigParser,
    DiscoveredClientServer,
    UniversalClientConfigScanner,
)


@pytest.fixture
def mock_clients_dir(tmp_path):
    """Sets up synthetic configs for all 9 supported AI clients."""
    # 1. Claude Desktop
    claude_dir = tmp_path / "Library/Application Support/Claude"
    claude_dir.mkdir(parents=True)
    (claude_dir / "claude_desktop_config.json").write_text(json.dumps({
        "mcpServers": {
            "filesystem": {
                "command": "npx",
                "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.0"]
            }
        }
    }))

    # 2. Claude Code
    (tmp_path / ".claude.json").write_text(json.dumps({
        "mcpServers": {
            "git": {
                "command": "uvx",
                "args": ["mcp-server-git==0.1.0"]
            }
        }
    }))

    # 3. Cursor
    cursor_dir = tmp_path / ".cursor"
    cursor_dir.mkdir(parents=True)
    (cursor_dir / "mcp.json").write_text(json.dumps({
        "mcpServers": {
            "memory": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-memory@1.0.0"]
            }
        }
    }))

    # 4. VS Code
    vscode_dir = tmp_path / ".vscode"
    vscode_dir.mkdir(parents=True)
    (vscode_dir / "mcp.json").write_text(json.dumps({
        "servers": {
            "postgres": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-postgres@0.1.0"]
            }
        }
    }))

    # 5. Zed (context_servers schema)
    zed_dir = tmp_path / ".config/zed"
    zed_dir.mkdir(parents=True)
    (zed_dir / "settings.json").write_text(json.dumps({
        "context_servers": {
            "sqlite": {
                "command": {
                    "path": "uvx",
                    "args": ["mcp-server-sqlite==0.2.0"]
                }
            }
        }
    }))

    # 6. Cline
    cline_dir = tmp_path / "Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/settings"
    cline_dir.mkdir(parents=True)
    (cline_dir / "cline_mcp_settings.json").write_text(json.dumps({
        "mcpServers": {
            "fetch": {
                "command": "uvx",
                "args": ["mcp-server-fetch==0.1.0"]
            }
        }
    }))

    # 7. Windsurf
    windsurf_dir = tmp_path / ".codeium/windsurf"
    windsurf_dir.mkdir(parents=True)
    (windsurf_dir / "mcp_config.json").write_text(json.dumps({
        "mcpServers": {
            "brave": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-brave-search@0.2.0"]
            }
        }
    }))

    # 8. Continue
    continue_dir = tmp_path / ".continue"
    continue_dir.mkdir(parents=True)
    (continue_dir / "config.json").write_text(json.dumps({
        "mcpServers": {
            "puppeteer": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-puppeteer@0.4.0"]
            }
        }
    }))

    # 9. LibreChat (YAML format)
    (tmp_path / ".librechat").mkdir(parents=True)
    (tmp_path / ".librechat/librechat.yaml").write_text("""
mcpServers:
  docker-server:
    command: docker
    args:
      - run
      - -i
      - mcp/docker-server:1.0.0
""")

    # 10. OpenWebUI
    (tmp_path / ".openwebui").mkdir(parents=True)
    (tmp_path / ".openwebui/config.json").write_text(json.dumps({
        "mcpServers": {
            "slack": {
                "command": "npx",
                "args": ["@modelcontextprotocol/server-slack@0.5.0"]
            }
        }
    }))


    # 11. Copilot CLI
    (tmp_path / ".config/github-copilot").mkdir(parents=True)
    (tmp_path / ".config/github-copilot/mcp.json").write_text(json.dumps({
        "mcpServers": {
            "copilot": {
                "command": "npx",
                "args": ["@modelcontextprotocol/copilot@1.0.0"]
            }
        }
    }))

    # 12. TypingMind
    (tmp_path / "Library/Application Support/TypingMind").mkdir(parents=True)
    (tmp_path / "Library/Application Support/TypingMind/mcp.json").write_text(json.dumps({
        "mcpServers": {
            "typing": {
                "command": "npx",
                "args": ["@modelcontextprotocol/typing@1.0.0"]
            }
        }
    }))

    # 13. Chatbox
    (tmp_path / "Library/Application Support/chatbox").mkdir(parents=True)
    (tmp_path / "Library/Application Support/chatbox/mcp.json").write_text(json.dumps({
        "mcpServers": {
            "chat": {
                "command": "npx",
                "args": ["@modelcontextprotocol/chat@1.0.0"]
            }
        }
    }))

    # 14. Bolt
    (tmp_path / ".bolt").mkdir(parents=True)
    (tmp_path / ".bolt/mcp.json").write_text(json.dumps({
        "mcpServers": {
            "bolt_server": {
                "command": "npx",
                "args": ["@modelcontextprotocol/bolt@1.0.0"]
            }
        }
    }))

    # 15. Jan
    (tmp_path / "Library/Application Support/jan").mkdir(parents=True)
    (tmp_path / "Library/Application Support/jan/mcp.json").write_text(json.dumps({
        "mcpServers": {
            "jan_server": {
                "command": "npx",
                "args": ["@modelcontextprotocol/jan@1.0.0"]
            }
        }
    }))

    # 16. Enso
    (tmp_path / ".enso").mkdir(parents=True)
    (tmp_path / ".enso/mcp.json").write_text(json.dumps({
        "mcpServers": {
            "enso_server": {
                "command": "npx",
                "args": ["@modelcontextprotocol/enso@1.0.0"]
            }
        }
    }))

    # 17. Sourcegraph Cody
    (tmp_path / ".config/Code/User/globalStorage/sourcegraph.cody-ai").mkdir(parents=True)
    (tmp_path / ".config/Code/User/globalStorage/sourcegraph.cody-ai/mcp.json").write_text(json.dumps({
        "mcpServers": {
            "cody_server": {
                "command": "npx",
                "args": ["@modelcontextprotocol/cody@1.0.0"]
            }
        }
    }))
    
    # 18. Roo Code
    roo_dir = tmp_path / "Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/settings"
    roo_dir.mkdir(parents=True)
    (roo_dir / "cline_mcp_settings.json").write_text(json.dumps({
        "mcpServers": {
            "roo-server": {
                "command": "npx",
                "args": ["roo-server@1.0.0"]
            }
        }
    }))

    # 19. Goose
    goose_dir = tmp_path / ".config/goose"
    goose_dir.mkdir(parents=True)
    (goose_dir / "config.yaml").write_text('''
mcpServers:
  goose-server:
    command: npx
    args:
      - goose-server@1.0.0
''')

    return tmp_path


def test_universal_scanner_discovers_all_clients(mock_clients_dir):
    scanner = UniversalClientConfigScanner(root=mock_clients_dir)
    servers = scanner.scan_all_clients()

    server_names = {s.server_name for s in servers}
    assert "filesystem" in server_names  # Claude Desktop
    assert "git" in server_names         # Claude Code
    assert "memory" in server_names      # Cursor
    assert "postgres" in server_names    # VS Code
    assert "sqlite" in server_names      # Zed
    assert "fetch" in server_names       # Cline
    assert "brave" in server_names       # Windsurf
    assert "puppeteer" in server_names   # Continue
    assert "docker-server" in server_names  # LibreChat
    assert "slack" in server_names       # OpenWebUI
    assert "copilot" in server_names
    assert "typing" in server_names
    assert "chat" in server_names
    assert "bolt_server" in server_names
    assert "jan_server" in server_names
    assert "enso_server" in server_names
    assert "cody_server" in server_names
    assert "roo-server" in server_names
    assert "goose-server" in server_names

    assert len(servers) >= 17


def test_universal_scanner_specific_client(mock_clients_dir):
    scanner = UniversalClientConfigScanner(root=mock_clients_dir)
    zed_servers = scanner.scan_client("zed")
    assert len(zed_servers) == 1
    assert zed_servers[0].server_name == "sqlite"
    assert zed_servers[0].package_name == "mcp-server-sqlite"
    assert zed_servers[0].version == "0.2.0"
    assert zed_servers[0].ecosystem == "PyPI"


def test_malformed_config_graceful_handling(tmp_path):
    bad_dir = tmp_path / ".cursor"
    bad_dir.mkdir(parents=True)
    bad_file = bad_dir / "mcp.json"
    bad_file.write_text("NOT VALID JSON {{{")

    scanner = UniversalClientConfigScanner(root=tmp_path)
    res = scanner.scan_client("cursor")
    assert res == []


def test_global_npm_scanner_discovery():
    scanner = UniversalClientConfigScanner()
    # Should run without exceptions even if no global npm packages are installed
    global_servers = scanner.scan_global()
    assert isinstance(global_servers, list)
