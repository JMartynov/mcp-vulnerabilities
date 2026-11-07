import curses
import argparse
from unittest.mock import MagicMock, patch

from mcp_vulnerabilities.audit.tui import McpTuiExplorer

def test_tui_initialization_headless():
    stdscr_mock = MagicMock()
    stdscr_mock.getmaxyx.return_value = (40, 100)
    args = argparse.Namespace(config=None, theme="dark", no_color=False)
    
    app = McpTuiExplorer(stdscr_mock, args, is_test=True)
    
    # Assert defaults
    assert app.focus_left is True
    assert app.selected_idx == 0
    assert app.scroll_offset == 0
    assert app.is_searching is False

def test_tui_navigation_keys():
    stdscr_mock = MagicMock()
    stdscr_mock.getmaxyx.return_value = (40, 100)
    args = argparse.Namespace(config=None, theme="dark", no_color=False)
    
    app = McpTuiExplorer(stdscr_mock, args, is_test=True)
    
    # Mock some data
    mock_server1 = MagicMock()
    mock_server1.spec.tools = [MagicMock(), MagicMock()]
    mock_server1.client = "client"
    mock_server1.server_name = "server"
    
    mock_server2 = MagicMock()
    app.filtered_servers = [mock_server1, mock_server2]
    app.servers = [mock_server1, mock_server2]
    app.height = 10
    app.findings = {}
    
    # Move down
    app.handle_keystroke(ord('j'))
    assert app.selected_idx == 1
    
    # Move down again (should stop at bottom)
    app.handle_keystroke(ord('j'))
    assert app.selected_idx == 1
    
    # Move up
    app.handle_keystroke(ord('k'))
    assert app.selected_idx == 0
    
    # Tab to switch focus
    app.handle_keystroke(ord('\t'))
    assert app.focus_left is False
    
    # Move down in details pane
    app.handle_keystroke(ord('j'))
    assert app.detail_scroll == 1

def test_tui_search_filter():
    stdscr_mock = MagicMock()
    args = argparse.Namespace(config=None, theme="dark", no_color=False)
    app = McpTuiExplorer(stdscr_mock, args, is_test=True)
    
    s1 = MagicMock()
    s1.server_name = "sqlite"
    s1.client = "cursor"
    
    s2 = MagicMock()
    s2.server_name = "github"
    s2.client = "claude"
    
    app.servers = [s1, s2]
    app.findings = {}
    app._apply_filter()
    assert len(app.filtered_servers) == 2
    
    # Start search
    app.handle_keystroke(ord('/'))
    assert app.is_searching is True
    
    # Type 'g'
    app.handle_keystroke(ord('g'))
    assert app.search_query == 'g'
    assert len(app.filtered_servers) == 1
    assert app.filtered_servers[0] == s2
    
    # Backspace
    app.handle_keystroke(curses.KEY_BACKSPACE)
    assert app.search_query == ''
    assert len(app.filtered_servers) == 2
    
    # Escape
    app.handle_keystroke(27)
    assert app.is_searching is False

@patch("mcp_vulnerabilities.audit.tui.ClientConfigFixer")
def test_tui_autofix_hotkey(mock_fixer):
    stdscr_mock = MagicMock()
    args = argparse.Namespace(config=None, theme="dark", no_color=False)
    app = McpTuiExplorer(stdscr_mock, args, is_test=True)
    
    s1 = MagicMock()
    s1.config_path = "/tmp/mock/config.json"
    app.filtered_servers = [s1]
    app.selected_idx = 0
    
    # Trigger 'f'
    app.handle_keystroke(ord('f'))
    
    mock_fixer.fix_config.assert_called_once_with("/tmp/mock/config.json", dry_run=False)
    assert "✅" in app.status_msg

@patch("mcp_vulnerabilities.audit.tui.SecurityPicture")
def test_tui_save_picture_hotkey(mock_sec_pic):
    stdscr_mock = MagicMock()
    args = argparse.Namespace(config=None, theme="dark", no_color=False)
    app = McpTuiExplorer(stdscr_mock, args, is_test=True)
    
    mock_pic_instance = MagicMock()
    mock_sec_pic.capture.return_value = mock_pic_instance
    
    # Trigger 'p'
    app.handle_keystroke(ord('p'))
    
    mock_sec_pic.capture.assert_called_once()
    mock_pic_instance.save.assert_called_once()
    assert "✅" in app.status_msg

@patch("subprocess.Popen")
def test_tui_copy_config(mock_popen):
    stdscr_mock = MagicMock()
    args = argparse.Namespace(config=None, theme="dark", no_color=False)
    app = McpTuiExplorer(stdscr_mock, args, is_test=True)
    # override is_test for the copy to work
    app.is_test = False 
    
    s1 = MagicMock()
    s1.command = "node"
    s1.args = ["index.js"]
    s1.env = {"API_KEY": "supersecret123"}
    app.filtered_servers = [s1]
    
    mock_proc = MagicMock()
    mock_popen.return_value = mock_proc
    
    # Trigger 'c'
    app.handle_keystroke(ord('c'))
    
    # Reset is_test
    app.is_test = True
    
    mock_popen.assert_called()
    assert "✅" in app.status_msg
    # Ensure sensitive token is not in the communicated string
    args, kwargs = mock_proc.communicate.call_args
    assert b"supersecret123" not in kwargs["input"]
    assert b"***REDACTED***" in kwargs["input"]


def test_tui_real_advisory_matching():
    stdscr_mock = MagicMock()
    args = argparse.Namespace(config=None, theme="dark", no_color=False)
    app = McpTuiExplorer(stdscr_mock, args, is_test=True)

    # Assert real OSV advisories were loaded into matcher
    assert len(app.matcher.advisories) > 0

    # Pick a valid indexed package to construct a matching test server
    valid_key = next((k for k in app.matcher._package_index if k and k != "n/a"), None)
    assert valid_key is not None
    adv = app.matcher._package_index[valid_key][0]
    aff = adv.get("affected", [{}])[0]
    pkg_name = aff.get("package", {}).get("name", valid_key)
    eco = aff.get("package", {}).get("ecosystem")

    from mcp_vulnerabilities.audit.parsers import DiscoveredClientServer
    server = DiscoveredClientServer(
        server_name="vulnerable_test_server",
        package_name=pkg_name,
        version=None,  # Unpinned triggers vulnerability
        ecosystem=eco,
        command="npx",
        args=[pkg_name],
        client_name="claude"
    )

    app.servers = [server]
    app._audit_servers()

    key = f"claude:{server.server_name}"
    assert key in app.findings
    assert len(app.findings[key]) > 0
    badge, color = app._get_server_badge(server)
    assert badge in ("[CRIT]", "[HIGH]", "[MED]")
    ascii_badge = app._get_ascii_badge(server)
    assert ascii_badge != "[CLEAN]"


def test_tui_config_isolation(tmp_path):
    import json
    cfg_file = tmp_path / "custom_client_config.json"
    cfg_content = {
        "mcpServers": {
            "isolated_db": {
                "command": "python",
                "args": ["-m", "db_server"]
            }
        }
    }
    cfg_file.write_text(json.dumps(cfg_content))

    stdscr_mock = MagicMock()
    args = argparse.Namespace(config=str(cfg_file), theme="dark", no_color=False)
    app = McpTuiExplorer(stdscr_mock, args, is_test=True)

    # Load data with config specified
    app._load_data()

    # Verify only the isolated config was loaded
    assert len(app.servers) == 1
    assert app.servers[0].server_name == "isolated_db"


def test_tui_header_text_formatting():
    import platform
    from mcp_vulnerabilities.audit.matcher import AuditFinding
    from mcp_vulnerabilities.audit.parsers import DiscoveredClientServer

    stdscr_mock = MagicMock()
    args = argparse.Namespace(config=None, theme="dark", no_color=False)
    app = McpTuiExplorer(stdscr_mock, args, is_test=True)

    # Initial state: 0 servers, no findings -> SECURE
    subtitle = app._get_header_subtitle()
    assert f"OS: {platform.system()}" in subtitle
    assert "Discovered: 0 Servers" in subtitle
    assert "Posture: SECURE" in subtitle

    server = DiscoveredClientServer(
        server_name="srv1",
        package_name="pkg1",
        version="1.0.0",
        ecosystem="npm",
        command="node",
        args=[],
        client_name="cursor"
    )
    app.servers = [server]

    # Add a CRITICAL finding
    crit_finding = MagicMock(spec=AuditFinding)
    crit_finding.severity_level = "CRITICAL"
    app.findings = {"cursor:srv1": [crit_finding]}

    crit_subtitle = app._get_header_subtitle()
    assert "Discovered: 1 Servers" in crit_subtitle
    assert "Posture: CRITICAL" in crit_subtitle

    # Change to HIGH finding
    high_finding = MagicMock(spec=AuditFinding)
    high_finding.severity_level = "HIGH"
    app.findings = {"cursor:srv1": [high_finding]}

    high_subtitle = app._get_header_subtitle()
    assert "Posture: HIGH" in high_subtitle

    # Change to MEDIUM finding
    med_finding = MagicMock(spec=AuditFinding)
    med_finding.severity_level = "MEDIUM"
    app.findings = {"cursor:srv1": [med_finding]}

    med_subtitle = app._get_header_subtitle()
    assert "Posture: WARNING" in med_subtitle


def test_tui_network_scanner_integration():
    import asyncio
    from unittest.mock import AsyncMock

    stdscr_mock = MagicMock()
    args = argparse.Namespace(config=None, target="127.0.0.1", ports="8000", theme="dark", no_color=False)
    app = McpTuiExplorer(stdscr_mock, args, is_test=True)

    # Mock net_scanner.scan_target to return a discovered MCP handshake listener
    app.net_scanner.scan_target = AsyncMock(return_value=[
        {
            "host": "127.0.0.1",
            "port": 8000,
            "path": "/sse",
            "mcp_handshake": True,
            "url": "http://127.0.0.1:8000/sse",
            "tools": [{"name": "live_tool", "description": "Active network tool"}]
        }
    ])

    # Explicitly run network scan block by mocking is_test=False during _load_data
    app.is_test = False
    with patch.object(app.scanner, "scan_all_clients", return_value=[]):
        app._load_data()
    app.is_test = True

    assert len(app.servers) == 1
    assert app.servers[0].client_name == "network"
    assert app.servers[0].server_name == "127.0.0.1:8000/sse"
    assert app.servers[0].url == "http://127.0.0.1:8000/sse"
    assert len(app.servers[0].declared_tools) == 1

