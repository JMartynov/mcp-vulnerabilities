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
