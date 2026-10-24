import pytest
import sys
import subprocess
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
import sys
import subprocess
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

# Mock mcp_fingerprints before anything else is imported
import sys
sys.modules['mcp_fingerprints'] = MagicMock()
sys.modules['mcp_fingerprints.models'] = MagicMock()
sys.modules['mcp_fingerprints.config_scanner'] = MagicMock()
sys.modules['mcp_fingerprints.models.ServerPackageSpec'] = MagicMock()

import mcp_vulnerabilities.audit.hub
from mcp_vulnerabilities.audit.hub import run_hub, sanitize_ansi

def test_invariant_1a_non_tty_fallback():
    # Run hub in non-TTY (pipe)
    # the CLI wrapper might output to stdout, which triggers the non-TTY fallback.
    # we need to ensure it runs cleanly and doesn't crash or print curses/termios.
    # We will invoke the main CLI via subprocess.
    result = subprocess.run(
        [sys.executable, "-m", "mcp_vulnerabilities.cli", "hub"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    # The command should exit cleanly without crashing.
    # It might exit 0 or 1 depending on whether vulnerabilities were found,
    # but it must not crash due to tty errors.
    assert result.returncode in (0, 1)
    # It must not complain about requiring an interactive terminal anymore.
    assert "Interactive hub requires an interactive TTY terminal" not in result.stdout
    assert "Interactive hub requires an interactive TTY terminal" not in result.stderr

def test_invariant_1b_automated_flag_json():
    # Because mcp_fingerprints is missing in this test env, mocking sys.argv 
    # and running hub directly is more reliable than subprocess.
    with patch("sys.argv", ["mcp-vuln", "hub", "--json"]), \
         patch("sys.stdout.isatty", return_value=True), \
         patch("mcp_vulnerabilities.audit.hub.sys.exit") as mock_exit:
         
        # we mock mcp_vulnerabilities.cli.main manually without relying on patch
        # which imports it eagerly.
        mock_cli_main = MagicMock()
        import sys
        sys.modules["mcp_vulnerabilities.cli"] = MagicMock()
        sys.modules["mcp_vulnerabilities.cli"].main = mock_cli_main
        
        args_mock = MagicMock()
        args_mock.json = True
        args_mock.batch = False
        mcp_vulnerabilities.audit.hub.run_hub(args_mock)
        
        # Should fallback to automated json audit
        assert sys.argv == ["mcp-vuln", "audit", "--format", "json"]
        mock_cli_main.assert_called_once()

def test_invariant_2a_2b_diff_preview_and_selection():
    # Test `do_fix_multi_client` directly via mock to simulate multi-client selection
    with patch("mcp_vulnerabilities.audit.hub.input", return_value="0"), \
         patch("mcp_vulnerabilities.audit.hub.print") as mock_print, \
         patch("mcp_vulnerabilities.audit.fixer.ClientConfigFixer.fix_all_clients") as mock_fix_all, \
         patch("mcp_vulnerabilities.audit.fixer.ClientConfigFixer.fix_config") as mock_fix_config:
         
        mock_fix_all.return_value = [
            {
                "status": "dry_run",
                "client": "claude",
                "path": "/fake/claude.json",
                "changes": [{"server_name": "vuln-server", "old_version": "1.0", "new_version": "2.0"}],
                "diff": "--- a/claude.json\n+++ b/claude.json\n- 1.0\n+ 2.0"
            },
            {
                "status": "dry_run",
                "client": "cursor",
                "path": "/fake/cursor.json",
                "changes": [{"server_name": "vuln-server2", "old_version": "1.0", "new_version": "3.0"}],
                "diff": "--- a/cursor.json\n+++ b/cursor.json\n- 1.0\n+ 3.0"
            }
        ]
        
        mcp_vulnerabilities.audit.hub.do_fix_multi_client()
        
        # Check that we requested diff prints
        diff_printed = any("--- a/claude.json" in call[0][0] for call in mock_print.call_args_list)
        assert diff_printed
        
        # Check that only the first client (claude) was fixed
        mock_fix_config.assert_called_once()
        assert mock_fix_config.call_args[0][0] == Path("/fake/claude.json")
        assert mock_fix_config.call_args[1]["dry_run"] is False

def test_invariant_3a_terminal_restoration_on_sigint():
    # Ensure handle_sigint calls restore_terminal and exits
    with patch("mcp_vulnerabilities.audit.hub.restore_terminal") as mock_restore, \
         patch("sys.exit") as mock_exit:
         
        mcp_vulnerabilities.audit.hub.handle_sigint(None, None)
        
        mock_restore.assert_called_once()
        mock_exit.assert_called_once_with(0)

def test_invariant_3b_ansi_injection_sanitization():
    # Test that ANSI escape characters are stripped
    dirty_string = "\x1b[31mDanger\x1b[0m \x1b[2JCVE-2023-1234"
    clean_string = sanitize_ansi(dirty_string)
    
    assert "\x1b" not in clean_string
    assert clean_string == "Danger CVE-2023-1234"

