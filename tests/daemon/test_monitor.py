import asyncio
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Monkey patch sys.modules to mock mcp_fingerprints for test isolation
@pytest.fixture(autouse=True, scope="session")
def mock_mcp_fingerprints_module():
    mock_mcp = MagicMock()
    mock_mcp.config_scanner = MagicMock()
    mock_mcp.config_scanner.ConfigScanner = MagicMock
    mock_mcp.config_scanner.NpmGlobalScanner = MagicMock
    mock_mcp.models = MagicMock()
    mock_mcp.snapshot_diff = MagicMock()
    sys.modules['mcp_fingerprints'] = mock_mcp
    sys.modules['mcp_fingerprints.config_scanner'] = mock_mcp.config_scanner
    sys.modules['mcp_fingerprints.models'] = mock_mcp.models
    sys.modules['mcp_fingerprints.snapshot_diff'] = mock_mcp.snapshot_diff

# DO it immediately as well to avoid collection time error
mock_mcp = MagicMock()
mock_mcp.config_scanner = MagicMock()
mock_mcp.config_scanner.ConfigScanner = MagicMock
mock_mcp.config_scanner.NpmGlobalScanner = MagicMock
mock_mcp.models = MagicMock()
mock_mcp.snapshot_diff = MagicMock()
sys.modules['mcp_fingerprints'] = mock_mcp
sys.modules['mcp_fingerprints.config_scanner'] = mock_mcp.config_scanner
sys.modules['mcp_fingerprints.models'] = mock_mcp.models
sys.modules['mcp_fingerprints.snapshot_diff'] = mock_mcp.snapshot_diff


from mcp_vulnerabilities.audit.parsers import DiscoveredClientServer
from mcp_vulnerabilities.audit.picture import SecurityPicture
from mcp_vulnerabilities.daemon.monitor import (
    AlertDispatcher,
    McpMonitorDaemon,
    MonitorConfig,
    check_status,
    parse_ports_spec,
    start_monitor,
    stop_monitor,
)

@pytest.fixture
def tmp_config(tmp_path):
    pid_file = tmp_path / "monitor.pid"
    log_file = tmp_path / "monitor.log"
    baseline_path = tmp_path / "security_picture.json"
    alert_cache_file = tmp_path / "alert_cache.json"

    return MonitorConfig(
        interval_seconds=1,
        targets="localhost",
        ports_spec="3000,8000-8002",
        notify_os=True,
        webhook_url="https://example.invalid/slack-webhook",
        pid_file=pid_file,
        log_file=log_file,
        baseline_path=baseline_path,
        debounce_window_sec=3600,
        alert_cache_file=alert_cache_file,
    )


def test_parse_ports_spec():
    assert parse_ports_spec("3000") == [3000]
    assert parse_ports_spec("3000,8000") == [3000, 8000]
    assert parse_ports_spec("8000-8002") == [8000, 8001, 8002]
    assert parse_ports_spec("3000, 8000-8002") == [3000, 8000, 8001, 8002]
    assert parse_ports_spec("") == []


def test_alert_dispatcher_debounce(tmp_config):
    dispatcher = AlertDispatcher(tmp_config)
    alert_id = "test_alert_1"

    assert not dispatcher._is_debounced(alert_id)

    dispatcher._mark_alert(alert_id)
    assert dispatcher._is_debounced(alert_id)

    # Modify debounce window to simulate time passing
    tmp_config.debounce_window_sec = -1
    assert not dispatcher._is_debounced(alert_id)


@patch("mcp_vulnerabilities.daemon.monitor.subprocess.run")
@patch("mcp_vulnerabilities.daemon.monitor.urllib.request.urlopen")
def test_alert_dispatcher_dispatch(mock_urlopen, mock_run, tmp_config):
    dispatcher = AlertDispatcher(tmp_config)
    alert_id = "test_alert_2"
    payload = {"test": "data"}

    # Mock response for urlopen
    mock_resp = MagicMock()
    mock_urlopen.return_value.__enter__.return_value = mock_resp

    dispatcher.dispatch("Test Title", "Test Message", "CRITICAL", alert_id, payload)

    # Should call subprocess for notify-send/osascript depending on platform
    assert mock_run.called
    
    # Should call urlopen for webhook
    assert mock_urlopen.called

    # Should be debounced now
    assert dispatcher._is_debounced(alert_id)
    mock_run.reset_mock()
    mock_urlopen.reset_mock()

    # Second call should be debounced
    dispatcher.dispatch("Test Title", "Test Message", "CRITICAL", alert_id, payload)
    assert not mock_run.called
    assert not mock_urlopen.called


@patch("mcp_vulnerabilities.daemon.monitor.os.kill")
def test_check_status_and_stop(mock_kill, tmp_config):
    pid_file = tmp_config.pid_file
    
    # Not existing
    assert not check_status(pid_file)
    assert not stop_monitor(pid_file)
    
    # Existing
    pid_file.write_text("12345")
    assert check_status(pid_file)
    
    # Stop
    # Mocking os.kill to succeed on SIGTERM, but fail on 0 to simulate process exit
    def side_effect(pid, sig):
        if sig == 0:
            raise OSError("No such process")
        return None
        
    mock_kill.side_effect = side_effect
    assert stop_monitor(pid_file)
    assert not pid_file.exists()


@patch("mcp_vulnerabilities.daemon.monitor.NetworkMCPScanner")
@patch("mcp_vulnerabilities.daemon.monitor.UniversalClientConfigScanner")
def test_run_monitoring_cycle(mock_client_scanner_cls, mock_net_scanner_cls, tmp_config):
    mock_net_scanner = AsyncMock()
    mock_net_scanner.scan_target.return_value = [
        {"host": "localhost", "port": 8000, "path": "/sse", "mcp_handshake": True}
    ]
    mock_net_scanner_cls.return_value = mock_net_scanner
    
    mock_client_scanner = MagicMock()
    mock_client_scanner.scan_all_clients.return_value = [
        DiscoveredClientServer(
            server_name="test-server",
            package_name="test-server",
            version="1.0.0",
            ecosystem="npm",
            command="npx",
            args=["run", "test-server"]
        )
    ]
    mock_client_scanner_cls.return_value = mock_client_scanner

    daemon = McpMonitorDaemon(tmp_config)
    
    # First run, no baseline -> saves baseline, returns None
    diff = asyncio.run(daemon.run_monitoring_cycle())
    assert diff is None
    assert tmp_config.baseline_path.exists()
    
    # Modify baseline slightly - wait, SecurityPictureDiffer checks added/removed, CVEs, tamper status, tool hash.
    # It doesn't check version drift directly! It checks version drift indirectly?
    # Let's check SecurityPictureDiffer.compare in picture_diff.py
    # Ah, it only adds to newly_introduced_vulnerabilities if confirmed_cves differ
    # Let's mock a CVE introduction to trigger drift
    baseline = SecurityPicture.load(tmp_config.baseline_path)
    baseline.servers[0].confirmed_cves = ["CVE-2023-1234"]
    baseline.save(tmp_config.baseline_path)
    
    # Second run, should detect drift
    diff = asyncio.run(daemon.run_monitoring_cycle())
    assert diff is not None
    assert diff.is_drift_detected


@patch("mcp_vulnerabilities.daemon.monitor.McpMonitorDaemon")
def test_start_monitor_cli(mock_daemon_cls, tmp_config):
    class Args:
        def __init__(self, **kwargs):
            for k, v in kwargs.items():
                setattr(self, k, v)
                
    # Start monitor
    args = Args(
        daemon=False,
        interval=10,
        targets="127.0.0.1",
        ports="3000",
        notify=True,
        webhook="http://test",
        pid_file=str(tmp_config.pid_file),
        log_file=str(tmp_config.log_file)
    )
    
    start_monitor(args)
    
    mock_daemon_cls.assert_called_once()
    daemon_instance = mock_daemon_cls.return_value
    daemon_instance.start.assert_called_once_with(daemon=False)
