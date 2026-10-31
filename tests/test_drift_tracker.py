import json
from pathlib import Path
from unittest.mock import patch

import pytest

from mcp_vulnerabilities.audit.drift import (
    build_inventory_snapshot_from_scan,
    save_baseline_snapshot,
    load_baseline_snapshot,
    compare_snapshots,
    InventorySnapshot,
    DiscoveredServer,
)
from mcp_vulnerabilities.audit.parsers import DiscoveredClientServer
from mcp_vulnerabilities.cli import main


@pytest.fixture
def mock_servers():
    return [
        DiscoveredClientServer(
            server_name="test-server",
            package_name="test-pkg",
            version="1.0.0",
            ecosystem="npm",
            command="npx",
            args=["-y", "test-pkg@1.0.0"],
            env={"API_KEY": "***"},
            declared_tools=[{"name": "test-tool"}]
        )
    ]


def test_build_inventory_snapshot(mock_servers):
    """INVARIANT_108_1: Verify inventory snapshot building from scan."""
    snapshot = build_inventory_snapshot_from_scan(mock_servers)
    assert snapshot.host_id == "local"
    assert len(snapshot.servers) == 1
    assert snapshot.servers[0].server_name == "test-server"
    assert snapshot.servers[0].package_name == "test-pkg"
    assert snapshot.servers[0].version == "1.0.0"
    assert snapshot.servers[0].env["API_KEY"] == "***"
    assert snapshot.servers[0].declared_tools == [{"name": "test-tool"}]


def test_save_and_load_baseline(tmp_path, mock_servers):
    """INVARIANT_108_1: Baseline round-trip serialization."""
    snapshot = build_inventory_snapshot_from_scan(mock_servers)
    baseline_path = tmp_path / "baseline.json"
    
    save_baseline_snapshot(snapshot, baseline_path)
    assert baseline_path.exists()
    
    loaded_snapshot = load_baseline_snapshot(baseline_path)
    assert loaded_snapshot.host_id == snapshot.host_id
    assert len(loaded_snapshot.servers) == 1
    assert loaded_snapshot.servers[0].server_name == "test-server"
    assert loaded_snapshot.servers[0].version == "1.0.0"
    assert loaded_snapshot.servers[0].declared_tools == [{"name": "test-tool"}]


def test_compare_snapshots_no_drift(mock_servers):
    """INVARIANT_108_2: Zero drift on unmodified systems."""
    snapshot1 = build_inventory_snapshot_from_scan(mock_servers)
    snapshot2 = build_inventory_snapshot_from_scan(mock_servers)
    
    diff_result = compare_snapshots(snapshot1, snapshot2)
    assert not diff_result.has_drift
    assert len(diff_result.details) == 0


def test_compare_snapshots_with_drift(mock_servers):
    """INVARIANT_108_3: Unauthorized shadow tool detection."""
    snapshot1 = build_inventory_snapshot_from_scan(mock_servers)
    
    mutated_servers = [
        DiscoveredClientServer(
            server_name="test-server",
            package_name="test-pkg",
            version="1.1.0",  # Mutated version
            ecosystem="npm",
            command="npx",
            args=["-y", "test-pkg@1.1.0"],
            env={"API_KEY": "***"},
            declared_tools=[{"name": "test-tool"}, {"name": "shadow_exfil"}]  # Added shadow tool
        )
    ]
    snapshot2 = build_inventory_snapshot_from_scan(mutated_servers)
    
    diff_result = compare_snapshots(snapshot1, snapshot2)
    assert diff_result.has_drift
    assert len(diff_result.details) == 1
    assert diff_result.details[0].server_name == "test-server"
    assert diff_result.details[0].status == "MODIFIED"
    assert "shadow_exfil" in diff_result.details[0].diff


def test_compare_snapshots_added_removed(mock_servers):
    snapshot1 = build_inventory_snapshot_from_scan(mock_servers)
    
    new_server = DiscoveredClientServer(
        server_name="new-server",
        package_name="new-pkg",
        version="2.0.0",
        ecosystem="npm",
        command="npx",
        args=[],
        env={},
        declared_tools=[]
    )
    snapshot2 = build_inventory_snapshot_from_scan([new_server])
    
    diff_result = compare_snapshots(snapshot1, snapshot2)
    assert diff_result.has_drift
    
    # We should have one ADDED (new-server) and one REMOVED (test-server)
    assert len(diff_result.details) == 2
    
    statuses = {d.status for d in diff_result.details}
    assert statuses == {"ADDED", "REMOVED"}


@patch("sys.argv", ["mcp-vuln", "audit", "--package", "@modelcontextprotocol/server-neo4j@0.6.1", "--diff", "nonexistent.json", "--fail-on-drift"])
@patch("sys.exit")
def test_cli_drift_exit_code_nonexistent(mock_exit):
    class TestExit(Exception): pass
    
    def side_effect(code=None):
        mock_exit.exit_code = code
        raise TestExit(f"exit({code})")
        
    mock_exit.side_effect = side_effect
    mock_exit.exit_code = None
    
    try:
        main()
    except TestExit:
        pass
    except Exception as e:
        print("Exception in test:", e)
        pass
    
    # Should exit with code 1 because nonexistent baseline loading fails
    assert mock_exit.exit_code == 1
    mock_exit.assert_called_with(1)


def test_cli_drift_fail_on_drift_detected(tmp_path, monkeypatch):
    """INVARIANT_108_4: CI Gate Enforcement via --fail-on-drift (exit code 2)."""
    # Create baseline snapshot with version 1.0.0
    baseline_server = DiscoveredServer(
        server_name="dummy-server",
        package_name="dummy-pkg",
        version="1.0.0",
        ecosystem="npm",
        command="npx",
        args=["dummy-pkg@1.0.0"]
    )
    baseline_snap = InventorySnapshot(
        host_id="local",
        servers=[baseline_server]
    )
    baseline_file = tmp_path / "baseline.json"
    save_baseline_snapshot(baseline_snap, baseline_file)

    exit_codes = []

    def mock_exit(code=0):
        exit_codes.append(code)
        raise SystemExit(code)

    monkeypatch.setattr("sys.exit", mock_exit)
    monkeypatch.setattr(
        "sys.argv",
        ["mcp-vuln", "audit", "--package", "dummy-pkg@2.0.0", "--diff", str(baseline_file), "--fail-on-drift"]
    )

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 2
