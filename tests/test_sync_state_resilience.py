"""Unit tests for resilient sync state management."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from mcp_vulnerabilities.state import SyncStateManager


def test_atomic_write_and_backup_creation() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        state_file = Path(tmpdir) / "sync_state.json"
        bak_file = Path(tmpdir) / "sync_state.json.bak"
        
        mgr = SyncStateManager(state_file=state_file)
        mgr.update_checkpoint("dummy_source", last_marker="12345")
        
        # Save should create the state file, but initially no backup 
        # (since there was no prior file to backup)
        mgr.save()
        assert state_file.is_file()
        assert not bak_file.is_file()
        
        # Save again should now create a backup of the previous state
        mgr.update_checkpoint("dummy_source", last_marker="67890")
        mgr.save()
        
        assert state_file.is_file()
        assert bak_file.is_file()
        
        # Verify state file has new data, backup has old data
        data_new = json.loads(state_file.read_text(encoding="utf-8"))
        data_old = json.loads(bak_file.read_text(encoding="utf-8"))
        
        assert data_new["sources"]["dummy_source"]["last_marker"] == "67890"
        assert data_old["sources"]["dummy_source"]["last_marker"] == "12345"


def test_corrupted_json_recovery() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        state_file = Path(tmpdir) / "sync_state.json"
        bak_file = Path(tmpdir) / "sync_state.json.bak"
        
        mgr = SyncStateManager(state_file=state_file)
        mgr.update_checkpoint("dummy_source", last_marker="valid_data")
        mgr.save()
        
        # Trigger creation of backup
        mgr.update_checkpoint("dummy_source", last_marker="valid_data_2")
        mgr.save()
        
        # Corrupt the main state file
        state_file.write_text("invalid json {", encoding="utf-8")
        
        # Reloading should fallback to the backup file
        reloaded_mgr = SyncStateManager(state_file=state_file)
        
        # It should recover the state from the backup file
        assert "dummy_source" in reloaded_mgr.state.sources
        assert reloaded_mgr.state.sources["dummy_source"].last_marker == "valid_data"


def test_missing_state_file_returns_default() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        state_file = Path(tmpdir) / "sync_state.json"
        
        # File doesn't exist
        mgr = SyncStateManager(state_file=state_file)
        
        assert mgr.state.version == "1.0.0"
        assert len(mgr.state.sources) == 0


def test_corrupted_json_and_no_backup_returns_default() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        state_file = Path(tmpdir) / "sync_state.json"
        
        # Create corrupted file without a backup
        state_file.write_text("invalid json {", encoding="utf-8")
        
        mgr = SyncStateManager(state_file=state_file)
        
        assert mgr.state.version == "1.0.0"
        assert len(mgr.state.sources) == 0
