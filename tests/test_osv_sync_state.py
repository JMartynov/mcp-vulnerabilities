"""Unit tests for incremental vulnerability sync checkpoint state management."""

from __future__ import annotations

import tempfile
from pathlib import Path

from mcp_vulnerabilities.state import SyncStateManager


def test_sync_state_manager_initialization_and_persistence() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        state_file = Path(tmpdir) / "sync_state.json"
        mgr = SyncStateManager(state_file=state_file)

        # Fresh state
        assert mgr.state.version == "1.0.0"
        assert len(mgr.state.sources) == 0

        # Update cvelist_v5 checkpoint
        chk1 = mgr.update_checkpoint(
            "cvelist_v5",
            last_marker="cves/2025/10xxx/CVE-2025-10193.json",
            records_scanned=500,
            records_synced=3,
            extra={"commit": "abc1234"},
        )
        assert chk1.last_marker == "cves/2025/10xxx/CVE-2025-10193.json"
        assert chk1.records_scanned == 500
        assert chk1.records_synced == 3
        assert chk1.extra["commit"] == "abc1234"
        assert chk1.last_scan_utc is not None

        # Update nvd checkpoint
        mgr.update_checkpoint(
            "nvd_api",
            last_marker="CVE-2025-6514",
            last_updated_at="2026-08-22T00:00:00Z",
            records_scanned=20,
            records_synced=5,
        )

        # Save to disk
        mgr.save()
        assert state_file.is_file()

        # Reload from disk
        mgr2 = SyncStateManager(state_file=state_file)
        assert len(mgr2.state.sources) == 2
        reloaded_cve = mgr2.get_checkpoint("cvelist_v5")
        assert reloaded_cve.last_marker == "cves/2025/10xxx/CVE-2025-10193.json"
        assert reloaded_cve.records_scanned == 500
        assert reloaded_cve.records_synced == 3

        reloaded_nvd = mgr2.get_checkpoint("nvd_api")
        assert reloaded_nvd.last_marker == "CVE-2025-6514"
        assert reloaded_nvd.last_updated_at == "2026-08-22T00:00:00Z"
