"""Incremental state and checkpoint management for vulnerability sync."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass
class SourceCheckpoint:
    """Checkpoint marker for an individual upstream vulnerability feed."""

    last_marker: str | None = None
    last_updated_at: str | None = None
    last_scan_utc: str | None = None
    records_scanned: int = 0
    records_synced: int = 0
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class SyncState:
    """Aggregated synchronization state across all upstream vulnerability feeds."""

    version: str = "1.0.0"
    last_global_sync_utc: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    sources: dict[str, SourceCheckpoint] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert state to serializable dictionary."""
        return {
            "version": self.version,
            "last_global_sync_utc": self.last_global_sync_utc,
            "sources": {k: asdict(v) for k, v in self.sources.items()},
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SyncState:
        """Construct SyncState from parsed dictionary."""
        raw_sources = data.get("sources", {})
        sources: dict[str, SourceCheckpoint] = {}
        for name, src_data in raw_sources.items():
            if isinstance(src_data, dict):
                sources[name] = SourceCheckpoint(
                    last_marker=src_data.get("last_marker"),
                    last_updated_at=src_data.get("last_updated_at"),
                    last_scan_utc=src_data.get("last_scan_utc"),
                    records_scanned=int(src_data.get("records_scanned", 0)),
                    records_synced=int(src_data.get("records_synced", 0)),
                    extra=src_data.get("extra", {}),
                )
        return cls(
            version=data.get("version", "1.0.0"),
            last_global_sync_utc=data.get("last_global_sync_utc", datetime.now(UTC).isoformat()),
            sources=sources,
        )


import logging
import os
import shutil

logger = logging.getLogger(__name__)


class SyncStateManager:
    """Manages loading, updating, and saving synchronization checkpoints."""

    def __init__(self, state_file: str | Path = "data/vulnerabilities/sync_state.json") -> None:
        self.state_file = Path(state_file)
        self.state: SyncState = self.load()

    def load(self) -> SyncState:
        """Load sync state from disk or initialize fresh state."""
        if self.state_file.is_file():
            try:
                content = self.state_file.read_text(encoding="utf-8")
                data = json.loads(content)
                return SyncState.from_dict(data)
            except Exception as e:
                logger.warning(f"Failed to load sync state from {self.state_file}: {e}")
                
                # Attempt to recover from backup
                bak_file = self.state_file.with_name(self.state_file.name + ".bak")
                if bak_file.is_file():
                    try:
                        logger.info(f"Attempting to recover from {bak_file}")
                        content = bak_file.read_text(encoding="utf-8")
                        data = json.loads(content)
                        recovered_state = SyncState.from_dict(data)
                        logger.info("Successfully recovered from backup.")
                        return recovered_state
                    except Exception as backup_err:
                        logger.warning(f"Failed to recover from backup {bak_file}: {backup_err}")

                return SyncState()
        return SyncState()

    def get_checkpoint(self, source_name: str) -> SourceCheckpoint:
        """Retrieve checkpoint for a specific source."""
        if source_name not in self.state.sources:
            self.state.sources[source_name] = SourceCheckpoint()
        return self.state.sources[source_name]

    def update_checkpoint(
        self,
        source_name: str,
        last_marker: str | None = None,
        last_updated_at: str | None = None,
        records_scanned: int | None = None,
        records_synced: int | None = None,
        extra: dict[str, Any] | None = None,
    ) -> SourceCheckpoint:
        """Update checkpoint for a specific source and stamp current UTC time."""
        chk = self.get_checkpoint(source_name)
        if last_marker is not None:
            chk.last_marker = last_marker
        if last_updated_at is not None:
            chk.last_updated_at = last_updated_at
        if records_scanned is not None:
            chk.records_scanned = records_scanned
        if records_synced is not None:
            chk.records_synced = records_synced
        if extra is not None:
            chk.extra.update(extra)

        chk.last_scan_utc = datetime.now(UTC).isoformat()
        self.state.last_global_sync_utc = chk.last_scan_utc
        return chk

    def save(self) -> None:
        """Persist current state to disk."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        data = self.state.to_dict()
        
        # Write to temporary file first
        tmp_file = self.state_file.with_suffix(f".tmp.{os.getpid()}")
        try:
            with open(tmp_file, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, sort_keys=True)
                f.flush()
                os.fsync(f.fileno())
            
            # Create a backup of the existing state file
            if self.state_file.exists():
                bak_file = self.state_file.with_name(self.state_file.name + ".bak")
                os.replace(self.state_file, bak_file)
                
            # Atomically replace the old state file with the new one
            os.replace(tmp_file, self.state_file)
        except Exception as e:
            logger.error(f"Error saving sync state: {e}")
            raise
        finally:
            if tmp_file.exists():
                try:
                    tmp_file.unlink()
                except OSError:
                    pass
