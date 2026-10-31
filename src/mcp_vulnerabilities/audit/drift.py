from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from mcp_vulnerabilities.audit.parsers import DiscoveredClientServer

logger = logging.getLogger(__name__)

# Try to import from mcp_fingerprints if available
try:
    from mcp_fingerprints.snapshot_diff import (
        InventorySnapshot as FpInventorySnapshot,
        DiscoveredServer as FpDiscoveredServer,
        compare_snapshots as fp_compare_snapshots,
        DiffResult as FpDiffResult,
        ServerDriftDetail as FpServerDriftDetail
    )
    HAS_FP = True
except ImportError:
    HAS_FP = False


@dataclass
class DiscoveredServer:
    server_name: str
    package_name: Optional[str] = None
    version: Optional[str] = None
    ecosystem: Optional[str] = None
    command: Optional[str] = None
    args: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    declared_tools: list[dict[str, Any]] = field(default_factory=list)
    client_name: str = "local"
    url: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    tools: list[Any] = field(default_factory=list)
    toolset_canonical_hash: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_name": self.server_name,
            "package_name": self.package_name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "command": self.command,
            "args": self.args,
            "env": self.env,
            "declared_tools": self.declared_tools,
            "client_name": self.client_name,
            "tools": [t.to_dict() if hasattr(t, "to_dict") else t for t in self.tools],
            "toolset_canonical_hash": self.toolset_canonical_hash,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> DiscoveredServer:
        return cls(
            server_name=data.get("server_name", ""),
            package_name=data.get("package_name"),
            version=data.get("version"),
            ecosystem=data.get("ecosystem"),
            command=data.get("command"),
            args=data.get("args", []),
            env=data.get("env", {}),
            declared_tools=data.get("declared_tools", []),
            client_name=data.get("client_name", "local"),
            tools=data.get("tools", []),
            toolset_canonical_hash=data.get("toolset_canonical_hash"),
        )


@dataclass
class ServerDriftDetail:
    server_name: str
    status: str  # "ADDED", "REMOVED", "MODIFIED"
    diff: str
    client_name: str = "local"
    old_version: Optional[str] = None
    new_version: Optional[str] = None
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    changes: list[str] = field(default_factory=list)

    @property
    def has_drift(self) -> bool:
        return bool(self.old_version != self.new_version or self.old_hash != self.new_hash or self.changes or self.diff)


@dataclass
class DiffResult:
    has_drift: bool
    details: list[ServerDriftDetail]
    added_servers: list[Any] = field(default_factory=list)
    removed_servers: list[Any] = field(default_factory=list)
    modified_servers: list[ServerDriftDetail] = field(default_factory=list)

    @property
    def has_changes(self) -> bool:
        return self.has_drift or bool(self.added_servers or self.removed_servers or self.modified_servers)

    @property
    def drift_count(self) -> int:
        return len(self.details)


@dataclass
class InventorySnapshot:
    host_id: str = "local"
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    servers: list[DiscoveredServer] = field(default_factory=list)
    snapshot_version: str = "1.0.0"

    @property
    def host_identifier(self) -> str:
        return self.host_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "snapshot_version": self.snapshot_version,
            "host_id": self.host_id,
            "host_identifier": self.host_id,
            "timestamp": self.timestamp,
            "servers": [s.to_dict() for s in self.servers]
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> InventorySnapshot:
        servers_data = data.get("servers", [])
        servers = [DiscoveredServer.from_dict(s) if isinstance(s, dict) else s for s in servers_data]
        return cls(
            snapshot_version=data.get("snapshot_version", "1.0.0"),
            host_id=data.get("host_id") or data.get("host_identifier", "local"),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            servers=servers
        )

    def save(self, path: str | Path) -> None:
        save_baseline_snapshot(self, path)

    @classmethod
    def load(cls, path: str | Path) -> InventorySnapshot:
        return load_baseline_snapshot(path)

    @classmethod
    def load_file(cls, path: str | Path) -> InventorySnapshot:
        return cls.load(path)


def build_inventory_snapshot_from_scan(
    discovered_servers: list[DiscoveredClientServer],
    host_id: str = "local"
) -> InventorySnapshot:
    """Builds an InventorySnapshot from a list of DiscoveredClientServer."""
    servers = []
    for ds in discovered_servers:
        c_name = getattr(ds, "client_name", None) or "local"
        servers.append(DiscoveredServer(
            server_name=ds.server_name,
            client_name=c_name,
            package_name=ds.package_name,
            version=ds.version,
            ecosystem=ds.ecosystem,
            command=ds.command,
            args=list(ds.args) if ds.args else [],
            env=dict(ds.env) if ds.env else {},
            declared_tools=list(ds.declared_tools) if ds.declared_tools else []
        ))
    
    return InventorySnapshot(
        host_id=host_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        servers=servers
    )


def save_baseline_snapshot(snapshot: InventorySnapshot, path: str | Path) -> None:
    """Saves the inventory snapshot to a JSON file."""
    path = Path(path)
    data = snapshot.to_dict() if hasattr(snapshot, "to_dict") else asdict(snapshot)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    logger.info("Saved baseline snapshot to %s (%d servers recorded)", path, len(snapshot.servers))


def load_baseline_snapshot(path: str | Path) -> InventorySnapshot:
    """Loads an inventory snapshot from a JSON file."""
    path = Path(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    return InventorySnapshot.from_dict(data)


def compare_snapshots(baseline: InventorySnapshot, current: InventorySnapshot) -> DiffResult:
    """Compares baseline and current InventorySnapshots and computes drift."""
    # Build maps
    baseline_map = {s.server_name: s for s in baseline.servers}
    current_map = {s.server_name: s for s in current.servers}

    added = []
    removed = []
    modified = []
    details = []

    for name, curr in current_map.items():
        if name not in baseline_map:
            detail = ServerDriftDetail(
                server_name=name,
                status="ADDED",
                diff=f"Server '{name}' added",
                client_name=curr.client_name,
                new_version=curr.version
            )
            details.append(detail)
            added.append(curr)
        else:
            base = baseline_map[name]
            changes = []
            if curr.version != base.version:
                changes.append(f"Version changed: {base.version} -> {curr.version}")
            if curr.command != base.command:
                changes.append(f"Command changed: {base.command} -> {curr.command}")
            if curr.args != base.args:
                changes.append(f"Args changed: {base.args} -> {curr.args}")
            if curr.declared_tools != base.declared_tools:
                changes.append(f"Declared tools changed: {base.declared_tools} -> {curr.declared_tools}")
            if curr.env != base.env:
                changes.append("Environment variables changed")

            if changes:
                detail = ServerDriftDetail(
                    server_name=name,
                    status="MODIFIED",
                    diff="; ".join(changes),
                    client_name=curr.client_name,
                    old_version=base.version,
                    new_version=curr.version,
                    changes=changes
                )
                details.append(detail)
                modified.append(detail)

    for name, base in baseline_map.items():
        if name not in current_map:
            detail = ServerDriftDetail(
                server_name=name,
                status="REMOVED",
                diff=f"Server '{name}' removed",
                client_name=base.client_name,
                old_version=base.version
            )
            details.append(detail)
            removed.append(base)

    has_drift = bool(added or removed or modified)
    return DiffResult(
        has_drift=has_drift,
        details=details,
        added_servers=added,
        removed_servers=removed,
        modified_servers=modified
    )
