"""Version-aware MCP catalog state and cache tracking."""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

logger = logging.getLogger("mcp_vulnerabilities.catalog")


def normalize_version(ver_str: str | None) -> str:
    """Normalize version string, stripping leading 'v' and handling semver."""
    if not ver_str:
        return ""
    clean = ver_str.strip().lstrip("vV")
    try:
        return str(Version(clean))
    except InvalidVersion:
        return clean


@dataclass
class ServerRecord:
    """State record for a single audited MCP server package."""

    name: str
    ecosystem: str
    last_version_seen: str = ""
    last_checked_utc: str = ""
    known_vulnerabilities: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class McpCatalogState:
    """Persistent catalog state tracking audited MCP packages and versions to prevent duplicate queries."""

    def __init__(self, state_file: str | Path = "data/mcp_catalog_state.json", ttl_days: int = 30) -> None:
        self.state_file = Path(state_file)
        self.ttl_days = ttl_days
        self.records: dict[str, ServerRecord] = {}
        self.load()

    @staticmethod
    def package_key(ecosystem: str, name: str) -> str:
        """Deterministic canonical package key."""
        return f"{ecosystem.strip().lower()}:{name.strip().lower()}"

    def load(self) -> None:
        """Load state from disk if exists."""
        if not self.state_file.exists():
            return
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
            for k, v in raw.get("servers", {}).items():
                self.records[k] = ServerRecord(
                    name=v["name"],
                    ecosystem=v["ecosystem"],
                    last_version_seen=v.get("last_version_seen", ""),
                    last_checked_utc=v.get("last_checked_utc", ""),
                    known_vulnerabilities=v.get("known_vulnerabilities", []),
                    metadata=v.get("metadata", {}),
                )
        except Exception as exc:
            logger.warning("Failed to load catalog state from %s: %s", self.state_file, exc)

    def save(self) -> None:
        """Atomically persist state to disk via temporary file."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": "1.0.0",
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "total_servers": len(self.records),
            "servers": {k: asdict(v) for k, v in sorted(self.records.items())},
        }
        tmp_file = self.state_file.with_suffix(".tmp")
        tmp_file.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp_file, self.state_file)

    def should_query(self, ecosystem: str, name: str, current_version: str | None = None) -> bool:
        """Check whether a package requires re-querying based on version change or TTL."""
        key = self.package_key(ecosystem, name)
        record = self.records.get(key)
        if not record:
            return True  # Never audited before

        # If current_version is provided, compare normalized versions
        if current_version:
            norm_curr = normalize_version(current_version)
            norm_last = normalize_version(record.last_version_seen)
            if norm_curr != norm_last or not record.last_version_seen:
                return True

        # Check TTL staleness (if last checked > ttl_days ago)
        if record.last_checked_utc:
            try:
                checked_dt = datetime.fromisoformat(record.last_checked_utc.replace("Z", "+00:00"))
                age_days = (datetime.now(UTC) - checked_dt).total_seconds() / 86400.0
                if age_days > self.ttl_days:
                    return True
            except Exception:
                return True

        return False

    def mark_stale(self, ecosystem: str, name: str) -> None:
        """Force a package to be re-queried on next pass (e.g. when an external advisory names it)."""
        key = self.package_key(ecosystem, name)
        if key in self.records:
            self.records[key].last_version_seen = ""
            self.records[key].last_checked_utc = ""

    def update_record(
        self,
        ecosystem: str,
        name: str,
        version: str = "",
        vulnerabilities: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Update or insert a server record after successful audit."""
        key = self.package_key(ecosystem, name)
        existing_vulns = self.records[key].known_vulnerabilities if key in self.records else []
        new_vulns = sorted(list(set(existing_vulns + (vulnerabilities or []))))

        existing_meta = self.records[key].metadata if key in self.records else {}
        if metadata:
            existing_meta.update(metadata)

        if version:
            norm_ver = normalize_version(version)
        else:
            norm_ver = normalize_version(self.records[key].last_version_seen) if key in self.records else ""

        self.records[key] = ServerRecord(
            name=name,
            ecosystem=ecosystem,
            last_version_seen=norm_ver,
            last_checked_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            known_vulnerabilities=new_vulns,
            metadata=existing_meta,
        )
