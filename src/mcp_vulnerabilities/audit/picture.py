"""
Stateful Security Picture Baseline (Task 111).
Serializes and loads security picture records and package baselines.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_STATE_DIR = Path.home() / ".mcp-vuln" / "state"
DEFAULT_SECURITY_PICTURE_FILE = DEFAULT_STATE_DIR / "security_picture.json"

@dataclass
class SecurityServerRecord:
    server_name: str
    package_name: str
    version: str | None
    ecosystem: str | None
    canonical_tool_hash: str | None
    passport_id: str | None
    confirmed_cves: List[str] = field(default_factory=list)
    cvss_severities: List[float] = field(default_factory=list)
    tamper_status: bool = False
    safe_upgrade_target: str | None = None
    metadata: Dict[str, Any] = field(default_factory=dict)

@dataclass
class SecurityPicture:
    timestamp: str
    scan_target: str
    total_servers: int
    vulnerable_servers: int
    tampered_servers: int
    servers: List[SecurityServerRecord] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def save(self, path: Optional[Path] = None) -> Path:
        target_path = path or DEFAULT_SECURITY_PICTURE_FILE
        target_path.parent.mkdir(parents=True, exist_ok=True)
        data = asdict(self)
        target_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        logger.info(f"Security picture saved to {target_path}")
        return target_path

    @classmethod
    def load(cls, path: Optional[Path] = None) -> Optional[SecurityPicture]:
        target_path = path or DEFAULT_SECURITY_PICTURE_FILE
        if not target_path.exists() or not target_path.is_file():
            return None
        try:
            data = json.loads(target_path.read_text(encoding="utf-8"))
            servers = [SecurityServerRecord(**s) for s in data.get("servers", [])]
            return cls(
                timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
                scan_target=data.get("scan_target", "local"),
                total_servers=data.get("total_servers", len(servers)),
                vulnerable_servers=data.get("vulnerable_servers", 0),
                tampered_servers=data.get("tampered_servers", 0),
                servers=servers,
                metadata=data.get("metadata", {})
            )
        except Exception as e:
            logger.warning(f"Failed to load security picture from {target_path}: {e}")
            return None
