import logging
import subprocess
import yaml
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.converters.pypa import PyPaConverter
from mcp_vulnerabilities.models import OsvVulnerability

logger = logging.getLogger(__name__)

class PyPaAdvisorySync:
    """Synchronize and parse advisories from the local PyPA database."""

    def __init__(self, target_packages: set[str] | None = None) -> None:
        self.target_packages = target_packages

    @classmethod
    def sync_local(cls, data_dir: str | Path, target_packages: set[str] | None = None) -> list[OsvVulnerability]:
        """Iterate through local PyPA advisory mirror and process matched advisories."""
        instance = cls(target_packages)
        return instance._sync(data_dir)

    def _sync(self, data_dir: str | Path) -> list[OsvVulnerability]:
        p = Path(data_dir)
        vulns_dir = p / "vulns"
        
        if not p.is_dir():
            logger.warning(f"PyPA advisory directory not found: {p}")
            return []

        if not vulns_dir.is_dir():
            vulns_dir = p

        sync_marker_path = p / ".sync_marker"
        last_sync = ""
        if sync_marker_path.exists():
            last_sync = sync_marker_path.read_text(encoding="utf-8").strip()

        # Compute a hash of all matching files to serve as sync marker
        # In a real git clone we'd use HEAD sha, but here we just want idempotency over files.
        import hashlib
        import os
        
        hasher = hashlib.sha256()
        
        collected = []
        
        # Sort paths to ensure deterministic hashing
        yaml_paths = sorted(list(vulns_dir.rglob("*.yaml")))
        for yaml_path in yaml_paths:
            try:
                if self.target_packages:
                    parent_name = yaml_path.parent.name.lower()
                    normalized_targets = {tp.lower().replace("_", "-") for tp in self.target_packages}
                    if parent_name not in normalized_targets:
                        continue

                stat = yaml_path.stat()
                hasher.update(f"{yaml_path.name}:{stat.st_mtime}:{stat.st_size}".encode('utf-8'))
                
            except Exception as e:
                logger.error(f"Failed to process PyPA advisory metadata {yaml_path}: {e}")

        current_sync = hasher.hexdigest()
        if current_sync == last_sync:
            logger.info("PyPA advisories already up-to-date. Skipping sync.")
            return []

        for yaml_path in yaml_paths:
            try:
                if self.target_packages:
                    parent_name = yaml_path.parent.name.lower()
                    normalized_targets = {tp.lower().replace("_", "-") for tp in self.target_packages}
                    if parent_name not in normalized_targets:
                        continue
                        
                with open(yaml_path, "r", encoding="utf-8") as f:
                    content = f.read()

                if "id: PYSEC" not in content and "id: 'PYSEC" not in content and 'id: "PYSEC' not in content:
                    continue

                v = PyPaConverter.from_yaml(content)
                collected.append(v)
            except Exception as e:
                logger.error(f"Failed to process PyPA advisory {yaml_path}: {e}")

        # Update the sync marker after successful parsing
        try:
            sync_marker_path.write_text(current_sync, encoding="utf-8")
        except Exception:
            pass

        return collected
