"""Automated remediation for vulnerable MCP servers in client configurations."""

import logging
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from .matcher import VulnerabilityMatcher, AuditFinding
import difflib

from .parsers import ClientConfigParser, UniversalClientConfigScanner

logger = logging.getLogger(__name__)


class ClientConfigFixer:
    """Identifies and remediates vulnerable MCP servers in client configurations."""

    def __init__(self, matcher: VulnerabilityMatcher):
        self.matcher = matcher

    def _calculate_minimum_safe_version(self, findings: list[AuditFinding]) -> str | None:
        """Calculates the highest fixed version among all findings."""
        if not findings:
            return None

        max_version: Version | None = None
        best_version_str: str | None = None

        for f in findings:
            if not f.fixed_version:
                continue

            try:
                v = Version(f.fixed_version)
                if max_version is None or v > max_version:
                    max_version = v
                    best_version_str = f.fixed_version
            except InvalidVersion:
                # If we can't parse semver, just take the first one or continue
                if max_version is None:
                    best_version_str = f.fixed_version

        return best_version_str

    def fix_config(self, config_path: Path, dry_run: bool = False, client_name: str | None = None) -> dict[str, Any]:
        """Fixes a client configuration file by replacing vulnerable versions, preserving format and comments."""
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        servers = ClientConfigParser.parse_file(config_path, client_name=client_name)
        original_text = config_path.read_text(encoding="utf-8")
        patched_text = original_text

        report = self.matcher.audit_servers(servers)
        
        # Group findings by server name
        findings_by_server: dict[str, list[AuditFinding]] = {}
        for f in report.findings:
            findings_by_server.setdefault(f.server_name, []).append(f)

        changes_made = []

        for server in servers:
            findings = findings_by_server.get(server.server_name)
            if not findings:
                continue
                
            safe_version = self._calculate_minimum_safe_version(findings)
            if not safe_version:
                logger.warning(f"No safe version found for {server.server_name}, skipping.")
                continue
                
            # If the current version is already >= safe_version (e.g. unpinned), skip
            try:
                if server.version and Version(server.version) >= Version(safe_version):
                    continue
            except InvalidVersion:
                pass

            old_version = server.version or "unpinned"
            
            pkg_esc = re.escape(server.package_name)
            
            # Safe string replacement for the config file text
            if old_version and old_version != "unpinned":
                old_esc = re.escape(old_version)
                if server.ecosystem == "npm":
                    pattern = rf'({pkg_esc}@){old_esc}'
                    patched_text = re.sub(pattern, rf'\g<1>{safe_version}', patched_text)
                elif server.ecosystem == "PyPI":
                    pattern = rf'({pkg_esc}(?:==|>=|<=|>|<|~=|@)){old_esc}'
                    patched_text = re.sub(pattern, rf'\g<1>{safe_version}', patched_text)
                elif server.ecosystem == "Docker":
                    pattern = rf'({pkg_esc}:){old_esc}'
                    patched_text = re.sub(pattern, rf'\g<1>{safe_version}', patched_text)
            else:
                if server.ecosystem == "npm":
                    pattern = rf'("{pkg_esc}")'
                    patched_text = re.sub(pattern, f'"{server.package_name}@{safe_version}"', patched_text)
                elif server.ecosystem == "PyPI":
                    pattern = rf'("{pkg_esc}")'
                    patched_text = re.sub(pattern, f'"{server.package_name}=={safe_version}"', patched_text)
                elif server.ecosystem == "Docker":
                    pattern = rf'("{pkg_esc}")'
                    patched_text = re.sub(pattern, f'"{server.package_name}:{safe_version}"', patched_text)

            if patched_text != original_text:
                changes_made.append({
                    "server_name": server.server_name,
                    "package_name": server.package_name,
                    "old_version": old_version,
                    "new_version": safe_version
                })
                # Update original text baseline for multiple changes
                original_text = patched_text

        if not changes_made:
            return {"status": "no_changes_needed", "changes": []}

        if dry_run:
            diff = list(difflib.unified_diff(
                config_path.read_text(encoding="utf-8").splitlines(keepends=True),
                patched_text.splitlines(keepends=True),
                fromfile=f"a/{config_path.name}",
                tofile=f"b/{config_path.name}"
            ))
            diff_text = "".join(diff)
            print(diff_text)
            return {
                "status": "dry_run",
                "changes": changes_made,
                "diff": diff_text
            }

        import sys

        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        backup_path = config_path.with_name(f"{config_path.name}.bak.{timestamp}")
        
        # Create atomic backup
        shutil.copy2(config_path, backup_path)
        
        # Atomically write
        tmp_path = config_path.with_name(f"{config_path.name}.tmp")
        
        try:
            tmp_path.write_text(patched_text, encoding="utf-8")
            os.replace(tmp_path, config_path)
        except Exception as e:
            logger.error(f"Failed to write config file {config_path}: {e}")
            if tmp_path.exists():
                tmp_path.unlink()
            # Restore from backup
            if backup_path.exists():
                shutil.copy2(backup_path, config_path)
            sys.exit(1)
        
        return {
            "status": "success",
            "changes": changes_made,
            "backup_path": str(backup_path)
        }

    def fix_all_clients(self, dry_run: bool = False, specific_client: str | None = None) -> list[dict[str, Any]]:
        """Fixes configurations across all supported clients or a specific one."""
        scanner = UniversalClientConfigScanner()
        results = []
        
        clients_to_scan = [specific_client] if specific_client else scanner.SUPPORTED_CLIENTS
        
        for client in clients_to_scan:
            paths = scanner.get_client_paths(client)
            for path in paths:
                if path.exists():
                    try:
                        res = self.fix_config(path, dry_run=dry_run, client_name=client)
                        if res["status"] in ("success", "dry_run"):
                            res["client"] = client
                            res["path"] = str(path)
                            results.append(res)
                    except Exception as e:
                        logger.error(f"Error fixing {client} config at {path}: {e}")
        return results

