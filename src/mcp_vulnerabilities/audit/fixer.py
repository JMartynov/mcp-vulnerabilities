"""Automated remediation for vulnerable MCP servers in client configurations."""

import json
import logging
import os
import re
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from .matcher import VulnerabilityMatcher, AuditFinding
from .parsers import ClientConfigParser

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

    def fix_config(self, config_path: Path, dry_run: bool = False) -> dict[str, Any]:
        """Fixes a client configuration file by replacing vulnerable versions."""
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        servers = ClientConfigParser.parse_file(config_path)
        with open(config_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        report = self.matcher.audit_servers(servers)
        
        # Group findings by server name
        findings_by_server: dict[str, list[AuditFinding]] = {}
        for f in report.findings:
            findings_by_server.setdefault(f.server_name, []).append(f)

        changes_made = []
        
        # We need to find the specific mcpServers key or use root
        raw_servers = data.get("mcpServers") or data.get("mcp_servers") or data.get("servers")
        
        
        if not isinstance(raw_servers, dict):
            if all(isinstance(v, dict) and ("command" in v or "args" in v) for v in data.values()):
                raw_servers = data
                
            else:
                return {"status": "no_servers_found"}

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
            
            # Find the args in the original dict
            srv_dict = raw_servers.get(server.server_name)
            if not srv_dict or not isinstance(srv_dict, dict):
                continue
                
            args = srv_dict.get("args", [])
            new_args = list(args)
            
            # We need to rewrite the args
            # Simple approach: find the arg that contains the package name and old version
            for i, arg in enumerate(new_args):
                if server.package_name in str(arg):
                    # Rewrite this arg based on ecosystem
                    if server.ecosystem == "npm":
                        if "@" in server.package_name and server.package_name.startswith("@"):
                            # scoped package
                            new_args[i] = f"{server.package_name}@{safe_version}"
                        else:
                            new_args[i] = f"{server.package_name}@{safe_version}"
                    elif server.ecosystem == "PyPI":
                        # We use == for pipx/uvx
                        if "==" in arg or ">=" in arg:
                            new_args[i] = re.sub(r"(==|>=|<=|>|<|~=|@).*", f"=={safe_version}", arg)
                        else:
                            new_args[i] = f"{arg}=={safe_version}"
                    elif server.ecosystem == "Docker":
                        if ":" in arg:
                            pkg = arg.rsplit(":", 1)[0]
                            new_args[i] = f"{pkg}:{safe_version}"
                        else:
                            new_args[i] = f"{arg}:{safe_version}"
                    break
            
            srv_dict["args"] = new_args
            changes_made.append({
                "server_name": server.server_name,
                "package_name": server.package_name,
                "old_version": old_version,
                "new_version": safe_version
            })

        if not changes_made:
            return {"status": "no_changes_needed", "changes": []}

        if not dry_run:
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            backup_path = config_path.with_name(f"{config_path.name}.bak.{timestamp}")
            shutil.copy2(config_path, backup_path)
            
            # Atomically write
            tmp_path = config_path.with_name(f"{config_path.name}.tmp")
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
                f.write("\n")
            os.replace(tmp_path, config_path)
            
            return {
                "status": "success",
                "changes": changes_made,
                "backup_path": str(backup_path)
            }
        
        return {
            "status": "dry_run",
            "changes": changes_made
        }

