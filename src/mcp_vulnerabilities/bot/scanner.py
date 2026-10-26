import logging
import re
from pathlib import Path
from dataclasses import dataclass
from typing import Any

from mcp_vulnerabilities.audit.parsers import ClientConfigParser, DiscoveredClientServer
from mcp_vulnerabilities.audit.fixer import ClientConfigFixer
from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher, AuditReport

logger = logging.getLogger(__name__)

IGNORE_DIRS = {".git", "node_modules", ".venv", "venv", "env", ".env", "dist", "build"}
SUPPORTED_EXTENSIONS = {".json", ".jsonc", ".yaml", ".yml"}

@dataclass
class RemediationPlan:
    config_path: Path
    original_text: str
    patched_text: str
    diff_text: str
    changes: list[dict[str, Any]]
    report: AuditReport

class RepositoryScanner:
    """Scans repository for MCP configurations and analyzes vulnerabilities."""

    def __init__(self, repo_root: Path, matcher: VulnerabilityMatcher):
        self.repo_root = repo_root
        self.matcher = matcher
        self.fixer = ClientConfigFixer(matcher)

    def discover_configs(self) -> list[Path]:
        """Recursively discovers all supported MCP client config files."""
        all_json_yaml = []
        for p in self.repo_root.rglob("*"):
            if not p.is_file():
                continue
                
            # Skip ignored directories
            skip = False
            for part in p.relative_to(self.repo_root).parts:
                if part in IGNORE_DIRS:
                    skip = True
                    break
            if skip:
                continue

            if p.suffix in SUPPORTED_EXTENSIONS or "Dockerfile" in p.name or p.name in [
                "claude_desktop_config.json", "mcp.json", "cline_mcp_settings.json", "settings.json", "mcp_config.json"
            ]:
                all_json_yaml.append(p)

        discovered = []
        for p in all_json_yaml:
            try:
                servers = ClientConfigParser.parse_file(p)
                if servers:
                    discovered.append(p)
            except Exception:
                pass
                
        return list(set(discovered))

    def _apply_fix_safely(self, text: str, server: DiscoveredClientServer, safe_version: str) -> str:
        """Applies version upgrade safely using strict regex to avoid collateral damage."""
        pkg_esc = re.escape(server.package_name)
        old_version = server.version or "unpinned"
        
        # If unpinned
        if old_version == "unpinned":
            if server.ecosystem == "npm":
                pattern = rf'([\s"\'\n])({pkg_esc})([\s"\'\n])'
                return re.sub(pattern, rf'\g<1>{server.package_name}@{safe_version}\g<3>', text)
            elif server.ecosystem == "PyPI":
                pattern = rf'([\s"\'\n])({pkg_esc})([\s"\'\n])'
                return re.sub(pattern, rf'\g<1>{server.package_name}=={safe_version}\g<3>', text)
            elif server.ecosystem == "Docker":
                pattern = rf'([\s"\'\n])({pkg_esc})([\s"\'\n])'
                return re.sub(pattern, rf'\g<1>{server.package_name}:{safe_version}\g<3>', text)
            return text

        old_esc = re.escape(old_version)
        if server.ecosystem == "npm":
            pattern = rf'({pkg_esc}@){old_esc}'
            return re.sub(pattern, rf'\g<1>{safe_version}', text)
        elif server.ecosystem == "PyPI":
            pattern = rf'({pkg_esc}(?:==|>=|<=|>|<|~=|@)){old_esc}'
            return re.sub(pattern, rf'\g<1>{safe_version}', text)
        elif server.ecosystem == "Docker":
            pattern = rf'({pkg_esc}:){old_esc}'
            return re.sub(pattern, rf'\g<1>{safe_version}', text)

        old_esc = re.escape(old_version)
        if server.ecosystem == "npm":
            pattern = rf'("{pkg_esc}@){old_esc}(")'
            return re.sub(pattern, rf'\g<1>{safe_version}\g<2>', text)
        elif server.ecosystem == "PyPI":
            pattern = rf'("{pkg_esc}(?:==|>=|<=|>|<|~=|@)){old_esc}(")'
            return re.sub(pattern, rf'\g<1>{safe_version}\g<2>', text)
        elif server.ecosystem == "Docker":
            pattern = rf'("{pkg_esc}:){old_esc}(")'
            return re.sub(pattern, rf'\g<1>{safe_version}\g<2>', text)
            
        return text


    def generate_plans(self) -> list[RemediationPlan]:
        """Generates remediation plans for all vulnerable configs."""
        configs = self.discover_configs()
        plans = []

        for config_path in configs:
            try:
                servers = ClientConfigParser.parse_file(config_path)
                if not servers:
                    continue
                    
                report = self.matcher.audit_servers(servers)
                if not report.findings:
                    continue

                fix_result = self.fixer.fix_config(config_path, dry_run=True)
                
                if fix_result["status"] == "dry_run" and fix_result.get("changes"):
                    original_text = config_path.read_text(encoding="utf-8")
                    
                    findings_by_server = {}
                    for f in report.findings:
                        findings_by_server.setdefault(f.server_name, []).append(f)
                    
                    patched_text = original_text
                    for server in servers:
                        findings = findings_by_server.get(server.server_name)
                        if not findings:
                            continue
                            
                        safe_version = self.fixer._calculate_minimum_safe_version(findings)
                        if not safe_version:
                            continue
                            
                        patched_text = self._apply_fix_safely(patched_text, server, safe_version)

                    plans.append(RemediationPlan(
                        config_path=config_path,
                        original_text=original_text,
                        patched_text=patched_text,
                        diff_text=fix_result["diff"],
                        changes=fix_result["changes"],
                        report=report
                    ))

            except Exception as e:
                logger.error(f"Error scanning {config_path}: {e}")

        return plans
