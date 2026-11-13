"""Vulnerability matching engine comparing discovered MCP client servers against OSV advisories."""

import gzip
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.cvss import (
    extract_advisory_severity,
    is_version_in_ranges,
    parse_version_lenient,
)
from mcp_vulnerabilities.models import OsvVulnerability

from .parsers import DiscoveredClientServer

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    advisory: OsvVulnerability
    matched_on: str


@dataclass
class AuditFinding:
    server_name: str
    package_name: str
    installed_version: str | None
    vulnerability_id: str
    summary: str
    severity_level: str
    cvss_score: float | None
    fixed_version: str | None
    affected_range: str
    references: list[str]
    is_confirmed: bool  # True if version specifically in range, False if warning on unpinned package
    is_cisa_kev: bool = False
    cisa_kev_date_added: str | None = None
    cisa_kev_due_date: str | None = None
    cisa_kev_ransomware_campaign_use: str | None = None
    cisa_kev_required_action: str | None = None


@dataclass
class AuditReport:
    scanned_servers: list[DiscoveredClientServer]
    findings: list[AuditFinding] = field(default_factory=list)

    @property
    def has_critical_or_high(self) -> bool:
        return any(f.severity_level in ("CRITICAL", "HIGH") for f in self.findings)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_servers_scanned": len(self.scanned_servers),
            "total_vulnerabilities_found": len(self.findings),
            "has_critical_or_high": self.has_critical_or_high,
            "servers": [
                {
                    "name": s.server_name,
                    "package": s.package_name,
                    "version": s.version,
                    "original_version": getattr(s, "original_version", None),
                    "resolution_source": getattr(s, "resolution_source", None),
                    "ecosystem": s.ecosystem,
                    "command": s.command,
                }
                for s in self.scanned_servers
            ],
            "findings": [
                {
                    "server_name": f.server_name,
                    "package_name": f.package_name,
                    "installed_version": f.installed_version,
                    "vulnerability_id": f.vulnerability_id,
                    "summary": f.summary,
                    "severity": f.severity_level,
                    "cvss_score": f.cvss_score,
                    "fixed_version": f.fixed_version,
                    "affected_range": f.affected_range,
                    "references": f.references,
                    "is_confirmed": f.is_confirmed,
                }
                for f in self.findings
            ],
        }


class VulnerabilityMatcher:
    """Evaluates client server dependencies against canonical OSV vulnerability records."""

    def __init__(self, advisories: list[dict[str, Any]]):
        self.advisories = advisories
        # Index advisories by normalized package name
        self._package_index: dict[str, list[dict[str, Any]]] = {}
        for adv in advisories:
            for affected in adv.get("affected", []):
                pkg = affected.get("package", {})
                name = pkg.get("name")
                if name:
                    norm = self._normalize_package_name(name)
                    self._package_index.setdefault(norm, []).append(adv)

    @classmethod
    def from_directory(cls, dir_path: Path) -> "VulnerabilityMatcher":
        """Loads all OSV JSON files from a directory."""
        advisories: list[dict[str, Any]] = []
        if not dir_path.exists():
            return cls(advisories)

        for json_file in dir_path.glob("*.json"):
            if json_file.name in (
                "sync_state.json",
                "mcp_catalog_state.json",
                "mcp_servers.json",
            ):
                continue
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    adv = json.load(f)
                    advisories.append(adv)
            except Exception as e:
                logger.debug(f"Skipping {json_file}: {e}")

        return cls(advisories)

    @classmethod
    def from_snapshot(cls, snapshot_path: Path) -> "VulnerabilityMatcher":
        """Loads OSV records from a consolidated JSON or gzip file."""
        if not snapshot_path.exists():
            return cls([])

        if snapshot_path.name.endswith(".gz"):
            with gzip.open(snapshot_path, "rt", encoding="utf-8") as f:
                data = json.load(f)
        else:
            with open(snapshot_path, "r", encoding="utf-8") as f:
                data = json.load(f)

        if isinstance(data, list):
            return cls(data)
        elif isinstance(data, dict) and "vulnerabilities" in data:
            vulns = data["vulnerabilities"]
            if isinstance(vulns, dict):
                return cls(list(vulns.values()))
            elif isinstance(vulns, list):
                return cls(vulns)
        return cls([])

    def get_advisory(self, advisory_id: str) -> OsvVulnerability | None:
        """Retrieve a specific advisory by exact ID or alias."""
        target = advisory_id.lower()
        for adv_dict in self.advisories:
            adv_id = adv_dict.get("id", "").lower()
            if adv_id == target:
                return OsvVulnerability.from_dict(adv_dict)

            aliases = [a.lower() for a in adv_dict.get("aliases", [])]
            if target in aliases:
                return OsvVulnerability.from_dict(adv_dict)
        return None

    def search(
        self, query: str, min_severity: str | None = None, ecosystem: str | None = None
    ) -> list[SearchResult]:
        """Search for advisories by keyword, severity, and ecosystem."""
        results = []
        query_lower = query.lower()

        severity_order = {
            "LOW": 1,
            "MEDIUM": 2,
            "MODERATE": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        min_rank = (
            severity_order.get(str(min_severity).upper(), 0) if min_severity else 0
        )

        for adv_dict in self.advisories:
            adv = OsvVulnerability.from_dict(adv_dict)

            # Severity check
            if min_rank > 0:
                # Extract severity using existing method
                sev_str, _ = self._extract_severity_info(adv_dict)
                rank = severity_order.get(sev_str.upper(), 0)
                if rank < min_rank:
                    continue

            # Ecosystem check (any affected package matches)
            if ecosystem:
                eco_lower = ecosystem.lower()
                matches_eco = False
                for aff in adv.affected:
                    aff_eco = (aff.package.ecosystem or "").lower()
                    if eco_lower == aff_eco:
                        matches_eco = True
                        break
                    # fuzzy mapping
                    if eco_lower == "npm" and aff_eco in ("npm", "javascript"):
                        matches_eco = True
                        break
                    if eco_lower == "pypi" and aff_eco in ("pypi", "python"):
                        matches_eco = True
                        break
                if not matches_eco:
                    continue

            # Text search (ID, Aliases, Package Name, Vulnerable Tools, Summary)
            matched_on = None
            if query_lower in (adv.id or "").lower():
                matched_on = f"ID match ({adv.id})"
            elif adv.aliases and any(
                query_lower in (a or "").lower() for a in adv.aliases
            ):
                matched_on = "Alias match"
            elif adv.summary and query_lower in adv.summary.lower():
                matched_on = "Summary match"
            else:
                for aff in adv.affected:
                    if (
                        aff.package
                        and aff.package.name
                        and query_lower in aff.package.name.lower()
                    ):
                        matched_on = f"Package match ({aff.package.name})"
                        break
                    if aff.database_specific and aff.database_specific.vulnerable_tools:
                        if any(
                            query_lower in (t or "").lower()
                            for t in aff.database_specific.vulnerable_tools
                        ):
                            matched_on = "Vulnerable tool match"
                            break

            if matched_on:
                results.append(SearchResult(advisory=adv, matched_on=matched_on))

        return results

    def audit_servers(
        self,
        servers: list[DiscoveredClientServer],
        severity_threshold: str | None = None,
    ) -> AuditReport:
        """Audits a list of discovered client servers and produces an AuditReport."""
        findings: list[AuditFinding] = []
        severity_order = {
            "LOW": 1,
            "MEDIUM": 2,
            "MODERATE": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }
        min_rank = severity_order.get(str(severity_threshold).upper(), 0)

        for server in servers:
            matched_advisories = self._find_advisories_for_server(server)
            for adv, affected_block in matched_advisories:
                finding = self._evaluate_vulnerability(server, adv, affected_block)
                if finding:
                    rank = severity_order.get(finding.severity_level.upper(), 1)
                    if rank >= min_rank:
                        findings.append(finding)

        return AuditReport(scanned_servers=servers, findings=findings)

    def _find_advisories_for_server(
        self,
        server: DiscoveredClientServer,
    ) -> list[tuple[dict[str, Any], dict[str, Any]]]:
        """Finds advisories that match the server's package name and ecosystem."""
        results = []
        norm_server = self._normalize_package_name(server.package_name)
        candidates = self._package_index.get(norm_server, [])

        for adv in candidates:
            for affected in adv.get("affected", []):
                pkg = affected.get("package", {})
                pkg_name = pkg.get("name", "")
                if self._normalize_package_name(pkg_name) != norm_server:
                    continue

                eco = (pkg.get("ecosystem") or "").lower()
                srv_eco = (server.ecosystem or "").lower()

                # Ecosystem compatibility check
                if srv_eco and eco and server.command != "manual":
                    if srv_eco == "npm" and eco not in ("npm", "javascript"):
                        continue
                    if srv_eco == "pypi" and eco not in ("pypi", "python"):
                        continue
                    if srv_eco in ("cargo", "rust") and eco not in ("cargo", "crates.io", "rust"):
                        continue
                    if srv_eco in ("go", "golang") and eco not in ("go", "golang"):
                        continue
                    if srv_eco in ("maven", "java") and eco not in ("maven", "java"):
                        continue
                    if srv_eco in ("docker", "containers") and eco not in ("docker", "containers"):
                        continue

                results.append((adv, affected))

        return results

    def _evaluate_vulnerability(
        self,
        server: DiscoveredClientServer,
        adv: dict[str, Any],
        affected: dict[str, Any],
    ) -> AuditFinding | None:
        """Evaluates whether the server's version falls within the affected range."""
        installed_ver = server.version
        ranges = affected.get("ranges", [])
        versions = affected.get("versions", [])

        is_vulnerable = False
        fixed_version: str | None = None
        range_descriptions: list[str] = []

        # Find fixed version from ranges
        for r in ranges:
            events = r.get("events", [])
            intro: str | None = None
            fix: str | None = None
            last_aff: str | None = None

            for ev in events:
                if "introduced" in ev:
                    intro = ev["introduced"]
                if "fixed" in ev:
                    fix = ev["fixed"]
                    if not fixed_version:
                        fixed_version = fix
                if "last_affected" in ev:
                    last_aff = ev["last_affected"]

            desc_parts = []
            if intro:
                desc_parts.append(f">={intro}")
            if fix:
                desc_parts.append(f"<{fix}")
            elif last_aff:
                desc_parts.append(f"<={last_aff}")

            if desc_parts:
                range_descriptions.append(", ".join(desc_parts))

        range_str = (
            " | ".join(range_descriptions)
            if range_descriptions
            else ("known versions" if versions else "all versions")
        )

        if not installed_ver:
            # Unpinned package warning
            is_vulnerable = True
            is_confirmed = False
        else:
            # Clean version string (remove leading 'v' or '=')
            clean_ver = installed_ver.lstrip("v=").strip()
            is_confirmed = self._is_version_in_ranges(clean_ver, ranges, versions)
            is_vulnerable = is_confirmed

        if not is_vulnerable:
            return None

        # Determine severity & CVSS
        severity_level, cvss_score = self._extract_severity_info(adv, affected=affected)

        # References
        refs = [r.get("url", "") for r in adv.get("references", []) if r.get("url")][:3]

        return AuditFinding(
            server_name=server.server_name,
            package_name=server.package_name,
            installed_version=installed_ver,
            vulnerability_id=adv.get("id", "UNKNOWN"),
            summary=adv.get("summary") or adv.get("details", "")[:120],
            severity_level=severity_level,
            cvss_score=cvss_score,
            fixed_version=fixed_version,
            affected_range=range_str,
            references=refs,
            is_confirmed=is_confirmed if installed_ver else False,
        )

    def _is_version_in_ranges(
        self,
        version_str: str,
        ranges: list[dict[str, Any]],
        versions: list[str],
    ) -> bool:
        """Checks if a version is within the specified OSV ranges or version list."""
        return is_version_in_ranges(version_str, ranges=ranges, versions=versions)

    _parse_version = staticmethod(parse_version_lenient)
    _extract_severity_info = staticmethod(extract_advisory_severity)

    @staticmethod
    def _normalize_package_name(name: str) -> str:
        clean = name.strip().lower()
        # Handle python normalization
        if not clean.startswith("@"):
            clean = re.sub(r"[-_.]+", "-", clean)
        return clean
