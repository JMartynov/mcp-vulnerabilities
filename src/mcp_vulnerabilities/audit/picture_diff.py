"""
Comparative Security Drift Engine (Task 112).
Compares baseline SecurityPicture against current audit state to categorize drift.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from mcp_vulnerabilities.audit.picture import SecurityPicture, SecurityServerRecord

logger = logging.getLogger(__name__)

@dataclass
class SecurityDriftReport:
    newly_introduced_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    resolved_vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    tamper_incidents: List[Dict[str, Any]] = field(default_factory=list)
    new_high_risk_tools: List[Dict[str, Any]] = field(default_factory=list)
    added_servers: List[Dict[str, Any]] = field(default_factory=list)
    removed_servers: List[Dict[str, Any]] = field(default_factory=list)
    tool_schema_changes: List[Dict[str, Any]] = field(default_factory=list)
    is_drift_detected: bool = False

class SecurityPictureDiffer:
    @staticmethod
    def compare(baseline: SecurityPicture, current: SecurityPicture) -> SecurityDriftReport:
        report = SecurityDriftReport()
        
        baseline_map = {s.package_name: s for s in baseline.servers}
        current_map = {s.package_name: s for s in current.servers}
        
        baseline_pkgs = set(baseline_map.keys())
        current_pkgs = set(current_map.keys())
        
        added = current_pkgs - baseline_pkgs
        removed = baseline_pkgs - current_pkgs
        
        for pkg in added:
            s = current_map[pkg]
            report.added_servers.append({"package_name": pkg, "version": s.version})
            if s.confirmed_cves:
                for cve in s.confirmed_cves:
                    report.newly_introduced_vulnerabilities.append({"package_name": pkg, "cve": cve})
            if s.tamper_status:
                report.tamper_incidents.append({"package_name": pkg, "reason": "Tamper detected in newly added server"})

        for pkg in removed:
            s = baseline_map[pkg]
            report.removed_servers.append({"package_name": pkg, "version": s.version})
            if s.confirmed_cves:
                for cve in s.confirmed_cves:
                    report.resolved_vulnerabilities.append({"package_name": pkg, "cve": cve})

        common = baseline_pkgs & current_pkgs
        for pkg in common:
            b_s = baseline_map[pkg]
            c_s = current_map[pkg]
            
            # Check version / CVE diffs
            b_cves = set(b_s.confirmed_cves)
            c_cves = set(c_s.confirmed_cves)
            
            for cve in c_cves - b_cves:
                report.newly_introduced_vulnerabilities.append({"package_name": pkg, "cve": cve, "version": c_s.version})
            for cve in b_cves - c_cves:
                report.resolved_vulnerabilities.append({"package_name": pkg, "cve": cve, "version": c_s.version})
                
            # Check tamper status
            if not b_s.tamper_status and c_s.tamper_status:
                report.tamper_incidents.append({"package_name": pkg, "version": c_s.version, "incident": "New tamper signature detected"})
                
            # Check tool hash / schema changes
            if b_s.canonical_tool_hash and c_s.canonical_tool_hash and b_s.canonical_tool_hash != c_s.canonical_tool_hash:
                report.tool_schema_changes.append({"package_name": pkg, "old_hash": b_s.canonical_tool_hash, "new_hash": c_s.canonical_tool_hash})

        report.is_drift_detected = bool(
            report.newly_introduced_vulnerabilities
            or report.resolved_vulnerabilities
            or report.tamper_incidents
            or report.new_high_risk_tools
            or report.added_servers
            or report.removed_servers
            or report.tool_schema_changes
        )
        return report
