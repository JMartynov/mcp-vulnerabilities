import logging
from dataclasses import dataclass, field
from typing import Any

from mcp_fingerprints.canonicalizer import (
    compute_toolset_canonical_hash,
    extract_tool_signature,
)
from mcp_fingerprints.drift_detector import TamperIncident

from mcp_vulnerabilities.compliance.models import (
    ComplianceTier,
    ComplianceViolation,
    OwaspComplianceReport,
)

logger = logging.getLogger(__name__)


@dataclass
class TamperReport:
    server_name: str
    package_name: str
    version: str
    status: str
    baseline_hash: str | None = None
    live_hash: str | None = None
    incidents: list[TamperIncident] = field(default_factory=list)


    def to_compliance_report(self) -> OwaspComplianceReport:
        
        violations = []
        for inc in self.incidents:
            if inc.incident_type == "SHADOW_TOOL_INJECTED":
                violations.append(ComplianceViolation(
                    owasp_id='LLM01:2025',
                    owasp_mcp_id='MCP002',
                    category_name='Shadow Tool',
                    severity=inc.severity,
                    target=self.server_name,
                    description=inc.details,
                    remediation_guidance='Remove unadvertised tools or verify upstream integrity.',
                    original_rule_id='MCP002'
                ))
            elif inc.incident_type == "SCHEMA_TAMPERING":
                violations.append(ComplianceViolation(
                    owasp_id='LLM01:2025',
                    owasp_mcp_id='MCP001',
                    category_name='Schema Tampering',
                    severity=inc.severity,
                    target=self.server_name,
                    description=inc.details,
                    remediation_guidance='Restore baseline tool schema.',
                    original_rule_id='MCP001'
                ))
            elif inc.incident_type == "DESCRIPTION_TAMPERING":
                violations.append(ComplianceViolation(
                    owasp_id='LLM01:2025',
                    owasp_mcp_id='MCP001',
                    category_name='Description Tampering',
                    severity=inc.severity,
                    target=self.server_name,
                    description=inc.details,
                    remediation_guidance='Restore baseline tool description.',
                    original_rule_id='MCP001'
                ))
            elif inc.incident_type == "MISSING_CRITICAL_TOOLS":
                violations.append(ComplianceViolation(
                    owasp_id='LLM01:2025',
                    owasp_mcp_id='MCP001',
                    category_name='Missing Tool',
                    severity=inc.severity,
                    target=self.server_name,
                    description=inc.details,
                    remediation_guidance='Restore missing critical tools.',
                    original_rule_id='MCP001'
                ))
                
        tier = ComplianceTier.COMPLIANT if not violations else ComplianceTier.NON_COMPLIANT
        return OwaspComplianceReport(score=100 if not violations else 0, tier=tier, violations=violations)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server_name": self.server_name,
            "package_name": self.package_name,
            "version": self.version,
            "status": self.status,
            "baseline_hash": self.baseline_hash,
            "live_hash": self.live_hash,
            "incidents": [
                {
                    "incident_type": inc.incident_type,
                    "severity": inc.severity,
                    "details": inc.details,
                    "affected_tools": inc.affected_tools,
                }
                for inc in self.incidents
            ]
        }

class SupplyChainTamperDetector:
    def __init__(self, matcher: Any):
        self.matcher = matcher

    def verify_server_integrity(self, server_spec: Any, runtime_tools: list[dict[str, Any]]) -> TamperReport:
        package_name = getattr(server_spec, "package_name", "")
        version = getattr(server_spec, "version", "")
        
        if not runtime_tools:
            return TamperReport(
                server_name=getattr(server_spec, "server_name", ""),
                package_name=package_name,
                version=version,
                status="INTEGRITY_UNKNOWN (NO_TOOLS_DECLARED)"
            )
            
        live_hash = compute_toolset_canonical_hash(runtime_tools)
        
        if not package_name or not version:
            return TamperReport(
                server_name=getattr(server_spec, "server_name", ""),
                package_name=package_name,
                version=version,
                status="INTEGRITY_UNKNOWN (NO_PASSPORT_BASELINE)"
            )
            
        spec = self.matcher.packages.get(package_name)
        if not spec:
            return TamperReport(
                server_name=getattr(server_spec, "server_name", ""),
                package_name=package_name,
                version=version,
                status="INTEGRITY_UNKNOWN (NO_PASSPORT_BASELINE)"
            )
            
        baseline_ver = None
        for v in spec.versions:
            if v.version == version:
                baseline_ver = v
                break
                
        if not baseline_ver:
            return TamperReport(
                server_name=getattr(server_spec, "server_name", ""),
                package_name=package_name,
                version=version,
                status="INTEGRITY_UNKNOWN (NO_PASSPORT_BASELINE)"
            )
            
        baseline_hash = baseline_ver.toolset_canonical_hash
        
        live_signatures = [extract_tool_signature(t) for t in runtime_tools]
        
        # Check for description tamper even if hash matches
        baseline_tools_map = {t.name: t for t in baseline_ver.tool_signatures}
        live_tools_map = {t.name: t for t in live_signatures}
        
        desc_tampered = []
        for name, live_sig in live_tools_map.items():
            if name in baseline_tools_map and live_sig.description_hash != baseline_tools_map[name].description_hash:
                desc_tampered.append(name)
        
        if live_hash == baseline_hash and not desc_tampered:
            return TamperReport(
                server_name=getattr(server_spec, "server_name", ""),
                package_name=package_name,
                version=version,
                status="INTEGRITY_VERIFIED",
                baseline_hash=baseline_hash,
                live_hash=live_hash
            )
            
        from mcp_fingerprints.drift_detector import compare_passports_for_drift
        
        old_source = {
            package_name: {
                "package_name": package_name,
                "versions": [
                    {
                        "version": version,
                        "toolset_canonical_hash": baseline_hash,
                        "tool_signatures": [
                            {"name": t.name, "canonical_hash": t.canonical_hash} 
                            for t in baseline_ver.tool_signatures
                        ]
                    }
                ]
            }
        }
        
        live_signatures = [extract_tool_signature(t) for t in runtime_tools]
        new_source = {
            package_name: {
                "package_name": package_name,
                "versions": [
                    {
                        "version": version,
                        "toolset_canonical_hash": live_hash,
                        "tool_signatures": [
                            {"name": t.name, "canonical_hash": t.canonical_hash} 
                            for t in live_signatures
                        ]
                    }
                ]
            }
        }
        
        drift_report = compare_passports_for_drift(old_source, new_source)
        
        incidents = []
        for inc in drift_report.incidents:
            if inc.incident_type == "tool_added":
                inc.incident_type = "SHADOW_TOOL_INJECTED"
                inc.severity = "CRITICAL"
                inc.details = f"Tool {', '.join(inc.affected_tools)} was injected."
            elif inc.incident_type == "tool_removed":
                inc.incident_type = "MISSING_CRITICAL_TOOLS"
                inc.severity = "MEDIUM"
                inc.details = f"Tool {', '.join(inc.affected_tools)} is missing."
            elif inc.incident_type == "hash_tamper":
                inc.incident_type = "SCHEMA_TAMPERING"
                inc.severity = "HIGH"
                inc.details = "Tool schema was tampered with."
                # We need to find affected tools
                baseline_tools = {t.name: t for t in baseline_ver.tool_signatures}
                live_tools_map = {t.name: t for t in live_signatures}
                common_tools = set(live_tools_map.keys()).intersection(set(baseline_tools.keys()))
                affected = []
                for tool_name in common_tools:
                    if live_tools_map[tool_name].canonical_hash != baseline_tools[tool_name].canonical_hash:
                        affected.append(tool_name)
                inc.affected_tools = affected
                
                # If no specific schema changes (e.g. just tool added/removed), drop this incident
                if not affected:
                    continue
                
            incidents.append(inc)
            
        if desc_tampered:
            incidents.append(TamperIncident(
                package_name=package_name,
                version=version,
                incident_type="DESCRIPTION_TAMPERING",
                severity="MEDIUM",
                details=f"Tool description behavior drifted for tools: {', '.join(desc_tampered)}",
                affected_tools=desc_tampered
            ))

        return TamperReport(
            server_name=getattr(server_spec, "server_name", ""),
            package_name=package_name,
            version=version,
            status="TAMPERED",
            baseline_hash=baseline_hash,
            live_hash=live_hash,
            incidents=incidents
        )
