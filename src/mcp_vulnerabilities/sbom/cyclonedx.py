import uuid
import datetime
from typing import Any, Dict, List, Optional
from mcp_vulnerabilities.audit.matcher import AuditReport, AuditFinding, DiscoveredClientServer
from mcp_vulnerabilities.probe.fingerprinter import ProbeAuditReport
from mcp_vulnerabilities.fingerprints.canonicalizer import extract_tool_signature, compute_sha256

class CycloneDxBomBuilder:
    def __init__(self):
        self.bom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
                "tools": {
                    "components": [
                        {
                            "type": "application",
                            "author": "mcp-vulnerabilities",
                            "name": "mcp-vuln",
                            "version": "1.0.0"
                        }
                    ]
                }
            },
            "components": [],
            "services": [],
            "dependencies": [],
            "vulnerabilities": []
        }

    def _generate_bom_ref(self, type_str: str, name: str, version: Optional[str] = None) -> str:
        ref = f"{type_str}:{name}"
        if version:
            ref += f"@{version}"
        return ref

    def add_audit_report(self, report: AuditReport) -> None:
        for server in report.scanned_servers:
            self._add_server_component(server)
            
        for finding in report.findings:
            self._add_vulnerability(finding)

    def add_probe_report(self, report: ProbeAuditReport) -> None:
        service_ref = self._generate_bom_ref("service", report.server_name, report.server_version)
        service = {
            "bom-ref": service_ref,
            "type": "application",
            "name": report.server_name,
            "version": report.server_version or "unknown",
            "endpoints": []
        }

        # Tools as components to allow hashes natively in CycloneDX components block
        tools = report.surface.get("tools", [])
        for tool in tools:
            sig = extract_tool_signature(tool)
            endpoint = f"mcp://{report.server_name}/tools/{sig.name}"
            service["endpoints"].append(endpoint)
            
            tool_comp_ref = f"tool:{report.server_name}:{sig.name}"
            tool_comp = {
                "bom-ref": tool_comp_ref,
                "type": "application",
                "name": sig.name,
                "description": sig.description or "",
            }
            if sig.canonical_hash:
                alg, val = sig.canonical_hash.split(":", 1) if ":" in sig.canonical_hash else ("SHA-256", sig.canonical_hash)
                if alg == "sha256": alg = "SHA-256"
                tool_comp["hashes"] = [{"alg": alg, "content": val}]
                
            self.bom["components"].append(tool_comp)
            
            # Dependency linkage
            self.bom["dependencies"].append({
                "ref": service_ref,
                "dependsOn": [tool_comp_ref]
            })
            
        self.bom["services"].append(service)

        for finding in report.findings:
            if isinstance(finding, AuditFinding):
                # Ensure the component exists
                found = False
                bom_ref = self._generate_bom_ref("component", finding.package_name, finding.installed_version)
                for comp in self.bom["components"]:
                    if comp["bom-ref"] == bom_ref:
                        found = True
                        break
                if not found:
                    self._add_server_component(DiscoveredClientServer(
                        server_name=finding.server_name,
                        package_name=finding.package_name,
                        version=finding.installed_version,
                        ecosystem="unknown",
                        command="",
                        args=[]
                    ))
                self._add_vulnerability(finding)

    def _add_server_component(self, server: DiscoveredClientServer) -> None:
        purl_eco = server.ecosystem.lower() if server.ecosystem else "generic"
        purl = f"pkg:{purl_eco}/{server.package_name}"
        if server.version:
            purl += f"@{server.version}"
        
        bom_ref = self._generate_bom_ref("component", server.package_name, server.version)
        
        # Check if already exists
        for c in self.bom["components"]:
            if c["bom-ref"] == bom_ref:
                return
                
        comp = {
            "bom-ref": bom_ref,
            "type": "library",
            "name": server.package_name,
            "purl": purl
        }
        if server.version:
            comp["version"] = server.version
            
        self.bom["components"].append(comp)

    def _add_vulnerability(self, finding: AuditFinding) -> None:
        bom_ref = self._generate_bom_ref("component", finding.package_name, finding.installed_version)
        
        vuln = {
            "id": finding.vulnerability_id,
            "ratings": [],
            "affects": [
                {
                    "ref": bom_ref,
                    "versions": [
                        {
                            "version": finding.installed_version or "unknown",
                            "status": "affected" if finding.is_confirmed else "unknown"
                        }
                    ]
                }
            ],
            "analysis": {
                "state": "affected" if finding.is_confirmed else "in_triage",
                "detail": finding.summary or "No summary provided."
            }
        }
        
        if finding.severity_level:
            severity_map = {
                "CRITICAL": "critical",
                "HIGH": "high",
                "MEDIUM": "medium",
                "LOW": "low",
                "MODERATE": "medium"
            }
            mapped_sev = severity_map.get(finding.severity_level.upper(), "unknown")
            
            rating = {
                "severity": mapped_sev,
                "method": "CVSSv3" if finding.cvss_score else "other"
            }
            if finding.cvss_score:
                rating["score"] = finding.cvss_score
            vuln["ratings"].append(rating)
                
        if finding.references:
            vuln["advisories"] = [{"url": ref} for ref in finding.references]
            
        self.bom["vulnerabilities"].append(vuln)
        
    def build(self) -> Dict[str, Any]:
        res = {k: v for k, v in self.bom.items() if v or k in ("components", "services", "vulnerabilities", "dependencies")}
        if not res.get("components"):
            res["components"] = []
        return res
