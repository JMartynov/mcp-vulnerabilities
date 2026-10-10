import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List

from mcp_vulnerabilities.audit import DiscoveredClientServer, VulnerabilityMatcher
from mcp_vulnerabilities.probe.client import McpProbeClient

logger = logging.getLogger(__name__)

# Known potentially dangerous tool names/keywords
HIGH_RISK_TOOL_NAMES = {
    "cypher_query",
    "write_file",
    "shell_exec",
    "execute_command",
    "evaluate_code",
    "run_command",
    "exec",
    "system",
}


@dataclass
class ToolWarning:
    tool_name: str
    description: str
    reason: str


@dataclass
class ProbeAuditReport:
    server_name: str
    server_version: str
    findings: List[Any] = field(
        default_factory=list
    )  # List[AuditFinding] from VulnerabilityMatcher
    tool_warnings: List[ToolWarning] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "server_name": self.server_name,
            "server_version": self.server_version,
            "findings": [
                {
                    "server_name": f.server_name,
                    "package_name": f.package_name,
                    "installed_version": f.installed_version,
                    "vulnerability_id": f.vulnerability_id,
                }
                for f in self.findings
            ],
            "tool_warnings": [
                {
                    "tool_name": w.tool_name,
                    "description": w.description,
                    "reason": w.reason,
                }
                for w in self.tool_warnings
            ],
        }


class McpFingerprinter:
    def __init__(self, matcher: VulnerabilityMatcher):
        self.matcher = matcher

    def scan(self, client: McpProbeClient, command_or_url: str) -> ProbeAuditReport:
        server_name = client.server_info.get("name", "unknown")
        server_version = client.server_info.get("version", "unknown")

        # Create DiscoveredClientServer to use the existing Matcher logic
        discovered_server = DiscoveredClientServer(
            server_name=server_name,
            package_name=server_name,
            version=server_version if server_version != "unknown" else None,
            ecosystem="npm",  # Default to npm, the matcher can handle fallback, or PyPI. Realistically we don't know for sure but most are npm or pip
            command="probe",
            args=[command_or_url],
        )

        # Audit with Matcher
        audit_report = self.matcher.audit_servers([discovered_server])

        # Check tools for high-risk names
        tool_warnings: List[ToolWarning] = []
        for tool in client.tools:
            name = tool.get("name", "")
            if name in HIGH_RISK_TOOL_NAMES or any(
                risk in name.lower() for risk in HIGH_RISK_TOOL_NAMES
            ):
                tool_warnings.append(
                    ToolWarning(
                        tool_name=name,
                        description=tool.get("description", ""),
                        reason="Matches known high-risk/vulnerable tool signature.",
                    )
                )

        return ProbeAuditReport(
            server_name=server_name,
            server_version=server_version,
            findings=audit_report.findings,
            tool_warnings=tool_warnings,
        )
