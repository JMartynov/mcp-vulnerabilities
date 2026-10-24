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
    surface: Dict[str, Any] = field(default_factory=dict)

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
            "surface": self.surface,
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
            surface={
                "instructions": client.surface.instructions,
                "capabilities": client.surface.capabilities,
                "tools_count": len(client.surface.tools),
                "prompts_count": len(client.surface.prompts),
                "resources_count": len(client.surface.resources),
                "tools": client.surface.tools,
                "prompts": client.surface.prompts,
                "resources": client.surface.resources,
            },
        )


@dataclass
class IdentificationResult:
    match_result: Any  # FingerprintMatchResult from mcp_fingerprints
    is_identified: bool
    package_name: str | None = None
    version: str | None = None
    confidence_score: float = 0.0
    vulnerabilities: List[Any] = field(default_factory=list)  # OsvVulnerability objects


class BehavioralTopologyIdentifier:
    def __init__(self, matcher=None, correlator=None):
        self.matcher = matcher
        self.correlator = correlator

    def identify_and_correlate(
        self,
        target: str | List[str],
        headers: Dict[str, str] | None = None,
        timeout: float = 10.0,
        min_confidence: float = 0.85,
    ) -> IdentificationResult:
        from mcp_fingerprints.prober import McpProber

        prober = McpProber(matcher=self.matcher)

        # probe() handles stdio vs http depending on target structure
        report = prober.probe(
            target=target,
            headers=headers,
            timeout=timeout,
            min_confidence_threshold=min_confidence,
        )

        if report.error:
            if "TimeoutExpired" in report.error or "timeout" in report.error.lower() or "failed to receive" in report.error.lower():
                raise TimeoutError(f"PROCESS_PROBE_TIMEOUT: {report.error}")
            raise RuntimeError(f"Probing failed: {report.error}")

        match = report.match_result
        if not match or not getattr(match, "matched", getattr(match, "is_identified", match.confidence_score >= min_confidence)):
            return IdentificationResult(
                match_result=match,
                is_identified=False,
                confidence_score=match.confidence_score if match else 0.0,
            )

        pkg_name = match.package_name
        version = match.matched_version if hasattr(match, "matched_version") else getattr(match, "version", None)

        vulns = []
        if self.correlator and pkg_name:
            timeline_res = self.correlator.correlate_package(pkg_name)
            if timeline_res:
                for state in timeline_res.timeline:
                    if state.version == version and state.is_vulnerable:
                        vulns.extend(state.matching_advisories if hasattr(state, "matching_advisories") else getattr(state, "advisories", []))

        return IdentificationResult(
            match_result=match,
            is_identified=True,
            package_name=pkg_name,
            version=version,
            confidence_score=match.confidence_score,
            vulnerabilities=vulns,
        )

