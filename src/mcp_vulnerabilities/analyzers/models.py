from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal


class ThreatSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ThreatCategory(str, Enum):
    PROMPT_INJECTION = "PROMPT_INJECTION"
    CODE_EXECUTION = "CODE_EXECUTION"
    CREDENTIAL_EXFILTRATION = "CREDENTIAL_EXFILTRATION"
    SYSTEM_OVERRIDE = "SYSTEM_OVERRIDE"
    RESOURCE_HIJACKING = "RESOURCE_HIJACKING"

@dataclass
class ThreatFinding:
    rule_id: str
    category: ThreatCategory
    severity: ThreatSeverity
    title: str
    description: str
    matched_target: str
    matched_pattern: str
    remediation_guidance: str
    cwe_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "matched_target": self.matched_target,
            "matched_pattern": self.matched_pattern,
            "remediation_guidance": self.remediation_guidance,
            "cwe_id": self.cwe_id,
        }

@dataclass
class AnalysisTarget:
    tools: list[dict[str, Any]] = field(default_factory=list)
    prompts: list[dict[str, Any]] = field(default_factory=list)
    resources: list[dict[str, Any]] = field(default_factory=list)
    instructions: str = ""


@dataclass
class ReadinessIssue:
    rule_id: str
    severity: Literal["CRITICAL", "WARNING", "INFO"]
    target: str
    message: str
    recommendation: str


@dataclass
class ReadinessReport:
    target_name: str
    score: int
    grade: Literal["A", "B", "C", "D", "F"]
    issues: list[ReadinessIssue] = field(default_factory=list)
    summary_counts: dict[str, int] = field(default_factory=dict)


class ProtocolTrustStatus(str, Enum):
    VERIFIED = "VERIFIED"
    RESTRICTED = "RESTRICTED"
    ELEVATED_RISK = "ELEVATED_RISK"
    SUSPICIOUS = "SUSPICIOUS"


class SupplyChainStatus(str, Enum):
    CLEAN = "CLEAN"
    OUTDATED = "OUTDATED"
    VULNERABLE = "VULNERABLE"
    CRITICAL_ATTACK_SURFACE = "CRITICAL_ATTACK_SURFACE"


class ReachabilityStatus(str, Enum):
    REACHABLE = "REACHABLE"
    UNREACHABLE_TRANSITIVE = "UNREACHABLE_TRANSITIVE"
    UNKNOWN = "UNKNOWN"


@dataclass
class ProtocolTrustAssessment:
    status: ProtocolTrustStatus = ProtocolTrustStatus.VERIFIED
    tool_capabilities: list[str] = field(default_factory=list)
    prompt_injection_guard: str = "UNGUARDED"
    parameter_sanitization: bool = False
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "tool_capabilities": self.tool_capabilities,
            "prompt_injection_guard": self.prompt_injection_guard,
            "parameter_sanitization": self.parameter_sanitization,
            "findings": self.findings,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ProtocolTrustAssessment":
        return cls(
            status=ProtocolTrustStatus(data.get("status", "VERIFIED")),
            tool_capabilities=data.get("tool_capabilities", []),
            prompt_injection_guard=data.get("prompt_injection_guard", "UNGUARDED"),
            parameter_sanitization=data.get("parameter_sanitization", False),
            findings=data.get("findings", []),
        )


@dataclass
class SupplyChainHygieneAssessment:
    status: SupplyChainStatus = SupplyChainStatus.CLEAN
    trivy_scanned: bool = False
    scan_timestamp: str = ""
    vulnerability_counts: dict[str, int] = field(default_factory=lambda: {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0})
    affected_packages: list[dict[str, Any]] = field(default_factory=list)
    reachability: ReachabilityStatus = ReachabilityStatus.UNKNOWN
    recommended_safe_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status.value,
            "trivy_scanned": self.trivy_scanned,
            "scan_timestamp": self.scan_timestamp,
            "vulnerability_counts": self.vulnerability_counts,
            "affected_packages": self.affected_packages,
            "reachability": self.reachability.value,
            "recommended_safe_version": self.recommended_safe_version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SupplyChainHygieneAssessment":
        return cls(
            status=SupplyChainStatus(data.get("status", "CLEAN")),
            trivy_scanned=data.get("trivy_scanned", False),
            scan_timestamp=data.get("scan_timestamp", ""),
            vulnerability_counts=data.get("vulnerability_counts", {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}),
            affected_packages=data.get("affected_packages", []),
            reachability=ReachabilityStatus(data.get("reachability", "UNKNOWN")),
            recommended_safe_version=data.get("recommended_safe_version"),
        )


@dataclass
class DualAxisSecurityAssessment:
    protocol_trust: ProtocolTrustAssessment = field(default_factory=ProtocolTrustAssessment)
    supply_chain_hygiene: SupplyChainHygieneAssessment = field(default_factory=SupplyChainHygieneAssessment)

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol_trust": self.protocol_trust.to_dict(),
            "supply_chain_hygiene": self.supply_chain_hygiene.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "DualAxisSecurityAssessment":
        pt = data.get("protocol_trust", {})
        sc = data.get("supply_chain_hygiene", {})
        return cls(
            protocol_trust=ProtocolTrustAssessment.from_dict(pt),
            supply_chain_hygiene=SupplyChainHygieneAssessment.from_dict(sc),
        )
