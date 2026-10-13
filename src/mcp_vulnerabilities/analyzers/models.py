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
