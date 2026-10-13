from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

class ComplianceTier(str, Enum):
    COMPLIANT = "COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"

@dataclass
class ComplianceViolation:
    owasp_id: str
    owasp_mcp_id: str
    category_name: str
    severity: str
    target: str
    description: str
    remediation_guidance: str
    original_rule_id: str

@dataclass
class OwaspComplianceReport:
    score: int
    tier: ComplianceTier
    violations: List[ComplianceViolation] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "tier": self.tier.value,
            "violations": [
                {
                    "owasp_id": v.owasp_id,
                    "owasp_mcp_id": v.owasp_mcp_id,
                    "category_name": v.category_name,
                    "severity": v.severity,
                    "target": v.target,
                    "description": v.description,
                    "remediation_guidance": v.remediation_guidance,
                    "original_rule_id": v.original_rule_id,
                }
                for v in self.violations
            ]
        }
