from typing import Optional
from mcp_vulnerabilities.threat.epss import EpssScore

class CompositeRiskScorer:
    @staticmethod
    def calculate_composite_score(cvss_score: float, epss_score: Optional[EpssScore]) -> float:
        if epss_score is not None:
            # S_threat = S_CVSS * 0.70 + S_EPSS * 3.0
            return cvss_score * 0.70 + epss_score.score * 3.0
        return float(cvss_score)

    @staticmethod
    def calculate_elevated_tier(base_tier: str, epss_score: Optional[EpssScore]) -> str:
        if epss_score and epss_score.is_high_risk:
            if base_tier == "MEDIUM":
                return "HIGH"
            elif base_tier == "HIGH":
                return "CRITICAL"
        return base_tier
