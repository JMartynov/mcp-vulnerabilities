from typing import Optional
from mcp_vulnerabilities.threat.epss import EpssScore

class CompositeRiskScorer:
    @staticmethod
    def calculate_trust_score(
        base_score: float = 100.0,
        critical_high_count: int = 0,
        medium_count: int = 0,
        low_count: int = 0,
        protocol_risk_penalty: float = 0.0,
        critical_high_unreachable_count: int = 0,
        medium_unreachable_count: int = 0,
        low_unreachable_count: int = 0,
    ) -> float:
        # Unreachable vulnerabilities are capped at 15.0 points total
        raw_unreachable_penalty = 2.0 * critical_high_unreachable_count + 0.5 * medium_unreachable_count + 0.1 * low_unreachable_count
        unreachable_penalty = min(15.0, raw_unreachable_penalty)
        
        # Reachable vulnerabilities are not capped (direct tool-reachable retain full risk penalty)
        reachable_penalty = 2.0 * critical_high_count + 0.5 * medium_count + 0.1 * low_count
        
        score = base_score - unreachable_penalty - reachable_penalty - protocol_risk_penalty
        return max(0.0, min(100.0, round(score, 1)))

    @staticmethod
    def calculate_trust_tier(trust_score: float) -> str:
        if trust_score >= 90.0:
            return "EXCELLENT"
        elif trust_score >= 75.0:
            return "GOOD"
        elif trust_score >= 50.0:
            return "FAIR"
        return "RISKY"

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
