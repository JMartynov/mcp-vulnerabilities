from typing import List, Dict, Any, Tuple
from .models import ComplianceTier, ComplianceViolation, OwaspComplianceReport
from mcp_vulnerabilities.analyzers.models import ReadinessIssue, ThreatFinding

# Mapping of original rule IDs to OWASP IDs
# We map Readiness rules, Threat Categories, and potentially AST taint categories.
RULE_MAPPINGS = {
    # Threats
    "SUPPLY_CHAIN": ("LLM03:2025", "MCP04", "Supply Chain Vulnerabilities"),
    "MALWARE": ("LLM03:2025", "MCP04", "Supply Chain Vulnerabilities"),
    "PROMPT_INJECTION": ("LLM01:2025", "MCP06", "Prompt Injection"),
    "CREDENTIAL_EXFILTRATION": ("LLM02:2025", "MCP01", "Sensitive Information Disclosure"),
    
    # AST Taint (typically string representation)
    "COMMAND_INJECTION": ("LLM05:2025", "MCP05", "Improper Output Handling"),
    "CODE_EVALUATION": ("LLM05:2025", "MCP05", "Improper Output Handling"),
    "SQL_INJECTION": ("LLM05:2025", "MCP05", "Improper Output Handling"),

    # Readiness
    "MCP-R006": ("LLM06:2025", "MCP02", "Excessive Agency"),
    "MCP-R007": ("LLM06:2025", "MCP02", "Excessive Agency"),
    "MCP-R001": ("LLM00", "MCP03", "Tool Poisoning / Shadowing"),  # No direct LLM0X for schema quality, maybe None or N/A, we use LLM00 or just empty
    "MCP-R002": ("LLM00", "MCP03", "Tool Poisoning / Shadowing"),
    "MCP-R003": ("LLM00", "MCP03", "Tool Poisoning / Shadowing"),
    "MCP-R004": ("LLM00", "MCP03", "Tool Poisoning / Shadowing"),
    "MCP-R005": ("LLM00", "MCP03", "Tool Poisoning / Shadowing"),
}

class OwaspComplianceScorer:
    @classmethod
    def _map_rule(cls, rule_id: str) -> Tuple[str, str, str]:
        if rule_id in RULE_MAPPINGS:
            return RULE_MAPPINGS[rule_id]
        
        # Fallbacks or string matching
        if "PROMPT_INJECTION" in rule_id.upper() or rule_id.endswith(".yar"):
             return ("LLM01:2025", "MCP06", "Prompt Injection")
        if "EXFILTRATION" in rule_id.upper() or "CREDENTIAL" in rule_id.upper():
             return ("LLM02:2025", "MCP01", "Sensitive Information Disclosure")
        if "INJECTION" in rule_id.upper() or "EVAL" in rule_id.upper():
             return ("LLM05:2025", "MCP05", "Improper Output Handling")
        if rule_id.startswith("MCP-R"):
             return ("LLM06:2025", "MCP02", "Excessive Agency")
        
        # Default fallback
        return ("LLMXX:2025", "MCPXX", "Unknown Vulnerability")

    @classmethod
    def evaluate(
        cls, 
        readiness_issues: List[ReadinessIssue] = None, 
        threat_findings: List[ThreatFinding] = None,
        taint_findings: List[Any] = None
    ) -> OwaspComplianceReport:
        readiness_issues = readiness_issues or []
        threat_findings = threat_findings or []
        taint_findings = taint_findings or []

        violations = []
        score = 100

        for issue in readiness_issues:
            owasp_id, mcp_id, cat_name = cls._map_rule(issue.rule_id)
            violations.append(
                ComplianceViolation(
                    owasp_id=owasp_id,
                    owasp_mcp_id=mcp_id,
                    category_name=cat_name,
                    severity=issue.severity,
                    target=issue.target,
                    description=issue.message,
                    remediation_guidance=issue.recommendation,
                    original_rule_id=issue.rule_id
                )
            )
            score -= cls._penalty(issue.severity)

        for finding in threat_findings:
            owasp_id, mcp_id, cat_name = cls._map_rule(finding.category.value)
            violations.append(
                ComplianceViolation(
                    owasp_id=owasp_id,
                    owasp_mcp_id=mcp_id,
                    category_name=cat_name,
                    severity=finding.severity.value,
                    target=finding.matched_target,
                    description=finding.description,
                    remediation_guidance=finding.remediation_guidance,
                    original_rule_id=finding.rule_id
                )
            )
            score -= cls._penalty(finding.severity.value)

        for taint in taint_findings:
            # Assuming taint object has sink_category, severity, sink_call, remediation
            cat = getattr(taint, "sink_category", "UNKNOWN")
            owasp_id, mcp_id, cat_name = cls._map_rule(cat)
            sev = getattr(taint, "severity", "HIGH")
            target = getattr(taint, "tool_name", "unknown")
            desc = f"Dangerous AST taint: {getattr(taint, 'sink_call', cat)}"
            rem = getattr(taint, "remediation", "Review input sanitation")
            violations.append(
                ComplianceViolation(
                    owasp_id=owasp_id,
                    owasp_mcp_id=mcp_id,
                    category_name=cat_name,
                    severity=sev,
                    target=f"tool:{target}",
                    description=desc,
                    remediation_guidance=rem,
                    original_rule_id=cat
                )
            )
            score -= cls._penalty(sev)

        score = max(0, score)
        
        tier = ComplianceTier.COMPLIANT
        if score < 70:
            tier = ComplianceTier.NON_COMPLIANT
        elif score < 100:
            tier = ComplianceTier.PARTIALLY_COMPLIANT

        # Sort violations by severity and category
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "WARNING": 4, "INFO": 5}
        violations.sort(key=lambda x: (severity_order.get(x.severity, 99), x.owasp_mcp_id))

        return OwaspComplianceReport(
            score=score,
            tier=tier,
            violations=violations
        )

    @staticmethod
    def _penalty(severity: str) -> int:
        sev = severity.upper()
        if sev == "CRITICAL": return 20
        if sev == "HIGH": return 15
        if sev == "MEDIUM" or sev == "WARNING": return 5
        if sev == "LOW" or sev == "INFO": return 1
        return 0
