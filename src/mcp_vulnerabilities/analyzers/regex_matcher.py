import re
from re import Pattern

from .models import ThreatCategory, ThreatSeverity


class RegexThreatMatcher:
    def __init__(self):
        # Dictionary of rule_id to (pattern, category, severity, title, description, remediation, cwe)
        self.rules: dict[str, tuple[Pattern, ThreatCategory, ThreatSeverity, str, str, str, str]] = {}
        self._initialize_rules()
        
    def _initialize_rules(self):
        # Prompt Injection & System Overrides
        self.add_rule(
            rule_id="R_PROMPT_INJ_001",
            pattern=r"(?i)(ignore\s+all\s+previous\s+instructions|you\s+are\s+now\s+in\s+debug\s+mode|system\s+prompt\s+override)",
            category=ThreatCategory.PROMPT_INJECTION,
            severity=ThreatSeverity.CRITICAL,
            title="Explicit Prompt Injection",
            description="Detects explicit instructions to ignore previous system prompts or enter debug modes.",
            remediation="Sanitize inputs for common jailbreak phrases and ensure system instructions cannot be overridden.",
            cwe="CWE-74"
        )
        self.add_rule(
            rule_id="R_PROMPT_INJ_002",
            pattern=r"(?m)^(---|```json)$",
            category=ThreatCategory.PROMPT_INJECTION,
            severity=ThreatSeverity.HIGH,
            title="Delimiter Escaping",
            description="Detects markdown delimiters that may be used to escape or confuse parsers.",
            remediation="Ensure input text that uses delimiters is properly escaped.",
            cwe="CWE-74"
        )
        self.add_rule(
            rule_id="R_PROMPT_INJ_003",
            pattern=r"[\u200B-\u200D\uFEFF]",
            category=ThreatCategory.PROMPT_INJECTION,
            severity=ThreatSeverity.HIGH,
            title="Hidden Instruction Concealment",
            description="Detects hidden zero-width characters commonly used to conceal malicious instructions.",
            remediation="Remove or sanitize zero-width characters from input strings.",
            cwe="CWE-74"
        )
        
        # Arbitrary Command Execution
        self.add_rule(
            rule_id="R_CODE_EXEC_001",
            pattern=r"(?i)\b(?:eval|exec|os\.system|subprocess\.Popen)\s*\(",
            category=ThreatCategory.CODE_EXECUTION,
            severity=ThreatSeverity.CRITICAL,
            title="Dynamic Language Evaluation",
            description="Detects usage of dangerous functions that evaluate dynamic code or execute commands.",
            remediation="Avoid using eval() or os.system() and use safe alternatives or restrict input.",
            cwe="CWE-94"
        )
        self.add_rule(
            rule_id="R_CODE_EXEC_002",
            pattern=r"(?i)/bin/sh\s+-c",
            category=ThreatCategory.CODE_EXECUTION,
            severity=ThreatSeverity.CRITICAL,
            title="Shell Execution Indicator",
            description="Detects direct invocation of a shell to execute commands.",
            remediation="Avoid executing arbitrary shell commands and use specific APIs instead.",
            cwe="CWE-78"
        )
        
        # Credential Exfiltration
        self.add_rule(
            rule_id="R_CRED_EXFIL_001",
            pattern=r"(?i)\b(?:AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|id_rsa|\.env)\b",
            category=ThreatCategory.CREDENTIAL_EXFILTRATION,
            severity=ThreatSeverity.CRITICAL,
            title="Sensitive Data Request",
            description="Detects requests or indicators targeting sensitive credentials or files.",
            remediation="Do not expose credentials or sensitive file paths in tool parameters or descriptions.",
            cwe="CWE-200"
        )

    def add_rule(self, rule_id: str, pattern: str, category: ThreatCategory, severity: ThreatSeverity, title: str, description: str, remediation: str, cwe: str):
        self.rules[rule_id] = (
            re.compile(pattern, re.VERBOSE),
            category,
            severity,
            title,
            description,
            remediation,
            cwe
        )

    def match(self, text: str) -> list[tuple[str, str, ThreatCategory, ThreatSeverity, str, str, str, str]]:
        matches = []
        for rule_id, (pattern, category, severity, title, description, remediation, cwe) in self.rules.items():
            found = pattern.search(text)
            if found:
                matches.append((
                    rule_id,
                    found.group(0),
                    category,
                    severity,
                    title,
                    description,
                    remediation,
                    cwe
                ))
        return matches
