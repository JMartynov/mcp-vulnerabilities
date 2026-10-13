rule ExplicitPromptInjection
{
    meta:
        category = "PROMPT_INJECTION"
        severity = "CRITICAL"
        title = "Explicit Prompt Injection"
        description = "Detects explicit instructions to ignore previous system prompts or enter debug modes."
        remediation = "Sanitize inputs for common jailbreak phrases and ensure system instructions cannot be overridden."
        cwe = "CWE-74"
    strings:
        $s1 = "ignore all previous instructions" nocase
        $s2 = "you are now in debug mode" nocase
        $s3 = "system prompt override" nocase
    condition:
        any of them
}

rule DelimiterEscaping
{
    meta:
        category = "PROMPT_INJECTION"
        severity = "HIGH"
        title = "Delimiter Escaping"
        description = "Detects markdown delimiters that may be used to escape or confuse parsers."
        remediation = "Ensure input text that uses delimiters is properly escaped."
        cwe = "CWE-74"
    strings:
        $s1 = "---"
        $s2 = "```json"
    condition:
        any of them
}
