rule SensitiveDataRequest
{
    meta:
        category = "CREDENTIAL_EXFILTRATION"
        severity = "CRITICAL"
        title = "Sensitive Data Request"
        description = "Detects requests or indicators targeting sensitive credentials or files."
        remediation = "Do not expose credentials or sensitive file paths in tool parameters or descriptions."
        cwe = "CWE-200"
    strings:
        $s1 = "AWS_SECRET_ACCESS_KEY" nocase
        $s2 = "GITHUB_TOKEN" nocase
        $s3 = "id_rsa" nocase
        $s4 = ".env" nocase
    condition:
        any of them
}
