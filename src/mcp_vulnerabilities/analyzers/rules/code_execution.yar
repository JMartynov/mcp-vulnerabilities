rule DynamicLanguageEvaluation
{
    meta:
        category = "CODE_EXECUTION"
        severity = "CRITICAL"
        title = "Dynamic Language Evaluation"
        description = "Detects usage of dangerous functions that evaluate dynamic code or execute commands."
        remediation = "Avoid using eval() or os.system() and use safe alternatives or restrict input."
        cwe = "CWE-94"
    strings:
        $s1 = "eval(" nocase
        $s2 = "exec(" nocase
        $s3 = "os.system(" nocase
        $s4 = "subprocess.Popen(" nocase
    condition:
        any of them
}

rule ShellExecutionIndicator
{
    meta:
        category = "CODE_EXECUTION"
        severity = "CRITICAL"
        title = "Shell Execution Indicator"
        description = "Detects direct invocation of a shell to execute commands."
        remediation = "Avoid executing arbitrary shell commands and use specific APIs instead."
        cwe = "CWE-78"
    strings:
        $s1 = "/bin/sh -c" nocase
    condition:
        any of them
}
