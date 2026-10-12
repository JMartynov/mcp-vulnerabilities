# Task 23 Contract: Cisco Parity Threat & Readiness Analyzers

## Objective
Implement threat detection engines matching and exceeding `cisco-ai-defense/mcp-scanner` without requiring commercial proprietary cloud subscriptions. Provide YARA pattern matching for tool descriptions, prompt defense heuristics against injection/system overrides, and a production readiness linter.

---

## Architectural Specification

### 1. New Subsystem: `src/mcp_vulnerabilities/analyzers/`
Create package `src/mcp_vulnerabilities/analyzers/` containing:
- `yara_rules.py`:
  - Curated YARA / regex rule signatures detecting:
    - Prompt Injection patterns (e.g. `ignore previous instructions`, `system prompt override`, markdown delimiter hijacking).
    - Dangerous Command Execution & Code Injection (`eval`, `exec`, `subprocess`, `/bin/sh`, reverse shell payloads in tool schemas or descriptions).
    - Data & Credential Exfiltration (`AWS_SECRET_ACCESS_KEY`, `id_rsa`, `.env` exfiltration patterns).
  - Engine: Attempts to use `yara-python` if installed; falls back seamlessly to compiled regex pattern matcher with 100% standard library compatibility if `yara-python` is absent.
- `prompt_defense.py`:
  - Static prompt analyzer scanning MCP prompts and tool descriptions for adversarial prompt injection techniques (jailbreaks, hidden Unicode tags, delimiter escaping).
- `readiness_linter.py`:
  - `ReadinessLinter`: Zero-dependency static analyzer evaluating tool schemas for:
    - Missing or vague tool descriptions (under 10 characters).
    - Untyped or overly broad parameters (`type: "any"` or missing property types).
    - Missing required parameter lists.
    - Lack of timeout or error schema specifications.
    - Returns structured lint warnings with severity ratings (`CRITICAL`, `WARNING`, `INFO`).
- `virustotal.py`:
  - Standalone SHA-256 malware blocklist checker for bundled files, with optional VirusTotal REST API querying if `VIRUSTOTAL_API_KEY` is provided in environment.

---

### 2. CLI Integration
- Add `--analyzers` flag to `mcp-vuln probe`:
  - E.g. `mcp-vuln probe --command "..." --analyzers yara,readiness,prompt`
  - Runs the selected analyzers against the retrieved tool schemas and descriptions.
  - Formats findings in terminal output with OWASP categorization and risk severity.
- Add subcommand `mcp-vuln lint-readiness`:
  - E.g. `mcp-vuln lint-readiness --command "..."` or `--schema schema.json`.

---

### 3. Verification & Acceptance Criteria
- Unit tests in `tests/test_analyzers.py`:
  1. `test_yara_detects_prompt_injection`: Verifies flagging of injection payloads in tool descriptions.
  2. `test_yara_detects_command_execution`: Verifies detection of shell execution indicators.
  3. `test_readiness_linter_flags_missing_types`: Flags untyped or missing property schemas.
  4. `test_virustotal_sha256_blocklist`: Verifies known malware SHA-256 hash lookup.
  5. `test_cli_probe_with_analyzers`: Tests `mcp-vuln probe --analyzers yara,readiness`.
- Non-Interactive Completion Directive: Complete autonomously without asking follow-up questions so session cleanly transitions to `Completed`.
