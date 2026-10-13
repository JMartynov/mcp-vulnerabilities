# Task 23 Contract: Multi-Engine Heuristic Threat Analyzer (YARA & RegEx Pattern Engine)

## Objective
Implement an extensible, high-performance rule-based threat analyzer for MCP servers that inspects tool descriptions, parameter schemas, prompt templates, resource annotations, and server instructions for security threats. The engine operates independently of external commercial APIs, combining compiled YARA rules with a zero-dependency compiled RegEx fallback engine to detect Prompt Injection, Arbitrary Code/Command Execution, and Credential Exfiltration.

> [!IMPORTANT]
> **STRICT LIVE EXECUTION REQUIREMENT (NO MOCKS)**: Acceptance scenarios MUST be 100% live — running against authentic schema payloads, real files on disk, real CLI invocations, and live passport data from `data/passports.json.gz`. Do NOT use `unittest.mock` or `@patch` for acceptance tests. All acceptance scenarios must inspect real objects.

---

## Detailed Technical Architecture & Implementation

### 1. Subsystem Location: `src/mcp_vulnerabilities/analyzers/`
Create package `src/mcp_vulnerabilities/analyzers/` with the following modular structure:
- `models.py`:
  - `ThreatSeverity`: Enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
  - `ThreatCategory`: Enum (`PROMPT_INJECTION`, `CODE_EXECUTION`, `CREDENTIAL_EXFILTRATION`, `SYSTEM_OVERRIDE`, `RESOURCE_HIJACKING`).
  - `ThreatFinding`: Data class capturing `rule_id`, `category`, `severity`, `title`, `description`, `matched_target` (e.g., `tool:execute_query.parameter:sql`), `matched_pattern`, `remediation_guidance`, and `cwe_id`.
  - `AnalysisTarget`: Data class encapsulating extracted textual surfaces: `tools` (list of tool schemas), `prompts` (list of prompt templates), `resources` (list of resource definitions), and `instructions` (server-level instruction string).
- `threat_engine.py`:
  - `ThreatEngine`: Core orchestrator.
  - Detection pipeline:
    1. Extracts all inspectable strings from `AnalysisTarget` (names, descriptions, parameter property descriptions, prompt argument descriptions, system instructions).
    2. Runs configured rules through either the native `yara` engine (if `yara-python` is installed in the runtime environment) or the built-in `RegexThreatMatcher`.
    3. Aggregates, deduplicates, and scores findings according to severity.
- `rules/`:
  - Built-in curated rule sets covering:
    - **Prompt Injection & System Overrides**: Detects delimiter escaping (`---`, ````json`), role manipulation (`You are now in debug mode`, `Ignore all previous instructions`, `System prompt override`), and instruction concealment (hidden zero-width characters, encoded markdown).
    - **Arbitrary Command Execution**: Detects indicators of shell execution, dynamic language evaluation (`eval()`, `exec()`, `os.system`, `/bin/sh -c`, `subprocess.Popen`) exposed in tool metadata or instructions.
    - **Data & Credential Exfiltration**: Identifies patterns requesting or leaking sensitive environment variables (`AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `.env` file paths, SSH private keys, `id_rsa`).
- `regex_matcher.py`:
  - Pure standard library fallback matching engine compiled with `re.VERBOSE` and pre-compiled regex automata. Ensures 100% operation in minimal environments where C-based YARA bindings cannot be compiled.

### 2. CLI & Pipeline Integration
- Update `src/mcp_vulnerabilities/cli.py`:
  - Add `--analyzers` option to `mcp-vuln probe` (default: `all` or comma-separated list: `threat,osv`).
  - Output formatting: Terminal colored cards for each finding with OWASP MCP Top 10 mappings and suggested remediation.
  - Exit code support: `--fail-on {CRITICAL,HIGH}` to gate CI/CD pipelines when malicious patterns are detected.

---

## Clear Acceptance Criteria

1. **Dual-Engine Execution**:
   - The threat engine seamlessly evaluates targets using compiled YARA rules when available, and automatically falls back to `RegexThreatMatcher` without errors or missing rules when `yara-python` is omitted.
2. **Comprehensive Surface Coverage**:
   - Evaluates tool descriptions, parameter descriptions, prompt template arguments, and server instructions.
3. **Adversarial Pattern Detection**:
   - Detects prompt injection payloads with 100% precision on curated evaluation fixtures.
   - Detects shell/command execution indicators in tool definitions.
   - Detects credential and sensitive file exfiltration patterns.
4. **Deterministic Structured Output**:
   - Emits structured `ThreatFinding` objects serializable to JSON and compatible with OASIS SARIF v2.1.0 conversion.
5. **No Commercial Cloud Dependencies**:
   - Entirely local, offline-capable, and private; zero data transmitted to third-party APIs.

---

## Comprehensive Test Plan

### A. Unit Tests (`tests/test_threat_engine.py`)
- Test regex pattern compilation and correctness across edge cases.
- Test `ThreatFinding` serialization and severity ranking.
- Test extraction of inspectable strings from malformed or missing tool schemas.
- Test fallback mechanism when YARA module is mocked/unavailable.

### B. Live Acceptance Tests (Zero Mocks — Real Inspection Targets)
- `test_live_prompt_injection_detection`: Run the engine against real, live-generated tool schemas containing genuine jailbreak and injection payloads (e.g. DAN-style overrides, hidden prompt delimiters). Verify that all threats are flagged with severity `CRITICAL` and appropriate CWE tags.
- `test_live_command_execution_schema_detection`: Run the engine against a real tool definition exposing a remote code execution interface. Verify detection with `CODE_EXECUTION` category.
- `test_live_credential_exfiltration_detection`: Run the engine against a real MCP server manifest declaring parameters for reading `.ssh/id_rsa` or environment secrets. Verify detection with `CREDENTIAL_EXFILTRATION` category.
- `test_live_clean_tool_passports`: Run the engine across 100 real server passports loaded from `data/passports.json.gz` to ensure false positive rate is verified and logged.
