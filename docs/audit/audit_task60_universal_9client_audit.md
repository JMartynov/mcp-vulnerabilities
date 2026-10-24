# Empirical Audit — Universal 9-Client Discovery & Multi-Config Edge Cases

## 1. Overview
This technical report details the findings and patches associated with the empirical audit of the Universal 9-Client Discovery and Multi-Config edge cases. The objective was to comprehensively evaluate and improve the configuration parsers to handle non-standard and highly permissive edge-case configurations safely.

## 2. Invariant Coverage & Audit Findings

### Scenario 1: Malformed & Permissive Configuration Parsing Invariant
* **Goal**: Validate that AI client configuration parsers can ingest JSON/JSONC with inline comments (`//`, `/* */`), trailing commas, unquoted keys, and UTF-8 BOM headers.
* **Findings**:
  * **Severity**: HIGH
  * **Observation**: The `ClientConfigParser.parse_file` method utilized `json.loads` and fallbacked to `yaml.safe_load`. The custom regex used to strip comments was incomplete, frequently breaking on URLs contained within JSON string properties, and trailing commas caused JSON validation failures. Additionally, UTF-8 BOMs (`\ufeff`) caused parser crashes.
  * **Patch Application**: Refactored the text cleaner in `parse_file` to strictly avoid replacing `//` when nested within double-quoted strings (using `r'"(?:\\.|[^"\\])*"'`), added handling to strip multiline `/* */` comments, removed UTF-8 BOM headers early in the pipeline, and safely removed trailing commas via regex capture groups before fallback to `yaml.safe_load`.

### Scenario 2: Global Package Discovery & Symlink Loop Guard Invariant
* **Goal**: Verify that symlink directory cycles (particularly common in `npm -g` cache or `.npx` roots) do not trigger `RecursionError` or endless loops during server discovery.
* **Findings**:
  * **Severity**: MEDIUM
  * **Observation**: Auditing `mcp_fingerprints.config_scanner.NpmGlobalScanner` (from upstream/dependency) revealed that the discovery process heavily relies on `Path.iterdir()`. Because `iterdir()` inherently performs shallow unrolling (checking `@scope/name` vs `package_name` and reading `package.json` immediately) rather than deep recursive globbing (`rglob` or custom DFS), it fundamentally sidesteps infinite loop cycles natively without crashing.
  * **Patch Application**: No direct core parser changes were strictly needed to handle infinite loops since `iterdir` is bounded to a depth of 1 or 2 explicitly. Test suite simulation with true recursive loops validated non-crashing behavior.

### Scenario 3: Cross-Platform Path & Environment Variable Expansion Invariant
* **Goal**: Ensure paths are cleanly normalized across OS environments (Windows `\` vs POSIX `/`), ensure environment variables like `${VAR}` expand effectively during command instantiation, and assert that secrets in configs do not leak.
* **Findings**:
  * **Severity**: HIGH
  * **Observation**: Environment variables specified in the command arguments were not being hydrated into execution directives, and path separators were inconsistently loaded depending on the OS generating the client config. Crucially, secret tokens stored in the `env` dictionary of client configs were passing natively into outputs unredacted.
  * **Patch Application**: In `ClientConfigParser._parse_server_entry`:
    * Substituted raw command instantiation with standard string replacement `replace("\\", "/")` to force consistent path strings.
    * Added standard library `os.path.expandvars` logic to expand `${VAR}` mappings inline.
    * Introduced a proactive security filter replacing values linked to known secret keys (matching regex `KEY|TOKEN|SECRET|PASSWORD`) with `***REDACTED***` to ensure stdout/SARIF telemetry remains safe.

## 3. Conclusion
The audit resulted in substantial improvements to configuration resilience. The parsers now tolerate wide variability in developer client configurations without regression, actively hydrate context for execution consistency across Windows/macOS/Linux, and sanitize sensitive telemetry securely. The verification suite `tests/audit/test_audit_task60.py` has been merged to enforce these invariants continuously.
