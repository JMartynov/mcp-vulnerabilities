# Task 112: Comparative Security Drift Engine (P0)

**Subsystem:** Posture Differential Analysis (`src/mcp_vulnerabilities/audit/picture_diff.py`, `tests/test_security_picture_diff.py`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave21_network_inspection_security_picture_and_cli_hub.md](master_plan_wave21_network_inspection_security_picture_and_cli_hub.md)

---

## 1. Objective & Problem Statement

Generic configuration diffing tools (like `diff` or generic JSON comparators) merely highlight line-by-line or key-value text differences. In enterprise AI security governance, security teams do not want line diffs—they need actionable intelligence on **security aspect mutations**:
- Did an update introduce an unpatched remote code execution vulnerability (CVE)?
- Was an existing CVE mitigated by a version upgrade?
- Did a supply-chain attack secretly modify a tool's parameter schema or implementation hash?
- Was a dangerous high-risk tool (such as arbitrary shell execution or file overwriting) newly exposed to an AI model?
- Was an unauthorized "shadow" MCP server started on a local port or added to an IDE configuration?

This task develops the **Comparative Security Drift Engine** (`SecurityPictureDiffer`):
1. Compares a baseline `SecurityPicture` against a live or newly captured `SecurityPicture`.
2. Segregates all detected drift into explicit security categories:
   - 🚨 `newly_introduced_vulnerabilities`
   - ✅ `resolved_vulnerabilities`
   - ⚠️ `tamper_incidents`
   - 🛡️ `new_high_risk_tools`
   - 👥 `added_servers` (Shadow MCP alerts)
   - ❌ `removed_servers`
   - 🔄 `tool_schema_changes`
3. Computes a cumulative drift severity rating (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `CLEAN`) and supports CI gate enforcement with automated exit codes.

---

## 2. Detailed Technical Requirements

### 2.1 Differential Engine Architecture (`src/mcp_vulnerabilities/audit/picture_diff.py`)

1. Implement `SecurityPictureDiffer`:
   ```python
   class SecurityPictureDiffer:
       def __init__(self, high_risk_classifier: HighRiskToolClassifier | None = None) -> None:
           self.classifier = high_risk_classifier or HighRiskToolClassifier()

       def compare(self, baseline: SecurityPicture, current: SecurityPicture) -> SecurityDriftReport:
           ...
   ```

### 2.2 Security Aspect Categorization

The engine matches servers across baseline and current snapshots by their unique composite `id` (`origin:client_or_host:server_name`):

1. 🚨 **`newly_introduced_vulnerabilities`**:
   - Compares the set of CVE/GHSA IDs on current servers against baseline servers.
   - Any CVE/GHSA present on current that was NOT present in baseline is classified here.
   - Enriches each finding with CVSS score, severity, and package version progression (e.g. `1.0.4 -> 1.1.0`).

2. ✅ **`resolved_vulnerabilities`**:
   - Any CVE/GHSA present on a baseline server that is NO LONGER present on the corresponding current server (due to version patch or removal).

3. ⚠️ **`tamper_incidents`**:
   - Detected if a server's `tamper_status` changed to `TAMPERED`.
   - Detected if a server's `toolset_canonical_hash` changed while the declared package version remained identical.
   - Lists exact tool canonical hash discrepancies.

4. 🛡️ **`new_high_risk_tools`**:
   - Identifies any tool newly exposed on a current server (or added via shadow server) that matches high-risk heuristics:
     - **Shell Execution**: tool names or descriptions matching `bash`, `sh`, `execute_command`, `run_command`, `exec`, `terminal`, `powershell`, `cmd`.
     - **Destructive Filesystem**: `write_file`, `delete_file`, `remove_file`, `overwrite_file`, `rmdir`, `modify_file`.
     - **Outbound Network / Exfiltration**: `fetch`, `curl`, `http_request`, `post`, `send_email`, `webhook`, `upload`.
     - **Credential Access**: `read_env`, `get_secret`, `keychain`, `dump_credentials`, `read_auth`.

5. 👥 **`added_servers` (Shadow MCP Alert)**:
   - Any server present in current that did not exist in baseline.
   - Differentiates between local client server addition and network listener discovery.

6. ❌ **`removed_servers`**:
   - Any server present in baseline that is absent from current.

7. 🔄 **`tool_schema_changes`**:
   - Identifies parameter mutations in existing tools: added parameters, removed parameters, type shifts, or changed required arguments.

### 2.3 Report Data Structure & Formatting

```python
@dataclass
class SecurityDriftReport:
    baseline_captured_at: str
    current_captured_at: str
    is_clean: bool
    drift_severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "CLEAN"
    newly_introduced_vulnerabilities: list[dict[str, Any]]
    resolved_vulnerabilities: list[dict[str, Any]]
    tamper_incidents: list[dict[str, Any]]
    new_high_risk_tools: list[dict[str, Any]]
    added_servers: list[dict[str, Any]]
    removed_servers: list[dict[str, Any]]
    tool_schema_changes: list[dict[str, Any]]

    def to_dict(self) -> dict[str, Any]:
        ...

    def to_terminal_summary(self) -> str:
        ...
```

### 2.4 Severity Determination & CI Policy

- **CRITICAL**: Any newly introduced CRITICAL CVE (CVSS >= 9.0) OR any `tamper_incidents`.
- **HIGH**: Any newly introduced HIGH CVE (CVSS 7.0–8.9) OR any `added_servers` exposing `new_high_risk_tools`.
- **MEDIUM**: Newly introduced MEDIUM CVEs (CVSS 4.0–6.9) OR unauthorized `tool_schema_changes`.
- **LOW**: Added servers with low-risk tools OR removed servers.
- **CLEAN**: Zero changes OR only `resolved_vulnerabilities`.

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_112_1 (Self-Diff Zero Drift):** Comparing any `SecurityPicture` against an exact copy of itself yields `is_clean == True`, `drift_severity == "CLEAN"`, and zero entries across all categories.
- [ ] **INVARIANT_112_2 (CVE Introduction Detection):** Bumping a package version from a clean release to a vulnerable release correctly flags `newly_introduced_vulnerabilities` with CVSS score and description.
- [ ] **INVARIANT_112_3 (Mitigation Accounting):** Upgrading a vulnerable server to its recommended safe version correctly records the fixed vulnerability in `resolved_vulnerabilities`.
- [ ] **INVARIANT_112_4 (Tamper Flagging):** Mutating an input schema without changing the package version triggers `tamper_incidents` and classifies overall drift as `CRITICAL`.
- [ ] **INVARIANT_112_5 (High-Risk Tool Classification):** Introducing a new tool named `execute_command` or containing "shell execution" in description triggers `new_high_risk_tools`.
- [ ] **INVARIANT_112_6 (Automated Test Coverage):** `tests/test_security_picture_diff.py` covers all 6 drift categories, severity escalation rules, and JSON/terminal formatting.

---

## 4. Deliverables

1. `src/mcp_vulnerabilities/audit/picture_diff.py`: Implementation of `SecurityPictureDiffer`, `HighRiskToolClassifier`, `SecurityDriftReport`, and formatters.
2. `tests/test_security_picture_diff.py`: Comprehensive test suite verifying categorization precision, severity calculation, and terminal/JSON serialization.
