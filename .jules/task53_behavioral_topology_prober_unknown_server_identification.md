# Task 53: Behavioral Topology Prober & Unknown Server Identification (P0)

## 1. Architectural Context & Technical Objective

In enterprise AI setups, developers routinely execute custom scripts, internal wrappers, or compiled binaries rather than referencing canonical npm/PyPI package names directly:
```json
"filesystem_service": {
  "command": "python",
  "args": ["-m", "custom_corp_launcher", "--env", "prod"]
}
```
CLI argument parsing cannot determine what package or version is running, blinding vulnerability scanners to known CVEs lurking within the wrapper.

`mcp-fingerprints` contains `McpIdentifier`, `McpProber`, and topological distance metrics (`compute_tool_topology_similarity`, `jaccard_similarity`, `compute_capability_similarity`). By dynamically querying the server's JSON-RPC interface and comparing its runtime tool schemas against 5,533 server passports, `mcp-vulnerabilities` can accurately determine the underlying package identity and exact version number with high mathematical confidence.

### Core Objectives:
1. Integrate `mcp_fingerprints.prober.McpProber` and `mcp_fingerprints.distance` into `src/mcp_vulnerabilities/probe/` and `src/mcp_vulnerabilities/cli.py`.
2. Enhance `mcp-vuln identify` and `mcp-vuln probe`:
   - Connect over stdio subprocess or HTTP/SSE JSON-RPC endpoints.
   - Perform protocol handshake (`initialize`, `tools/list`, `prompts/list`, `resources/list`).
   - Extract tool names, parameter schemas, types, and descriptions into normalized `ToolContractSignature` objects.
   - Run topological similarity matching against all 5,533 passports in `passports.json.gz`.
   - Score candidates based on:
     - Tool name exact matches.
     - Parameter structure Jaccard similarity.
     - Type and required field graph alignment.
3. When confidence exceeds the threshold (e.g. $\ge 85\%$), attribute the server to the matched package & version.
4. Immediately correlate the identified version with known OSV CVE/GHSA advisories, displaying active threats and remediation advice.

---

## 2. Target Files & Documentation
- `src/mcp_vulnerabilities/probe/fingerprinter.py`
- `src/mcp_vulnerabilities/probe/client.py`
- `src/mcp_vulnerabilities/cli.py`
- `tests/test_behavioral_topology_prober.py`
- `docs/tasks/README.md`

---

## 3. Super Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Exact Topological Identification Invariant
- **Preconditions**: A custom wrapper `python -m mock_wrapper` exposes the exact tool schemas of `@modelcontextprotocol/server-filesystem@0.6.2` (including `read_file`, `write_file`, `list_directory`).
- **Test Steps**:
  1. Run `mcp-vuln identify --command "python -m mock_wrapper" --correlate`.
- **Invariants**:
  - [x] **INVARIANT_1A (High Confidence Identification)**: The system MUST identify the server as `@modelcontextprotocol/server-filesystem` with confidence $>95\%$.
  - [x] **INVARIANT_1B (Version Precision)**: The identified version MUST match `0.6.2`.
  - [x] **INVARIANT_1C (Vulnerability Correlation)**: The output MUST list CVE-2026-114090 (Directory Traversal) associated with this version.

### Scenario 2: Novel / Proprietary Server Distinction Invariant
- **Preconditions**: An entirely proprietary server exposing unique corporate tools (`query_internal_erp`, `submit_leave_request`) that do not exist in the public passport database.
- **Test Steps**:
  1. Run `mcp-vuln identify --command "python -m proprietary_erp"`.
- **Invariants**:
  - [x] **INVARIANT_2A (No False Positive Attribution)**: Topological confidence for any public package MUST be below the threshold ($<50\%$).
  - [x] **INVARIANT_2B (Classification)**: Classified as `NO_MATCH (CONFIDENCE_TOO_LOW)` or `PROPRIETARY_UNTRACKED_SERVER`.
  - [x] **INVARIANT_2C (Clean Audit)**: No false CVE warnings are emitted.

### Scenario 3: Process Timeout & Deadlock Prevention Invariant
- **Preconditions**: A target process that deadlocks, hangs on stdin, or emits endless stdout noise.
- **Test Steps**:
  1. Run `mcp-vuln identify --command "python -m hanging_process" --timeout 3.0`.
- **Invariants**:
  - [x] **INVARIANT_3A (Enforced Timeout)**: The probing operation MUST terminate strictly within $3.0$ seconds (plus small teardown delta $\le 0.5$s).
  - [x] **INVARIANT_3B (Process Cleanup)**: The deadlocked subprocess MUST be sent SIGTERM/SIGKILL, preventing orphaned zombie processes.
  - [x] **INVARIANT_3C (Informative Error)**: Emits `PROCESS_PROBE_TIMEOUT` with process PID and arguments.

### Scenario 4: Remote HTTP/SSE Probing Invariant
- **Preconditions**: A remote server running on `http://127.0.0.1:8080/sse`.
- **Test Steps**:
  1. Run `mcp-vuln identify --url "http://127.0.0.1:8080/sse" --header "Authorization: Bearer test"`.
- **Invariants**:
  - [x] **INVARIANT_4A**: Negotiates SSE stream and JSON-RPC session over HTTP.
  - [x] **INVARIANT_4B**: Correctly identifies remote endpoint tools and matches against passport database.

---

## 4. Implementation Steps

1. Update `src/mcp_vulnerabilities/probe/fingerprinter.py`:
   - Implement `BehavioralTopologyIdentifier` wrapping `mcp_fingerprints.prober.McpProber` and `distance.py`.
   - Implement `identify_and_correlate(target, min_confidence=0.85)`.
2. Update `src/mcp_vulnerabilities/cli.py`:
   - Enhance `mcp-vuln identify` with `--command`, `--url`, `--min-confidence`, and `--correlate` flags.
   - Connect results directly to `VulnerabilityCorrelator`.
3. Author comprehensive unit and integration tests in `tests/test_behavioral_topology_prober.py`.
4. Verify `pytest -q tests/test_behavioral_topology_prober.py` passes 100%.
