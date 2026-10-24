# Task 62: Empirical Audit — Dynamic Behavioral Topology Server Prober & Transports (P0)

## 1. Architectural Context & Technical Objective

When an AI client configuration runs wrapped scripts or custom executables (e.g. `python -m my_corp_wrapper` or `node /opt/custom/server.js`), static CLI parsing cannot determine the package name or version. The prober subsystem (`probe/client.py`, `probe/transport.py`, `probe/fingerprinter.py`) dynamically spawns the process over STDIO or connects via SSE, issues MCP initialization requests, retrieves the live tool schemas, and computes topological Jaccard similarity against the 5,533 server passports to unmask hidden CVEs.

In real-world deployment, servers emit non-JSON stdout debug lines, crash abruptly, hang on stdin read, or close SSE connections unexpectedly.

This task conducts an autonomous, live empirical audit of the dynamic probing engine under real subprocess transports and network failures, verifies invariant compliance, authors `tests/audit/test_audit_task62.py`, and publishes a comprehensive technical report to `docs/audit/audit_task62_behavioral_topology_prober.md` categorizing all findings by **HIGH**, **MEDIUM**, and **LOW** severity.

---

## 2. Target Files & Isolation Boundaries
- Scope: `src/mcp_vulnerabilities/probe/client.py`, `src/mcp_vulnerabilities/probe/transport.py`, `src/mcp_vulnerabilities/probe/fingerprinter.py`, `src/mcp_vulnerabilities/fingerprints/matcher.py`
- Test Suite: `tests/audit/test_audit_task62.py`
- Audit Deliverable: `docs/audit/audit_task62_behavioral_topology_prober.md`

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Subprocess STDIO Transport Noise Filtering Invariant
- **Preconditions**: Probe a live subprocess that prints noisy log lines to stdout (e.g. `INFO:root:Starting server...`, `Debug warning 123`) before responding with valid JSON-RPC 2.0 messages.
- **Invariants**:
  - [x] **INVARIANT_1A (Noise Immunity)**: The STDIO transport must cleanly ignore non-JSON prefix noise and deserialize valid JSON-RPC frames without crashing.
  - [x] **INVARIANT_1B (Timeout & Process Teardown)**: Unresponsive child processes must be terminated via SIGTERM/SIGKILL after timeout without leaving zombie processes.

### Scenario 2: Network SSE Transport Resilience Invariant
- **Preconditions**: Probe local SSE servers with simulated network disruptions: drop connection mid-stream, emit malformed chunked encoding, or return HTTP 502/504 errors.
- **Invariants**:
  - [x] **INVARIANT_2A (Clean Disconnect Handling)**: Broken SSE connections must cleanly close socket file descriptors without leaking threads or memory.
  - [x] **INVARIANT_2B (Explicit Transport Errors)**: Prober must return structured diagnostics (e.g. `TransportError: Connection closed prematurely`) rather than unhandled Python exceptions.

### Scenario 3: Topological Similarity & Version Distance Invariant
- **Preconditions**: Probe an unlabelled server whose toolset is identical to a known server with 98% topological similarity, but with 1 newly added tool.
- **Invariants**:
  - [x] **INVARIANT_3A (Topological Match Precision)**: Must identify the correct candidate package and report match confidence >= 95%.
  - [x] **INVARIANT_3B (Vulnerability Correlation Stamping)**: Must cross-reference the matched server passport against OSV advisories and stamp all applicable CVE IDs.

---

## 4. Implementation Steps

1. Author live empirical test suite `tests/audit/test_audit_task62.py` verifying all 3 scenarios and invariants.
2. Run live verification across the prober codebase; fix any edge-case failures.
3. Author comprehensive technical report in `docs/audit/audit_task62_behavioral_topology_prober.md` detailing all evaluated invariants, findings graded by HIGH/MEDIUM/LOW, and concrete patch proposals.

## Non-Interactive Completion Directive
Execute this task end-to-end without asking interactive questions. Implement `tests/audit/test_audit_task62.py`, verify that all tests pass (`pytest -q`), generate the complete technical report in `docs/audit/audit_task62_behavioral_topology_prober.md`, and conclude directly with a complete patch so the remote environment cleanly transitions to `Completed`.
