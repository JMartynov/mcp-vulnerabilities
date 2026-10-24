# Task 52: Supply-Chain Tamper & Shadow Tool Drift Detection (P0)

## 1. Architectural Context & Technical Objective

Standard vulnerability scanners rely exclusively on version strings declared in client configurations (e.g. `@org/mcp-server@1.2.0`). However, software supply chain attacks frequently involve:
1. **Unadvertised / Injected Shadow Tools**: An attacker injects hidden tools (e.g., `execute_system_command`, `exfiltrate_credentials`) into an existing server package without incrementing the version number.
2. **Schema & Parameter Tampering**: Tool parameters are modified to weaken validation, remove required authentication flags, or introduce path traversal vectors.
3. **Registry / Repository Tampering**: An unbumped package version is republished or modified locally.

Because the version number remains unchanged, conventional scanners report the server as safe.

`mcp-fingerprints` computes a cryptographic `toolset_canonical_hash` for every release version, cataloged in 5,533 server passports. By comparing runtime tool definitions against the baseline passport hash, `mcp-vulnerabilities` can detect supply-chain tampering and shadow tool injection with cryptographic certainty.

### Core Objectives:
1. Integrate `mcp_fingerprints.canonicalizer.compute_toolset_canonical_hash` and `mcp_fingerprints.drift_detector.detect_toolset_drift`.
2. Add `--verify-signatures` (and `--strict-integrity`) flags to `mcp-vuln audit` and `mcp-vuln probe`.
3. For each audited server:
   - Extract declared or runtime tool definitions.
   - Compute the live `toolset_canonical_hash`.
   - Retrieve the authoritative passport baseline hash for that pinned version.
   - Detect and classify anomalies:
     - **SHADOW_TOOL_INJECTED**: Extra tools present at runtime that do not exist in the official baseline.
     - **SCHEMA_TAMPERING**: Parameter names, types, or descriptions modified without version increment.
     - **MISSING_CRITICAL_TOOLS**: Tools declared in baseline omitted at runtime.
4. Emit dedicated high-severity alerts in CLI, JSON, and SARIF (`MCP001/supply-chain-tampering`, `MCP002/shadow-tool-injection`).

---

## 2. Target Files & Documentation
- `src/mcp_vulnerabilities/audit/tamper_detector.py` (New module)
- `src/mcp_vulnerabilities/audit/matcher.py`
- `src/mcp_vulnerabilities/audit/reporters.py`
- `src/mcp_vulnerabilities/cli.py`
- `tests/test_supply_chain_tamper_detector.py`
- `docs/tasks/README.md`

---

## 3. Super Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Clean Baseline Signature Verification Invariant
- **Preconditions**: A server pinned to `@modelcontextprotocol/server-filesystem@0.6.2` exposes the exact tool schemas declared in the official passport (`read_file`, `write_file`, `list_directory`, etc.).
- **Test Steps**:
  1. Run `mcp-vuln audit --verify-signatures`.
- **Invariants**:
  - [x] **INVARIANT_1A (Hash Match)**: Computed live hash MUST exactly equal the passport `toolset_canonical_hash`.
  - [x] **INVARIANT_1B (Status Tag)**: The report MUST flag the server as `INTEGRITY_VERIFIED`.
  - [x] **INVARIANT_1C (Exit Code)**: In `--strict-integrity` mode, it MUST exit with code 0 (clean).

### Scenario 2: Shadow Tool Injection Invariant (Critical Attack Scenario)
- **Preconditions**: A malicious actor injects an unadvertised tool `execute_command(cmd: str)` into `@modelcontextprotocol/server-filesystem@0.6.2` while leaving the package version as `0.6.2`.
- **Test Steps**:
  1. Run `mcp-vuln audit --verify-signatures`.
- **Invariants**:
  - [x] **INVARIANT_2A (Tamper Detection)**: The system MUST detect hash mismatch.
  - [x] **INVARIANT_2B (Shadow Tool Attribution)**: The report MUST explicitly name `execute_command` as `[SHADOW_TOOL_INJECTED]`.
  - [x] **INVARIANT_2C (Severity Rating)**: The finding MUST be tagged with `Severity: CRITICAL` / `Threat: Supply-Chain Tampering`.
  - [x] **INVARIANT_2D (Strict Exit Code)**: In `--strict-integrity` mode, it MUST exit with a non-zero exit code (e.g. code 2).

### Scenario 3: Schema Parameter Tampering Invariant
- **Preconditions**: In `@org/sql-server@1.0.0`, a tool `query_db` has its parameter `read_only: bool` altered or removed.
- **Test Steps**:
  1. Run `mcp-vuln audit --verify-signatures`.
- **Invariants**:
  - [x] **INVARIANT_3A (Field Diff)**: The detector MUST output a detailed schema diff highlighting the removed or modified parameter.
  - [x] **INVARIANT_3B (Alert Classification)**: Classified as `SCHEMA_TAMPERING_DETECTED` with High severity.

### Scenario 4: Untracked Server Graceful Handling Invariant
- **Preconditions**: A private proprietary server not present in `mcp-fingerprints` passport catalog.
- **Test Steps**:
  1. Run `mcp-vuln audit --verify-signatures`.
- **Invariants**:
  - [x] **INVARIANT_4A (No False Positive)**: It MUST NOT report tampering for servers without a baseline.
  - [x] **INVARIANT_4B (Status Reporting)**: Tagged as `INTEGRITY_UNKNOWN (NO_PASSPORT_BASELINE)`.

### Scenario 5: SARIF Rule Emittance Invariant
- **Preconditions**: Run audit with `--verify-signatures --format sarif`.
- **Test Steps**:
  1. Inspect generated SARIF report.
- **Invariants**:
  - [x] **INVARIANT_5A**: Emits SARIF rule `MCP001` (`mcp-supply-chain-tampering`) and `MCP002` (`mcp-shadow-tool-injection`).
  - [x] **INVARIANT_5B**: Message includes baseline hash, live hash, and list of anomalous tools.

---

## 4. Implementation Steps

1. Create `src/mcp_vulnerabilities/audit/tamper_detector.py`:
   - Implement `SupplyChainTamperDetector` using `compute_toolset_canonical_hash` and `detect_toolset_drift`.
   - Implement `verify_server_integrity(server_spec, runtime_tools)`.
2. Update `src/mcp_vulnerabilities/cli.py`:
   - Add `--verify-signatures` and `--strict-integrity` flags to `audit` and `probe` commands.
3. Update `src/mcp_vulnerabilities/audit/reporters.py`:
   - Render integrity status badges (`VERIFIED`, `TAMPERED`, `UNKNOWN`) in console tables and JSON.
   - Add SARIF rules for `MCP001` and `MCP002`.
4. Author comprehensive test suite in `tests/test_supply_chain_tamper_detector.py`.
5. Verify `pytest -q tests/test_supply_chain_tamper_detector.py` passes 100%.
