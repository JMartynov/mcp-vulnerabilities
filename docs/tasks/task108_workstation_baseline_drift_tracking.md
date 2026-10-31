# Task 108: Workstation Baseline Drift Tracking & CI Enforcement (P2)

**Subsystem:** Workstation Security & CI Governance CLI (`src/mcp_vulnerabilities/cli.py`, `src/mcp_vulnerabilities/audit/drift.py`, `tests/test_drift_tracker.py`)  
**Priority:** `P2`  
**Parent Plan:** [master_plan_wave20_mcp_fingerprints_capability_adoption.md](master_plan_wave20_mcp_fingerprints_capability_adoption.md)

---

## 1. Objective & Problem Statement

In enterprise development environments, developers configure multiple AI clients (Claude Desktop, Cursor, VS Code, Zed, Cline, Windsurf) with various MCP servers. Attackers or malicious supply chain packages can stealthily inject "shadow tools", mutate tool parameter schemas to exfiltrate prompt context, or silently swap server packages for compromised forks without changing visible configuration files.

While `mcp_fingerprints.snapshot_diff` provides low-level snapshot comparison algorithms, `mcp-vulnerabilities` lacks a native CLI interface to capture approved workstation baselines and enforce zero-drift gates in CI/CD pipelines.

This task integrates **Workstation Baseline Drift Tracking** directly into `mcp-vuln audit`:
1. `--save-baseline <path>`: Captures the state of all configured clients and global packages into an authenticated baseline inventory snapshot.
2. `--diff <baseline_path>`: Compares the live workstation or repository state against the baseline.
3. `--fail-on-drift`: Enforces strict CI gates, failing with exit code `2` if unauthorized servers, injected tools, schema drift, or fingerprint hash mutations are detected.

---

## 2. Detailed Technical Requirements

### 2.1 CLI Argument Registration (`src/mcp_vulnerabilities/cli.py`)
1. In `src/mcp_vulnerabilities/cli.py`, extend the `audit` parser (`aud_p`):
   ```python
   aud_p.add_argument(
       "--save-baseline",
       metavar="PATH",
       help="Save scanned client server inventory as an approved baseline snapshot file",
   )
   aud_p.add_argument(
       "--diff",
       dest="baseline_diff",
       metavar="PATH",
       help="Path to an approved baseline snapshot JSON file to compare against current state",
   )
   aud_p.add_argument(
       "--fail-on-drift",
       action="store_true",
       help="Exit with non-zero exit code (code 2) if baseline drift is detected",
   )
   ```

### 2.2 Drift Engine Implementation (`src/mcp_vulnerabilities/audit/drift.py`)
1. Create `src/mcp_vulnerabilities/audit/drift.py` integrating with `mcp_fingerprints.snapshot_diff`:
   - Import `InventorySnapshot`, `DiscoveredServer`, `compare_snapshots`, `DiffResult`, `ServerDriftDetail` from `mcp_fingerprints.snapshot_diff`.
   - Implement `build_inventory_snapshot_from_scan(discovered_servers, host_id="local") -> InventorySnapshot`:
     * Converts `DiscoveredClientServer` records from `UniversalClientConfigScanner` and `ConfigScanner` into `DiscoveredServer` objects.
     * Captures `server_name`, `client_name`, `package_name`, `version`, command, args, env keys (masking sensitive values), and cryptographic `toolset_canonical_hash`.
2. Implement Baseline Save (`--save-baseline`):
   - Invokes `snapshot.save(output_path)`.
   - Emits informative terminal confirmation: `✅ Approved baseline snapshot saved to <path> (<N> servers recorded)`.
3. Implement Baseline Diff (`--diff`):
   - Loads baseline snapshot from disk via `InventorySnapshot.load(baseline_path)`.
   - Generates live snapshot from current client scan.
   - Computes `diff_result = compare_snapshots(baseline, current)`.
   - Formats drift report:
     * **Added Servers**: Highlighted in yellow/warning (unauthorized new servers).
     * **Removed Servers**: Highlighted in cyan (missing servers).
     * **Modified Servers (Schema/Hash Drift)**: Highlighted in red/bold:
       - Displays exact changes: added tools, removed tools, parameter type modifications, or canonical hash shifts.
   - If `--json` flag is provided:
     * Output structured JSON:
       ```json
       {
         "has_drift": true,
         "drift_count": 3,
         "added_servers": [...],
         "removed_servers": [...],
         "modified_servers": [
           {
             "server_name": "filesystem",
             "client_name": "claude",
             "old_hash": "a1b2...",
             "new_hash": "c3d4...",
             "changes": ["Tool 'write_file': Parameter 'overwrite' added"]
           }
         ]
       }
       ```
   - Exit code handling:
     * If `--fail-on-drift` is set and `diff_result.has_changes`: exit with code `2`.
     * Otherwise exit with code `0`.

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_108_1 (Baseline Round-Trip Serialization):** Running `mcp-vuln audit --all-clients --save-baseline .mcp-baseline.json` creates a valid JSON file that can be loaded back into `InventorySnapshot` with identical servers and hashes.
- [ ] **INVARIANT_108_2 (Zero Drift on Unmodified Systems):** Running `mcp-vuln audit --all-clients --diff .mcp-baseline.json` immediately after saving the baseline reports `0 drift detected` and exits with code `0`.
- [ ] **INVARIANT_108_3 (Unauthorized Shadow Tool Detection):** Adding an extra tool to a mock server configuration triggers a clear drift alert: `Tool 'shadow_exfil': Tool added` and identifies the modified server.
- [ ] **INVARIANT_108_4 (CI Gate Enforcement via `--fail-on-drift`):** When drift exists and `--fail-on-drift` is enabled, the CLI process terminates with exit code `2`.
- [ ] **INVARIANT_108_5 (JSON Telemetry Parity):** With `--json` supplied, stdout emits parseable JSON matching the `DiffResult` schema.
- [ ] **INVARIANT_108_6 (Automated Test Suite):** `tests/test_drift_tracker.py` covers baseline creation, diffing, parameter mutation detection, and CLI exit codes.

---

## 4. Deliverables

1. `src/mcp_vulnerabilities/cli.py`: Added `--save-baseline`, `--diff`, and `--fail-on-drift` CLI options to the `audit` command.
2. `src/mcp_vulnerabilities/audit/drift.py`: Drift engine integrating with `mcp_fingerprints.snapshot_diff` and formatting table/JSON reports.
3. `tests/test_drift_tracker.py`: Comprehensive test suite verifying drift detection, schema mutation alerts, and CLI exit code contracts.
