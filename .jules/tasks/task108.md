# Task Contract: Task 108 — Workstation Baseline Drift Tracking & CI Enforcement (P2)

### 1. Context & Objective:
Integrate Workstation Baseline Drift Tracking directly into `mcp-vuln audit` to detect shadow tools, altered schemas, or mutated server packages:
1. CLI Arguments in `src/mcp_vulnerabilities/cli.py`:
   - In `audit` subparser (`aud_p`):
     * `--save-baseline PATH`: Save scanned client server inventory as an approved baseline snapshot file.
     * `--diff PATH` (or `--diff-baseline PATH`): Path to approved baseline snapshot JSON file to compare against current state.
     * `--fail-on-drift`: Exit with exit code 2 if baseline drift is detected.
2. Drift Engine Implementation in `src/mcp_vulnerabilities/audit/drift.py`:
   - Integrate with `mcp_fingerprints.snapshot_diff` (import `InventorySnapshot`, `DiscoveredServer`, `compare_snapshots`, `DiffResult`, `ServerDriftDetail` or fallback if missing).
   - Implement `build_inventory_snapshot_from_scan(discovered_servers, host_id="local") -> InventorySnapshot`.
   - Baseline save: serialize inventory snapshot to JSON file at path.
   - Baseline diff: load baseline snapshot, compare against current scan, produce formatted terminal diff report (highlighting added, removed, and modified servers/tools/hashes) and structured JSON when `--json` is supplied.
   - Enforce exit code 2 when `--fail-on-drift` is set and drift is detected; otherwise exit 0.
3. Unit testing:
   - Add `tests/test_drift_tracker.py` testing baseline creation, diffing, schema mutation detection, and exit codes.

### 2. Files to Create/Modify:
- `src/mcp_vulnerabilities/cli.py`
- `src/mcp_vulnerabilities/audit/drift.py`
- `tests/test_drift_tracker.py`

### 3. Strict Guardrails:
- Zero unauthorized external dependencies.
- Verify tests with `pytest tests/test_drift_tracker.py`.

### 4. Defaults when blocked:
- If a rule above cannot be met, leave that part as it was, list it in the summary with the reason, and continue. Do not ask questions.

### 5. Completion Directive:
- Implement all requested changes, verify with unit tests, and finalize your response directly with a concise summary. Do not ask conversational follow-up questions, so the task cleanly transitions to Completed.
