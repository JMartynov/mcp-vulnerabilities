# Task: Wave 23 Track D — Acceptance Test Gap Analysis & Chaos Hardening (Tasks 133, 134)

## Overview & Mandate
You are assigned **Wave 23 Track D: Acceptance Test Gap Analysis & Chaos Hardening** for `mcp-vulnerabilities`.
Your task is to identify coverage gaps in the acceptance testing surface and implement robust invariant and chaos suites as specified in:
- `docs/tasks/task133_acceptance_test_gap_analysis_and_invariants.md` (Coverage Gap Analysis Matrix & Invariant Harness)
- `docs/tasks/task134_edge_case_chaos_hardening_test_synthesis.md` (Chaos Hardening & Adversarial Testing)

## Instructions & Deliverables
1. **Gap Analysis & Audit Reports**:
   Generate detailed reports under `docs/reports/wave23_audits/`:
   - `docs/reports/wave23_audits/acceptance_gap_matrix.md`: Exhaustive matrix mapping every CLI subcommand and security engine against existing acceptance tests, identifying gaps (unmocked sockets, bridge CORS validation, reverse proxy frame edge cases, TUI resize handling).
   - `docs/reports/wave23_audits/chaos_hardening_report.md`: Resilience verification report documenting adversarial test results across corrupted snapshots, malformed JSON-RPC frames, dropped TCP handshakes, and concurrent lock contention.

2. **Unified Acceptance Invariants Suite**:
   Author and verify `tests/test_acceptance_invariants.py`:
   - Validates invariants across CLI invocation (help flags, version output, exit code guarantees: 0 for clean, 1 for errors, 2 for vulnerabilities detected, 5 for drift).
   - Validates JSON output schema compliance across all subcommands with `--format json`.
   - Validates config discovery for local AI clients.

3. **Chaos Hardening Test Suite & Adversarial Fixtures**:
   - Create adversarial test fixtures under `tests/fixtures/malformed/` (e.g. truncated JSON, invalid OSV ranges, malformed PURLs, corrupted lockfiles).
   - Author and verify `tests/test_acceptance_chaos_hardening.py` covering:
     - Graceful recovery when reading corrupted `mcp_catalog_state.json` or snapshot files.
     - Malformed JSON-RPC protocol frames sent to proxy or probe.
     - Concurrent access to state files and lockfiles.
     - Unexpected EOF and broken pipe recovery.

4. **Local Verification**:
   - Run `python3 -m pytest tests/test_acceptance_invariants.py tests/test_acceptance_chaos_hardening.py -q` and verify all tests pass.

## Non-Interactive Completion Directive
Execute the gap analysis, create the adversarial fixtures in `tests/fixtures/malformed/`, author and verify both test suites under `tests/`, generate the two reports under `docs/reports/wave23_audits/`, and commit directly without asking open-ended questions so this session cleanly transitions to `Completed`.
