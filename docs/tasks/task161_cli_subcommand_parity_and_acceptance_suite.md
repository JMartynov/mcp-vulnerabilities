# Task 161: CLI Subcommand Tree Parity and Acceptance Invariant Suite

## Status: IN PROGRESS
**Priority:** P1  
**Components:** CLI Parser, Subcommand Handlers, Acceptance Tests  
**Target Files:**
- `src/mcp_vulnerabilities/cli.py`
- `tests/test_acceptance_invariants.py`
- `tests/test_acceptance_universal_clients.py`

---

## 1. Objectives & Scope

1. **Complete Subcommand Registration:**
   - Expose `network-scan`, `tui`, `monitor`, and `bridge` subcommands directly in `src/mcp_vulnerabilities/cli.py:create_parser()`.
   - Wire their respective arguments (`--port`, `--timeout`, `--interface`, `--format`, `--daemon`) to their underlying engine entrypoints.
2. **Acceptance Invariants Harmonization:**
   - Un-skip and assert all CLI invariant tests in `tests/test_acceptance_invariants.py`.
   - Guarantee `--help` returns exit code 0 and `--format json` outputs valid schema JSON for all subcommands.
3. **Universal 17-Client Mock Discovery Suite:**
   - Expand `tests/test_acceptance_universal_clients.py` to assert discovery across all 17 documented AI clients.

---

## 2. Acceptance Criteria

- [ ] All 13 CLI subcommands appear in `mcp-vuln --help` with exit code 0.
- [ ] `tests/test_acceptance_invariants.py` passes 100% with 0 skipped tests.
- [ ] `tests/test_acceptance_universal_clients.py` covers all 17 clients.
