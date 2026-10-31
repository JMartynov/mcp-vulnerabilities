# Task: Wave 23 Track E — Documentation Parity & Harmonization (Task 135)

## Overview & Mandate
You are assigned **Wave 23 Track E: Full-Surface Documentation Parity Audit & Specification Harmonization** for `mcp-vulnerabilities`.
Your task is to conduct a complete audit of all documentation files against actual CLI capabilities and establish 100% specification parity as described in:
- `docs/tasks/task135_full_surface_documentation_parity_harmonization.md`

## Instructions & Deliverables
1. **Documentation Updates & Alignment**:
   - Audit and update `README.md`:
     - Document all CLI subcommands (`audit`, `network-scan`, `identify`, `probe-safe`, `proxy`, `audit-transitive`, `audit-typosquat`, `verify-feed`, `hub`, `tui`, `monitor`, `bridge`, `remediate-pr`).
     - Include full flag tables, example commands, exit code definitions (`0`, `1`, `2`, `3`, `5`), and supported environment variables.
   - Audit and update `docs/SPECIFICATION.md`:
     - Define formal JSON schemas for `SecurityPicture`, drift event types, passport data, and proxy audit logs.
   - Audit and update `docs/IMPLEMENTATION.md`:
     - Document runtime architecture of daemons (`monitor`, `bridge`), sandboxed network prober, curses TUI split-pane renderer, and reverse proxy interception.
   - Update `CHANGELOG.md` with Wave 23 audit and verification entries.

2. **Automated Documentation Parity Test**:
   Author and verify `tests/test_documentation_parity.py`:
   - Programmatically inspects `src/mcp_vulnerabilities/cli.py` (or argument parser) to extract all registered subcommands and options.
   - Asserts that every single subcommand is documented in `README.md` and `docs/SPECIFICATION.md`.
   - Asserts that exit codes (`0`, `1`, `2`, `3`, `5`) and key environment variables are documented.

3. **Audit Report**:
   Generate `docs/reports/wave23_audits/documentation_parity_audit.md` detailing:
   - Full surface coverage matrix of all CLI commands, flags, and parameters.
   - Discrepancies identified and harmonized across `README.md`, `docs/SPECIFICATION.md`, `docs/IMPLEMENTATION.md`.
   - Automated parity test results.

4. **Local Verification**:
   - Run `python3 -m pytest tests/test_documentation_parity.py -q` and verify it passes.

## Non-Interactive Completion Directive
Execute the documentation audit, harmonize `README.md`, `docs/SPECIFICATION.md`, `docs/IMPLEMENTATION.md`, and `CHANGELOG.md`, create and verify `tests/test_documentation_parity.py`, write `docs/reports/wave23_audits/documentation_parity_audit.md`, and commit directly without asking open-ended questions so this session cleanly transitions to `Completed`.
