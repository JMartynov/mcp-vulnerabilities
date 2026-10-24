# Task 64: Empirical Audit — Interactive Terminal Security Hub Robustness (P0)

## 1. Architectural Context & Technical Objective

The interactive terminal security hub (`hub.py`, `cli.py`) provides human security operators with real-time vulnerability inspection, diff previews, and selective autofixing across all 9 supported AI client configuration formats. If the hub fails to detect non-TTY environments (such as CI/CD pipelines or piped shell commands), crashes on abrupt terminal resize or SIGINT, or prints unsanitized ANSI escape characters from remote vulnerability advisories, it can corrupt terminal state or introduce terminal escape injection vulnerabilities.

This task conducts an autonomous, live empirical audit of the terminal hub across TTY/non-TTY modes, signal handling, escape sequence sanitization, and diff preview workflows, authors `tests/audit/test_audit_task64.py`, and publishes a comprehensive technical report to `docs/audit/audit_task64_interactive_hub_robustness.md` categorizing all findings by **HIGH**, **MEDIUM**, and **LOW** severity.

---

## 2. Target Files & Isolation Boundaries
- Scope: `src/mcp_vulnerabilities/audit/hub.py`, `src/mcp_vulnerabilities/cli.py`
- Test Suite: `tests/audit/test_audit_task64.py`
- Audit Deliverable: `docs/audit/audit_task64_interactive_hub_robustness.md`

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Non-TTY & Pipeline Graceful Fallback Invariant
- **Preconditions**: Execute `mcp-vulnerabilities hub` with standard input redirected from a pipe (`cat <file> | ...`) or `sys.stdin.isatty() == False`.
- **Invariants**:
  - [x] **INVARIANT_1A (Non-Interactive TTY Fallback)**: If running in a non-TTY environment, the command must never invoke curses or interactive termios ioctls; it must fall back cleanly to table or batch reporting without crash.
  - [x] **INVARIANT_1B (Automated Flag Compatibility)**: Passing `--json` or `--batch` produces valid JSON/machine-readable output with exit code 0 when vulnerabilities are reported.

### Scenario 2: Diff Preview & Multi-Client Selection Invariant
- **Preconditions**: Mock multiple client configurations with pending security upgrades across Claude, Cursor, and Windsurf.
- **Invariants**:
  - [x] **INVARIANT_2A (Unified Diff Integrity)**: The hub must generate accurate, readable unified diffs comparing original and modified configuration files prior to applying fixes.
  - [x] **INVARIANT_2B (Atomic Multi-Client State Machine)**: Selecting or deselecting specific client targets must mutate only the selected files upon commit, leaving non-selected configs strictly untouched.

### Scenario 3: Terminal State Restoration & ANSI Sanitization Invariant
- **Preconditions**: Deliver a simulated `SIGINT` (Ctrl+C) mid-interaction; render vulnerability advisories containing injected ANSI escape codes (e.g. `\x1b[2J`, cursor repositioning, or OSC title injection).
- **Invariants**:
  - [x] **INVARIANT_3A (Terminal Restoration on SIGINT)**: Terminal state (echo, cursor visibility, alternative screen buffer) must be unconditionally restored upon SIGINT or unhandled exception.
  - [x] **INVARIANT_3B (ANSI Injection Sanitization)**: Advisory strings, CVE summaries, and package names containing terminal escape sequences must be stripped or escaped before being written to stdout.

---

## 4. Implementation Steps

1. Author live empirical test suite `tests/audit/test_audit_task64.py` verifying all 3 scenarios and invariants.
2. Run live verification across `hub.py` and `cli.py`; fix any edge-case failures.
3. Author comprehensive technical report in `docs/audit/audit_task64_interactive_hub_robustness.md` detailing all evaluated invariants, findings graded by HIGH/MEDIUM/LOW, and concrete patch proposals.

## Non-Interactive Completion Directive
Execute this task end-to-end without asking interactive questions. Implement `tests/audit/test_audit_task64.py`, verify that all tests pass (`pytest -q`), generate the complete technical report in `docs/audit/audit_task64_interactive_hub_robustness.md`, and conclude directly with a complete patch so the remote environment cleanly transitions to `Completed`.
