# Task: Wave 23 Track C — Tool Code Review & Resilience Audit (Tasks 130, 131, 132)

## Overview & Mandate
You are assigned **Wave 23 Track C: Exhaustive Tool Code Review & Failure Mode Hardening** for `mcp-vulnerabilities`.
Your task is to conduct an architectural and operational code review and harden the 12 core CLI tools and security engines specified in:
- `docs/tasks/task130_code_review_scanning_probing_tools.md` (`audit`, `network-scan`, `identify`, `probe-safe`)
- `docs/tasks/task131_code_review_defensive_security_engines.md` (`proxy`, `audit-transitive`, `audit-typosquat`, `verify-feed`)
- `docs/tasks/task132_code_review_interactive_daemon_services.md` (`hub`, `tui`, `monitor`, `bridge`)

## Instructions & Deliverables
1. **Line-by-Line Code Review & Failure Mode Analysis**:
   - Audit protocol handling (stdio unbuffered pipes, SSE reconnects, Streamable HTTP).
   - Audit socket and connection lifecycle: ensure connection pools and sockets are closed with deterministic `try...finally` or context managers.
   - Audit timeout traps: ensure all external network requests or child process communications enforce explicit timeouts.
   - Audit signal handling and cleanup in daemons (`monitor`, `bridge`, `hub`, `tui` curses restore on crash).

2. **Code Hardening & Bug Fixes**:
   - Apply robust error handling, graceful fallback for broken pipes (`EPIPE`), connection drops, malformed JSON-RPC frames, and permission denied errors in `src/mcp_vulnerabilities/`.
   - Prevent descriptor leaks and zombie child processes in sandboxed prober and daemon workers.

3. **Code Review Audit Reports**:
   Generate detailed reports under `docs/reports/wave23_audits/`:
   - `docs/reports/wave23_audits/code_review_scanning_tools.md`
   - `docs/reports/wave23_audits/code_review_defensive_engines.md`
   - `docs/reports/wave23_audits/code_review_daemon_services.md`
   Each report must detail:
   - Tool architecture and execution path analysis.
   - Failure mode taxonomy (broken pipes, hanging subprocesses, socket leaks, malformed payloads).
   - Code diffs and resilience improvements implemented.

4. **Automated Regression Tests**:
   - Add targeted resilience tests verifying the hardened error paths (e.g. timeout handling, invalid JSON-RPC schemas, socket close on error).
   - Run `python3 -m pytest tests/ -k "resilience or probe or proxy or daemon" -q` (or relevant tests) and verify clean passes.

## Non-Interactive Completion Directive
Conduct the code reviews, apply all necessary hardening fixes in `src/mcp_vulnerabilities/`, write the 3 code review reports under `docs/reports/wave23_audits/`, verify existing and new tests pass, and commit directly without asking open-ended questions so this session cleanly transitions to `Completed`.
