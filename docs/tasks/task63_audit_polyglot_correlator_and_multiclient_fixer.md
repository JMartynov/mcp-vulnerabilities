# Task 63: Empirical Audit — Polyglot Vulnerability Correlator & Native Multi-Client Fixer (P0)

## 1. Architectural Context & Technical Objective

Remediating vulnerable MCP servers across diverse client configurations (`audit/fixer.py`, `fingerprints/correlator.py`) requires multi-ecosystem SemVer evaluation (npm, PyPI, crates.io, Go, Maven, Docker) and atomic file modifications. If an auto-fixer modifies a file without a guaranteed atomic backup, or updates a package to an incompatible or non-existent safe version, user developer configurations can be rendered unparseable or broken.

This task conducts an autonomous, live empirical audit of the multi-client auto-fixer and polyglot correlator across live multi-client config files and simulated disk write failures, verifies invariant compliance, authors `tests/audit/test_audit_task63.py`, and publishes a comprehensive technical report to `docs/audit/audit_task63_polyglot_and_fixer.md` categorizing all findings by **HIGH**, **MEDIUM**, and **LOW** severity.

---

## 2. Target Files & Isolation Boundaries
- Scope: `src/mcp_vulnerabilities/audit/fixer.py`, `src/mcp_vulnerabilities/fingerprints/correlator.py`, `src/mcp_vulnerabilities/audit/matcher.py`
- Test Suite: `tests/audit/test_audit_task63.py`
- Audit Deliverable: `docs/audit/audit_task63_polyglot_and_fixer.md`

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Multi-Client In-Place Config Remediation Invariant
- **Preconditions**: Create vulnerable configurations across Claude Desktop, Cursor, Zed (`context_servers`), Windsurf, and Cline targeting vulnerable npm and PyPI servers.
- **Invariants**:
  - [x] **INVARIANT_1A (Native Schema Preservation)**: Updating Zed `settings.json` must update context server configurations while preserving all user editor preferences and comment formatting.
  - [x] **INVARIANT_1B (Atomic Backup Creation)**: An atomic backup `<config>.bak.<timestamp>` must be created before any bytes are written to the original file.

### Scenario 2: Rollback on Disk Write Failure Invariant
- **Preconditions**: Simulate an OS write failure (e.g. read-only filesystem permission, disk full, or write permission denied) during config remediation.
- **Invariants**:
  - [x] **INVARIANT_2A (Clean Atomic Rollback)**: If writing fails mid-operation, the target configuration file must be restored to its exact original state from the backup.
  - [x] **INVARIANT_2B (Non-Zero Exit & Error Logging)**: The fixer must exit with code `1` and log a descriptive error rather than leaving partially written files.

### Scenario 3: Polyglot Upgrade Target Resolution Invariant
- **Preconditions**: Correlate vulnerabilities across Cargo (Rust), Go, Maven (Java), and Docker Hub container images.
- **Invariants**:
  - [x] **INVARIANT_3A (Monotonic Upgrade Target)**: For all packages with fixes, `recommended_safe_version` must be strictly greater than the vulnerable version (`safe_version > current_version`).
  - [x] **INVARIANT_3B (No-Fix Available Explicit Flag)**: When an active zero-day vulnerability has no safe fixed release, the correlator must flag `no_fix_available: True` and never recommend downgrading or breaking dependencies.

---

## 4. Implementation Steps

1. Author live empirical test suite `tests/audit/test_audit_task63.py` verifying all 3 scenarios and invariants.
2. Run live verification across the fixer and correlator codebase; fix any edge-case failures.
3. Author comprehensive technical report in `docs/audit/audit_task63_polyglot_and_fixer.md` detailing all evaluated invariants, findings graded by HIGH/MEDIUM/LOW, and concrete patch proposals.

## Non-Interactive Completion Directive
Execute this task end-to-end without asking interactive questions. Implement `tests/audit/test_audit_task63.py`, verify that all tests pass (`pytest -q`), generate the complete technical report in `docs/audit/audit_task63_polyglot_and_fixer.md`, and conclude directly with a complete patch so the remote environment cleanly transitions to `Completed`.
