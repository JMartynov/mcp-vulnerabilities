# Empirical Audit — Polyglot Vulnerability Correlator & Native Multi-Client Fixer

This technical report details the empirical audit of the multi-client auto-fixer (`src/mcp_vulnerabilities/audit/fixer.py`) and polyglot correlator (`src/mcp_vulnerabilities/fingerprints/correlator.py`).

## 1. Findings Overview

### HIGH Severity

**1. H1: Risk of Configuration Data Loss on Write Failure**
- **Description:** Previously, `ClientConfigFixer.fix_config` wrote directly over configuration files and temporarily created files before moving them without robust failure handling. If an OS write failure (e.g., read-only filesystem or out-of-disk-space) occurred mid-operation, the configuration file could be left in an unparseable state.
- **Remediation Implemented:**
  - Enforced an atomic backup creation phase (`<config>.bak.<timestamp>`) prior to any file writes.
  - Placed the patched text write operation and the subsequent `os.replace` within a robust `try...except` block.
  - Reverted to the original configuration from the backup upon exception, unlinked the temporary file, and triggered `sys.exit(1)` to abort gracefully.

### MEDIUM Severity

**2. M1: Potential Version Downgrades During Auto-Fixing**
- **Description:** The `VulnerabilityCorrelator` did not previously check the current installed version when determining a target "safe" version, posing a risk that an automated fix could implicitly downgrade a package or suggest a breaking major version implicitly if it was technically marked as "safe".
- **Remediation Implemented:**
  - Introduced `get_remediation_for_version` in `CorrelatedTimeline` (`src/mcp_vulnerabilities/fingerprints/models.py`).
  - Added constraints to enforce monotonic upgrade targeting (ensuring the `recommended_safe_version` is strictly greater than the `current_version`).
  - Safe versions that are mathematically lower or equal to the current version are rejected.

### LOW Severity

**3. L1: Missing "No Fix Available" Indicator for Zero-Day Threats**
- **Description:** In instances of zero-day vulnerabilities where no safe upstream release exists, the vulnerability engine simply omitted the `safe_version` field. While structurally valid, this lacked an explicit flag.
- **Remediation Implemented:**
  - Implemented the `no_fix_available` boolean property in `CorrelatedTimeline`.
  - Added logic mapping the explicit lack of safe candidate versions to evaluate this property to `True`.

## 2. Invariant Compliance Verification

All invariants were rigorously validated using the test suite `tests/audit/test_audit_task63.py`:

- [x] **INVARIANT_1A (Native Schema Preservation):** Validated that in-place format and user comments are explicitly preserved when updating versions.
- [x] **INVARIANT_1B (Atomic Backup Creation):** Validated that `.bak` files are successfully written with correct timestamping before data mutations.
- [x] **INVARIANT_2A (Clean Atomic Rollback):** Validated through `unittest.mock.patch` simulation of `PermissionError` that files revert entirely to their initial pristine states upon failure.
- [x] **INVARIANT_2B (Non-Zero Exit):** Validated that exceptions result in immediate termination with `code 1`.
- [x] **INVARIANT_3A (Monotonic Upgrade Target):** Evaluated that Rust, Go, and Python parsing strictly guarantees `safe_version > current_version`.
- [x] **INVARIANT_3B (No-Fix Available Explicit Flag):** Validated `no_fix_available` evaluates correctly against zero-day mock datasets.
