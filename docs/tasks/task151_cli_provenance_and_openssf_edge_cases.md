# Task 151: CLI Provenance URL Tuple Resolution & OpenSSF None-Ecosystem Hardening (P1)

**Target Wave:** Wave 28 (Runtime Edge Cases & CLI Resilience)  
**Priority:** `P1` (High - Fixes runtime unhandled exceptions in `mcp-vuln search` and `mcp-vuln hub`)  
**Status:** `Done`  

---

## 1. Architectural Context & Technical Objective

During end-to-end CLI workflow testing on live configurations, two runtime exceptions were identified in core subcommands:

1. **`TypeError` in `src/mcp_vulnerabilities/provenance.py`**:
   - `resolve_provenance_urls(advisory_id, aliases)` performs `all_ids = [advisory_id] + aliases`.
   - When OSV advisory models pass `aliases` as a `tuple` (or `None`), list concatenation fails with:
     ```text
     TypeError: can only concatenate list (not "tuple") to list
     ```
   - This causes `mcp-vuln search` to crash whenever an advisory contains alias tuples.

2. **`AttributeError` in `src/mcp_vulnerabilities/threat_intel/openssf_malicious.py`**:
   - `get_malicious_record(self, ecosystem, package_name, version=None)` executes:
     ```python
     key = f"{ecosystem.lower()}::{package_name}"
     ```
   - Discovered client servers without an explicitly resolved ecosystem provide `ecosystem=None`, triggering:
     ```text
     AttributeError: 'NoneType' object has no attribute 'lower'
     ```
   - This causes `mcp-vuln hub --json` and client audits to fail when encountering generic unpinned stdio servers.

The objective of Task 151 is to resolve both edge cases with defensive type normalization and add unit tests to ensure regressions never recur.

---

## 2. Invariant Specifications

- **INVARIANT_151_1 (Provenance Tuple & None Safety)**:
  `resolve_provenance_urls` must accept `aliases` as `list[str]`, `tuple[str, ...]`, `None`, or any iterable of strings, safely converting them to a list without raising `TypeError`.
- **INVARIANT_151_2 (OpenSSF None Ecosystem Safety)**:
  `get_malicious_record` in `OpenSSFMaliciousSync` must safely handle `ecosystem=None` or empty string without raising `AttributeError`, returning `None` immediately if `ecosystem` or `package_name` is missing or falsy.
- **INVARIANT_151_3 (CLI End-to-End Resilience)**:
  Both `mcp-vuln search <query>` and `mcp-vuln hub --json` must complete execution without crashing when processing records with alias tuples or servers with unspecified ecosystems.
- **INVARIANT_151_4 (Automated Test Coverage)**:
  Unit tests must be added to `tests/test_provenance.py` and `tests/test_openssf_malicious_packages.py` covering all edge-case type variants.

---

## 3. Target Files & Isolation Boundaries

- **Files to Modify:**
  - `src/mcp_vulnerabilities/provenance.py`
  - `src/mcp_vulnerabilities/threat_intel/openssf_malicious.py`
  - `tests/test_provenance.py` (or new test cases in `tests/test_openssf_malicious_packages.py`)
  - `docs/tasks/README.md`
- **Boundaries:**
  - Preserve all existing interfaces and signatures.
  - Do not alter unaffected commands or data models.
