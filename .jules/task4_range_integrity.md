### Task: Implement OSV 1.6 Range Integrity & Grouped Event Ordering in Deduplicator

#### 1. Context & Contract:
In `src/mcp_vulnerabilities/deduplicator.py`:
1. In `_merge_affected_packages()`:
   - When merging `events_set`, do not emit duplicate adjacent `fixed` events without an intervening `introduced` event in a SEMVER range.
   - Group events into valid OSV 1.6 pairs or distinct `RangeSpec` entries if multiple introduced/fixed ranges exist.
   - Ensure `RangeSpec.events` strictly satisfies OSV 1.6 specification rules (an `introduced` event must precede any `fixed` or `last_affected` event).
2. Ensure database-specific merging preserves highest CVSS/EPSS scores and unions CWEs/vulnerable tools.

#### 2. Strict Guardrails:
- Must produce documents that strictly pass `OsvValidator.validate()`.
- Zero new external dependencies.

#### 3. Testing:
- Add tests in `tests/test_osv_validator.py` or `tests/test_osv_template_conformance.py` asserting that deduplication of records with conflicting fix versions produces valid OSV 1.6 ranges passing `OsvValidator.validate()`.
- All tests must pass with `pytest`.
