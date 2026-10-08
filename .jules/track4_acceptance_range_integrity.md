### Task: Implement Acceptance Test Suite for Multi-Source Deduplication & OSV 1.6 Range Integrity

#### 1. Context & Contract:
Create a dedicated end-to-end acceptance test file: `tests/test_acceptance_range_integrity.py`.
It must verify that merging heterogeneous vulnerability records with conflicting fix versions always produces 100% compliant OSV 1.6 documents:
1. `test_overlapping_cve_ghsa_conflicting_fixes_produce_valid_ranges()`:
   - Construct two overlapping advisories sharing the same alias:
     - Advisory 1 (CVE): `introduced: "0"`, `fixed: "0.4.0"`
     - Advisory 2 (GHSA): `introduced: "0"`, `fixed: "0.4.1"`
   - Merge them using `OsvDeduplicator.deduplicate_and_merge()`.
   - Assert that `OsvValidator.validate()` returns zero errors.
2. `test_no_adjacent_duplicate_fixed_events()`:
   - Inspect the merged `RangeSpec.events` to guarantee there are never two adjacent `fixed` events without an intervening `introduced` event.
3. `test_highest_cvss_and_epss_preservation()`:
   - Provide differing CVSS scores (e.g. 7.5 vs 8.8) and EPSS scores across sources.
   - Assert that the merged record's `database_specific` preserves the maximum CVSS score, vectors, and EPSS score.

#### 2. Strict Guardrails:
- Must validate directly with `OsvValidator.validate()`.
- All tests must pass with `pytest`.
