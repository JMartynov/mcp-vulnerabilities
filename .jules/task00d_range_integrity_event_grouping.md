### Task: OSV 1.6 Range Integrity & Deduplicator Event Grouping (Foundational 00-D)

#### 1. Architectural Context & Purpose:
The Open Source Vulnerability (OSV) v1.6 specification requires that `ranges` specify affected versions as ordered pairs of events: typically an `introduced` event followed by a `fixed` or `limit` event within a single `RangeSpec`. When merging advisories originating from different sources (e.g., GitHub GHSA vs CVEListV5 vs OSV.dev), the deduplicator previously combined events into arbitrary sequences, sometimes emitting adjacent `fixed` events without corresponding `introduced` versions or mixing `SEMVER` and `ECOSYSTEM` types within the same range block.
This violated OSV schema validation and caused client-side version evaluators to miscalculate vulnerable boundaries.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/deduplicator.py`: Methods `merge_records()` and `_normalize_ranges()`.
* `src/mcp_vulnerabilities/models.py`: Dataclasses `RangeSpec` and `EventSpec`.
* `src/mcp_vulnerabilities/validator.py`: Schema conformance checks.
* `tests/test_acceptance_range_integrity.py`: Acceptance test suite testing range merging and event integrity.

#### 3. Engineering & Implementation Blueprint:
1. **Event Grouping by `(type, repo)`**:
   - In `_normalize_ranges()`, group incoming events by range type (`SEMVER`, `ECOSYSTEM`, `GIT`) and repository URL.
2. **Deterministic Event Pairing**:
   - For each group, sort events chronologically / by version.
   - Enforce that every `fixed` event is preceded by an `introduced` event (defaulting to `introduced: "0"` if absent).
   - De-duplicate redundant `fixed` versions, preserving the earliest applicable fix version.
3. **OSV 1.6 Schema Conformance**:
   - Verify that output ranges pass standard `OsvValidator.validate_record()`.

#### 4. Guardrails & Security Invariants:
* **No Dangling Fix Events**: A range must never begin with a `fixed` event without an initial `introduced` boundary.
* **Type Isolation**: Never merge `GIT` commit ranges with `SEMVER` package ranges into the same `RangeSpec`.

#### 5. Acceptance Criteria:
- [x] Deduplicator groups events by `(type, repo)` into discrete `RangeSpec` objects.
- [x] Dangling `fixed` events without preceding `introduced` boundaries are normalized with `introduced: "0"`.
- [x] Merged ranges pass strict OSV 1.6 schema validation.
- [x] Acceptance tests in `tests/test_acceptance_range_integrity.py` pass with 100% assertions satisfied.
