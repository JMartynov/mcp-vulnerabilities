### Task: OSV Batch Version-Scoped Querying & Active Vulnerability Stamping

#### 1. Overview & Context:
When querying OSV.dev batch API (`pipeline.py:570`), the payload currently omits `"version"`, retrieving all historical advisories regardless of whether the installed release is patched. By passing `"version"` and comparing against `RangeSpec`, the pipeline can determine and stamp a `currently_vulnerable: bool` flag directly into each entry in `data/vulnerabilities/index.json`.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/pipeline.py`:
  * Lines 358–365: Candidate batch payload generation.
  * Lines 570–605: `_query_osv_batch()` payload and mapping.
  * Lines 510–528: `index_entries` generation and `index.json` output.
* `src/mcp_vulnerabilities/models.py`: `RangeSpec`, `EventSpec`, `AffectedPackage`.

#### 3. Implementation Details:
1. In `src/mcp_vulnerabilities/pipeline.py`:
   - In `_query_osv_batch()`: Include `"version": p["version"]` in the OSV query dictionary whenever `p.get("version")` is non-empty.
   - Implement `_is_version_vulnerable(version: str, ranges: tuple[RangeSpec, ...]) -> bool`:
     - Compare semver version against `introduced` and `fixed` events.
     - If `version >= introduced` and (`fixed is None` or `version < fixed`), mark as vulnerable.
   - In the search index entry builder (lines 510–528):
     Add `"currently_vulnerable": is_vuln` to each package entry in `index_entries`.
2. Update `data/vulnerabilities/index.json` schema documentation in `docs/SPECIFICATION.md`.

#### 4. Strict Guardrails:
- Handle non-semver strings gracefully (fallback to `True` if undetermined).
- Do not break backward compatibility of `index.json` consumers (keep existing fields intact).

#### 5. Acceptance Criteria & Tests:
- [ ] OSV batch queries include `"version"` when known.
- [ ] `data/vulnerabilities/index.json` contains `currently_vulnerable` boolean for each package.
- [ ] Unit test in `tests/test_osv_pipeline.py` verifies accurate semver range evaluation (`0.3.9` is vulnerable when `fixed: 0.4.0`; `0.4.0` is not vulnerable).
- [ ] All tests pass with `pytest`.
