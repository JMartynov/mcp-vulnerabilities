### Task: OSV Batch Version-Scoped Querying & Active Vulnerability Stamping

#### 1. Architectural Context & Problem Analysis:
When the vulnerability ingestion pipeline queries the OSV.dev batch API (`pipeline.py:570`), the payload currently omits `"version"`:
```json
{"package": {"name": "fastmcp", "ecosystem": "PyPI"}}
```
While OSV correctly returns all historical security advisories associated with `fastmcp`, downstream consumers (AI security firewalls, agent sandboxes, and developers auditing `data/vulnerabilities/index.json`) cannot determine whether the currently deployed version of the server is **actively vulnerable** or **already patched** without executing client-side range calculations.

By:
1. Passing `"version"` in the OSV query payload when known, and
2. Evaluating `AffectedPackage.ranges` against the server's version at index compilation time,
the pipeline can stamp a deterministic `currently_vulnerable: bool` flag directly into each package record in [`data/vulnerabilities/index.json`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/data/vulnerabilities/index.json).

#### 2. Codebase References:
* `src/mcp_vulnerabilities/pipeline.py`:
  * Lines 358–365: Candidate batch payload generation.
  * Lines 570–605: `_query_osv_batch()` implementation.
  * Lines 510–528: Search index compilation (`index_entries`).
* `src/mcp_vulnerabilities/models.py`: `RangeSpec`, `EventSpec`, `AffectedPackage`.
* `data/vulnerabilities/index.json`: Output index schema.

#### 3. Engineering & Implementation Blueprint:
1. In `src/mcp_vulnerabilities/pipeline.py` (`_query_osv_batch`):
   - Include `"version"` in the OSV payload whenever `item.get("version")` is non-empty:
     ```python
     q = {"package": {"name": p["name"], "ecosystem": p["ecosystem"]}}
     if p.get("version"):
         q["version"] = p["version"]
     ```
2. Implement semver range evaluator in `src/mcp_vulnerabilities/pipeline.py` (or `models.py`):
   ```python
   def is_version_affected(version_str: str | None, ranges: tuple[RangeSpec, ...]) -> bool:
       if not version_str:
           return True  # Conservatively mark vulnerable if version unknown
       # Parse version and evaluate introduced/fixed event boundaries
       ...
   ```
3. Update `index_entries` generation in `pipeline.py`:
   ```python
   pkgs = [
       {
           "name": aff.package.name,
           "ecosystem": aff.package.ecosystem,
           "purl": aff.package.purl,
           "severity": aff.database_specific.severity,
           "cvss_score": aff.database_specific.cvss_score,
           "currently_vulnerable": is_version_affected(candidate_version, aff.ranges),
       }
       for aff in record.affected
   ]
   ```
4. Update `docs/SPECIFICATION.md` documenting the new `currently_vulnerable` field in the index schema.

#### 4. Guardrails & Backward Compatibility:
* **Schema Non-Breaking**: Adding `currently_vulnerable` to `index.json` is purely additive; existing fields (`id`, `summary`, `aliases`, `packages`) remain untouched.
* **Conservative Fallback**: If an installed version string cannot be parsed as valid semver, default to `currently_vulnerable: True` to prevent false negatives.

#### 5. Acceptance Criteria & Test Plan:
- [ ] OSV batch queries include `"version"` when known.
- [ ] `data/vulnerabilities/index.json` entries include `currently_vulnerable: true/false` for each package.
- [ ] Unit test in `tests/test_osv_pipeline.py` verifies:
  * Version `0.3.9` with range `introduced: "0", fixed: "0.4.0"` evaluates to `currently_vulnerable: True`.
  * Version `0.4.0` with the same range evaluates to `currently_vulnerable: False`.
  * Unknown/empty version evaluates to `currently_vulnerable: True`.
- [ ] 100% of existing tests pass (`pytest -v`).
