# Task 166: Cross-Repo CI Delta Detection and Release Trigger Suite

## Objective
Fix critical bugs in `scripts/check_deltas.py` that prevent automated release bumping on upstream changes, extend delta detection to `data/passports.json.gz`, and add comprehensive end-to-end tests for cross-repo synchronization.

## Background & Issues Identified
- `scripts/check_deltas.py` calls `OsvVulnerability.parse_obj(data)`, which fails with an AttributeError because `OsvVulnerability` is a dataclass using `.from_dict(data)`. The generic `except Exception: pass` swallows the failure, causing `check_deltas.py` to always report `delta_detected=false`.
- Delta checking completely ignores `data/passports.json.gz`, meaning new server passports never trigger release version bumps.

## Scope of Changes
1. `scripts/check_deltas.py`:
   - Replace `OsvVulnerability.parse_obj(data)` with `OsvVulnerability.from_dict(data)`.
   - Add passport delta evaluation: compare server count and sha256 checksum of `data/passports.json.gz` against previous baseline, setting `delta_detected=true` if new passports are present.
2. `tests/test_cross_repo_dispatch_and_release.py`:
   - Add test cases testing `scripts/check_deltas.py` with mock old and new vulnerability/passport sets.
3. `.github/workflows/cross_repo_sync.yml`:
   - Ensure delta output keys match between `check_deltas.py` and the workflow step conditions.

## Acceptance Criteria
- `scripts/check_deltas.py` correctly parses OSV advisories and detects added/modified records.
- Passport changes in `data/passports.json.gz` trigger `delta_detected=true`.
- `pytest tests/test_cross_repo_dispatch_and_release.py` passes 100%.
