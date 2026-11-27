# Task 170: CI Workflow Hardening, Delta Backup Fix, and Cascading Release Automation

## 1. Objective
Resolve the four CI/CD workflow reliability and release-cascade gaps identified during the 5-day GitHub Actions audit (`2026-11-22` to `2026-11-27`) across `cross_repo_sync.yml`, `daily_sync.yml`, `snapshot_release.yml`, `daily_web_audit.yml`, `docker.yml`, `sign_release.yml`, and `scripts/check_deltas.py`.

## 2. Background & Issues Identified
1. **`cross_repo_sync.yml` False Delta & Unnecessary Daily Version Bumps:**
   - `scripts/check_deltas.py` checks `Path("data/passports_backup.json.gz")` and returns `True` whenever that backup file does not exist (`if not old_passport.exists(): return True`).
   - `cross_repo_sync.yml` never backed up `data/passports.json.gz` to `data/passports_backup.json.gz` before fetching latest passports, and backed up `data/vulnerabilities_backup` only after fetching passports, causing every daily run to trigger a false positive version bump and PyPI release (`v1.7.33`–`v1.7.44`).
   - Temporary backup directories/files (`data/vulnerabilities_backup`, `data/passports_backup.json.gz`) must be cleaned up before `git add data/` so backup artifacts are never staged, and `git push` must use a retry-with-rebase loop instead of `|| echo "Failed to push"`.
2. **Missing Concurrency Coordination & Downstream Release Dispatch (`docker.yml` & `sign_release.yml`):**
   - `daily_sync.yml` and `cross_repo_sync.yml` mutate the same files and tags without sharing a concurrency group.
   - Because tags and GitHub Releases created with `GITHUB_TOKEN` do not trigger `on: push: tags` (`docker.yml`) or `on: release: published` (`sign_release.yml`), neither workflow has executed during automated releases. Both `daily_sync.yml` and `cross_repo_sync.yml` should explicitly trigger `docker.yml` (at `--ref "v${NEW_VERSION}"`) and `sign_release.yml` upon creating a release.
3. **`snapshot_release.yml` CLI Arguments & Checksum Verification:**
   - `export-osv` should explicitly pass `--data-dir data/vulnerabilities --output-dir dist/osv` (consistent with `daily_sync.yml`), ensure `dist/mcp-offline.tar.gz.sha256` exists alongside `dist/SHA256SUMS.txt` before `gh release create`, and set `timeout-minutes: 30`.
4. **Redundant `daily_web_audit.yml` Triggers:**
   - `daily_web_audit.yml` triggers on `schedule`, `workflow_dispatch`, AND `push` (`paths: docs/data/**`), while also being explicitly dispatched via `gh workflow run daily_web_audit.yml` in `daily_sync.yml` and `cross_repo_sync.yml`, causing duplicate back-to-back audit runs on every sync push. Adding a `concurrency` group (`cancel-in-progress: true`) and `timeout-minutes: 20` prevents redundant overlapping audit runs.

## 3. Files to Modify in `JMartynov/mcp-vulnerabilities`

| # | File Path | Required Change |
|:---:|:---|:---|
| 1 | `.github/workflows/cross_repo_sync.yml` | Add shared `concurrency` group (`mcp-vuln-data-sync`, `cancel-in-progress: false`) and `timeout-minutes: 45`. Back up both `data/passports.json.gz` -> `data/passports_backup.json.gz` and `data/vulnerabilities` -> `data/vulnerabilities_backup` **before** fetching latest passports. Clean up `data/vulnerabilities_backup` and `data/passports_backup.json.gz` right after `check_deltas.py`. Replace `git push ... || echo "Failed to push"` with a 5-attempt retry-with-rebase loop. Dispatch `docker.yml --ref "v${NEW_VERSION}"` and `sign_release.yml` on release creation. |
| 2 | `.github/workflows/daily_sync.yml` | Add shared `concurrency` group (`mcp-vuln-data-sync`, `cancel-in-progress: false`). Remove redundant duplicate `site_builder` / `updates_builder` call inside the `commit_push` `else` branch. Dispatch `docker.yml --ref "v${NEW_VERSION}"` and `sign_release.yml` on release creation. |
| 3 | `.github/workflows/snapshot_release.yml` | Add `timeout-minutes: 30`. Pass `--data-dir data/vulnerabilities` to `export-osv`. Ensure `dist/mcp-offline.tar.gz.sha256` is verified/present alongside `dist/SHA256SUMS.txt` before `gh release create`. |
| 4 | `.github/workflows/daily_web_audit.yml` | Add `concurrency` group (`daily-web-audit-${{ github.ref }}`, `cancel-in-progress: true`) and `timeout-minutes: 20` to deduplicate overlapping push + dispatch triggers. |
| 5 | `.github/workflows/docker.yml` & `.github/workflows/sign_release.yml` | Add `timeout-minutes: 30` and ensure `workflow_dispatch` supports clean manual and automated dispatch from release pipelines (`sign_release.yml` also gracefully creating `docs/data/vulnerabilities.json.gz` from `vulnerabilities.json.gz` if `docs/data/vulnerabilities.json` is absent). |
| 6 | `tests/test_ci_workflows.py` *(new)* | Add unit tests validating all workflow YAML files parse cleanly, share expected concurrency/timeout settings, back up and clean up `passports_backup.json.gz` in `cross_repo_sync.yml`, and verify `check_deltas.py` behavior when `passports_backup.json.gz` matches `passports.json.gz`. |

## 4. Acceptance Criteria & Verification Commands
- [x] `uv run pytest tests/test_ci_workflows.py tests/test_e2e_cross_repo_sync.py -v` passes 100% (`37 passed`).
- [x] All modified GitHub Actions workflows trigger and pass on GitHub Actions (`CI`, `Daily Web Card Audit`, `Deploy GitHub Pages`, `Cross-Repo Synchronization`, `Build and Publish Docker Image`, `Sign Release`, `Snapshot Distribution Release`).

## 5. Implementation & CI Verification Status (Completed 2026-11-27)
- **Status:** `Done`
- **GitHub Issue:** [#28](https://github.com/JMartynov/mcp-vulnerabilities/issues/28)
- **Task Board Item:** `PVTI_lAHOD-xmQM4BmPcAzhMXCfc` (`mcp-vulnerabilities Task Board` #4)
- **Implementation Commit:** `a944efc` (`fix(ci): harden workflow concurrency, passport delta backup, and release cascades (Task 170)`)
- **Verified Passing GitHub Actions Runs:**
  - **CI:** Run [`45982907610`](https://github.com/JMartynov/mcp-vulnerabilities/actions/runs/45982907610) — `success` (Python 3.12 & 3.14: `698 passed, 4 skipped`, including `34/34` in `tests/test_ci_workflows.py`)
  - **Test Action:** Run [`45983027339`](https://github.com/JMartynov/mcp-vulnerabilities/actions/runs/45983027339) — `success`
  - **Deploy GitHub Pages:** Runs [`45982907578`](https://github.com/JMartynov/mcp-vulnerabilities/actions/runs/45982907578) & [`45985859127`](https://github.com/JMartynov/mcp-vulnerabilities/actions/runs/45985859127) — `success`
  - **Daily Web Card Audit:** Runs [`45982995314`](https://github.com/JMartynov/mcp-vulnerabilities/actions/runs/45982995314) & [`45985854896`](https://github.com/JMartynov/mcp-vulnerabilities/actions/runs/45985854896) — `success`
  - **Cross-Repo Synchronization:** Run [`45983001123`](https://github.com/JMartynov/mcp-vulnerabilities/actions/runs/45983001123) — `success` (verified `delta_detected=false` with `data/passports_backup.json.gz` properly backed up and cleaned up; no false version bump)
  - **Snapshot Distribution Release:** Run [`45983006738`](https://github.com/JMartynov/mcp-vulnerabilities/actions/runs/45983006738) — `success` (published release [`snapshot-2026.11.27`](https://github.com/JMartynov/mcp-vulnerabilities/releases/tag/snapshot-2026.11.27) with all 6 artifacts including `mcp-offline.tar.gz.sha256` and `SHA256SUMS.txt`)
  - **Build and Publish Docker Image:** Run [`45983013075`](https://github.com/JMartynov/mcp-vulnerabilities/actions/runs/45983013075) — `success`
  - **Sign Release:** Run [`45983021479`](https://github.com/JMartynov/mcp-vulnerabilities/actions/runs/45983021479) — `success`
