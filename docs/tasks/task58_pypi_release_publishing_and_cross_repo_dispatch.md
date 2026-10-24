# Task 58: PyPI Release Publishing & Upstream Cross-Repo Dispatch Pipeline (P1)

## 1. Architectural Context & Technical Objective

To ensure autonomous end-to-end continuous delivery across the MCP security ecosystem, two release engineering pipelines must be aligned:
1. **PyPI Publishing for `mcp-fingerprints`**:
   - `mcp-fingerprints` now contains `data_loader.py` for multi-tier snapshot loading.
   - An automated release pipeline must build wheels and sdist, upload them to PyPI.org via GitHub Actions OIDC Trusted Publishing, and publish release tags (`v1.0.18+`).
2. **Upstream Cross-Repository Dispatch Triggering**:
   - Whenever `mcp-fingerprints` publishes a new release (or updates `passports.json.gz`), it must dispatch a webhook event (`upstream_fingerprints_updated`) to `mcp-vulnerabilities`.
   - In `mcp-vulnerabilities`, `.github/workflows/cross_repo_sync.yml` must receive this event, download the new snapshot, re-run `site_builder.py` with multi-core acceleration, detect delta changes via `delta_detector.py`, bump version if substantive updates occurred, and automatically publish a release.

### Core Objectives:
1. **In `mcp-fingerprints`**:
   - Verify and harden `.github/workflows/release.yml` with OIDC Trusted Publishing and PyPI environment.
   - Author a release trigger script (`scripts/trigger_pypi_release.py` or GitHub Action) that builds and publishes releases when a `v*` tag is pushed.
2. **In `mcp-vulnerabilities`**:
   - Update `.github/workflows/cross_repo_sync.yml`:
     - Listen to `repository_dispatch` event `types: [upstream_fingerprints_updated]`.
     - Ingest updated `passports.json.gz` via `mcp_fingerprints.data_loader.get_passports_path()`.
     - Rebuild site shards with `--workers 4`.
     - Run `delta_detector.py` to identify newly correlated vulnerabilities or version fixes.
     - If delta detected, automatically bump patch version and dispatch release.
3. Add end-to-end simulation tests verifying the dispatch webhook payload, delta detection gating, and release trigger flow.

---

## 2. Target Files & Documentation
- `.github/workflows/cross_repo_sync.yml`
- `.github/workflows/daily_sync.yml`
- `scripts/trigger_upstream_dispatch.py` (New helper script)
- `tests/test_cross_repo_dispatch_and_release.py`
- `docs/tasks/README.md`

---

## 3. Super Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Repository Dispatch Event Payload Invariant
- **Preconditions**: A mock GitHub `repository_dispatch` event with type `upstream_fingerprints_updated` and client payload `{"upstream_version": "1.0.18", "passports_count": 5690}`.
- **Test Steps**:
  1. Validate workflow YAML against GitHub Actions schema.
  2. Simulate event dispatch ingestion in `cross_repo_sync.yml`.
- **Invariants**:
  - [x] **INVARIANT_1A (Event Binding)**: The workflow MUST bind strictly to `repository_dispatch: types: [upstream_fingerprints_updated]`.
  - [x] **INVARIANT_1B (Payload Extraction)**: Client payload version MUST be extracted and logged into GitHub Step Summary.

### Scenario 2: Delta-Gated Release Bumping Invariant
- **Preconditions**: Ingestion runs after upstream fingerprint update.
- **Test Steps**:
  1. Case A: Upstream fingerprints added 5 new servers, but 0 new CVE correlations were produced.
  2. Case B: Upstream fingerprints updated a server version that matches an active HIGH severity CVE.
- **Invariants**:
  - [x] **INVARIANT_2A (No Spurious Release)**: Case A MUST report `DELTA_DETECTED: false` and MUST NOT bump the package version or publish a redundant PyPI release.
  - [x] **INVARIANT_2B (Automated Version Bump)**: Case B MUST report `DELTA_DETECTED: true`, bump the patch version in `pyproject.toml`, and trigger release publishing.

### Scenario 3: Fallback on API Rate Limit Invariant
- **Preconditions**: GitHub API rate limits exceeded during asset download.
- **Test Steps**:
  1. Simulate HTTP 403 on GitHub release asset endpoint.
- **Invariants**:
  - [x] **INVARIANT_3A (Graceful Raw Fallback)**: Automatically falls back to raw content CDN or cached snapshot without job failure.

---

## 4. Implementation Steps

1. In `.github/workflows/cross_repo_sync.yml`:
   - Add `repository_dispatch` trigger for `upstream_fingerprints_updated`.
   - Update step to invoke `mcp_vulnerabilities.site_builder --workers 4`.
   - Gate release dispatch on `delta_detector.py` output.
2. Create `scripts/trigger_upstream_dispatch.py`:
   - Utility to emit authenticated dispatch events to `mcp-vulnerabilities` from CI runners.
3. Author verification tests in `tests/test_cross_repo_dispatch_and_release.py`.
4. Verify `pytest -q tests/test_cross_repo_dispatch_and_release.py` passes 100%.

## Non-Interactive Completion Directive
Execute this task end-to-end without asking interactive questions. Implement `.github/workflows/cross_repo_sync.yml`, `.github/workflows/daily_sync.yml`, and `scripts/trigger_upstream_dispatch.py`. Add tests in `tests/test_cross_repo_dispatch_and_release.py`, verify that all tests pass (`pytest -q`), and conclude directly with a complete patch so the remote environment cleanly transitions to `Completed`.
