### Task: Pull Request Continuous Integration Workflow (ci.yml)

#### 1. Architectural Context & Problem Analysis:
The repository currently maintains only one automated GitHub Actions workflow: `.github/workflows/daily_sync.yml`. This workflow triggers solely on a scheduled cron (`0 3 * * *`) and direct pushes to `main`. 

Consequently, pull requests, feature branches, and external contributions are **completely ungated**:
* Inadvertent syntax errors, breaking schema changes, or invalid OSV 1.6 JSON records can be merged without automated verification.
* Test regressions in converters, deduplicators, or filters remain undetected until the next scheduled daily sync breaks `main`.
* A dedicated, lightweight continuous integration workflow (`.github/workflows/ci.yml`) is necessary to enforce strict quality gates before any branch integrates.

#### 2. Codebase References:
* `.github/workflows/daily_sync.yml`: Baseline for environment setup, caching, and CLI invocation.
* `pyproject.toml`: Build dependencies, test runners, and project metadata.
* `tests/test_acceptance_*.py`: Acceptance test suites to be executed as mandatory quality gates.

#### 3. Engineering & Implementation Blueprint:
1. Author `.github/workflows/ci.yml`:
   * **Triggers**:
     * `pull_request`: targeting branches `[ main ]`.
     * `push`: on branches `[ 'feature/**', 'fix/**', 'jules/**' ]`.
   * **Concurrency**: Cancel in-progress runs for the same branch/PR ref:
     ```yaml
     concurrency:
       group: ${{ github.workflow }}-${{ github.ref }}
       cancel-in-progress: true
     ```
   * **Job Matrix**: Run across supported Python environments (`3.12`, `3.14`).
   * **Execution Pipeline**:
     1. `actions/checkout@v4` with full depth or head ref.
     2. `actions/setup-python@v5` with pip caching.
     3. Dependency installation: `pip install -e ".[dev]"`.
     4. Dataset Integrity Gate: `python -m mcp_vulnerabilities.cli validate --dir data/vulnerabilities`.
     5. Acceptance & Regression Suite: `pytest -v tests/`.
2. Configure branch protection readiness: Ensure step names are deterministic so they can be designated as required status checks in GitHub repository settings.

#### 4. Guardrails & Performance Invariants:
* **Fast Execution**: Must complete within **< 2 minutes** by utilizing pip caching and avoiding unnecessary heavy bulk registry scraping during CI runs.
* **Deterministic Failure**: Any malformed JSON in `data/vulnerabilities/` or single test failure in `pytest` must fail the job with non-zero exit code.
* **Offline Independence**: CI tests must rely on unit mocks or local fixtures, ensuring runner network blips never cause flaky CI failures.

#### 5. Acceptance Criteria & Test Plan:
- [ ] `.github/workflows/ci.yml` is valid YAML and conforms strictly to GitHub Actions schema.
- [ ] Pull requests targeting `main` automatically trigger the CI workflow.
- [ ] Modifying an advisory in `data/vulnerabilities/` with missing required OSV 1.6 fields fails the `cli validate` step.
- [ ] A test failure in `tests/` successfully blocks the CI status check.
- [ ] All 74+ tests pass cleanly on clean branches.
