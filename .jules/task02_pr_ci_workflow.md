### Task: Pull Request Continuous Integration Workflow (ci.yml)

#### 1. Overview & Context:
Currently, `.github/workflows/daily_sync.yml` only runs on daily schedule (03:00 UTC) and direct pushes to `main`. Pull requests and feature branches lack automated regression testing. We need a fast, isolated GitHub Actions CI workflow to validate schemas and run the full test suite on PRs before merging.

#### 2. Codebase References:
* `.github/workflows/daily_sync.yml`: Existing workflow step references.
* `pyproject.toml`: Build dependencies and test requirements.
* `tests/test_acceptance_*.py`: Acceptance test suite to be executed on CI.

#### 3. Implementation Details:
1. Create `.github/workflows/ci.yml`:
   - Trigger on: `pull_request` against `main`, and `push` to branches.
   - Job matrix: Python 3.12 (and optional 3.13).
   - Execution Steps:
     a) Checkout code with `actions/checkout@v4`.
     b) Setup Python with `actions/setup-python@v5` and pip caching.
     c) Install dependencies: `pip install -e ".[dev]"`.
     d) Validate OSV dataset schemas: `python -m mcp_vulnerabilities.cli validate --dir data/vulnerabilities`.
     e) Execute test suite: `pytest -v`.
2. Ensure proper concurrency cancellation:
   ```yaml
   concurrency:
     group: ${{ github.workflow }}-${{ github.ref }}
     cancel-in-progress: true
   ```

#### 4. Strict Guardrails:
- Must execute quickly ($<2$ minutes).
- Must fail the check if any OSV JSON file in `data/vulnerabilities` violates the OSV 1.6.0 schema.
- Must fail the check if any pytest test fails.

#### 5. Acceptance Criteria:
- [ ] `.github/workflows/ci.yml` is syntactically valid YAML and conforms to GitHub Actions schema.
- [ ] PR checks trigger automatically when branches are pushed.
- [ ] Schema validation and all 74+ tests run and must pass for green CI status.
