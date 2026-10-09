### Task: Reusable GitHub Action for CI/CD Pipeline Scanning (action.yml)

#### 1. Architectural Context & Purpose:
Organizations and developers adopting Model Context Protocol (MCP) servers in their projects need an effortless way to prevent vulnerable MCP server dependencies from entering production or being configured into AI client settings.
Creating an official, reusable GitHub Action defined in `action.yml` allows repository owners to add a 4-line security gate to their CI workflows:
```yaml
- name: Audit MCP Servers
  uses: JMartynov/mcp-vulnerabilities@v1
  with:
    config-path: ".claude/claude_desktop_config.json"
    fail-on-severity: "HIGH"
```
This turns `mcp-vulnerabilities` into a turnkey DevSecOps scanning tool for the entire AI and agentic developer ecosystem.

#### 2. Codebase References:
* `action.yml`: Target GitHub Action definition file at repository root.
* `src/mcp_vulnerabilities/cli.py`: CLI invocation target.
* `README.md`: Public developer documentation.
* `.github/workflows/test_action.yml`: Smoke test workflow verifying the action.

#### 3. Engineering & Implementation Blueprint:
1. **Create Root `action.yml`**:
   - Define composite action metadata:
     - `name`: "Audit MCP Vulnerabilities"
     - `description`: "Scan AI client configurations (Claude Desktop, Cursor) or lockfiles (package.json, uv.lock, requirements.txt) against the curated MCP vulnerability database."
     - `inputs`:
       - `config-path`: Path to client config file (optional).
       - `manifest-path`: Path to dependency manifest or lockfile (optional).
       - `fail-on-severity`: Minimum severity to fail the build (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`, default: `HIGH`).
       - `format`: Output format (`table` or `json`, default: `table`).
       - `python-version`: Python version to execute with (default: `3.12`).
     - `outputs`:
       - `findings-count`: Total number of vulnerabilities detected.
       - `has-critical-or-high`: Boolean string indicating if high/critical issues exist.
   - `runs`: Using composite steps:
     - Set up Python.
     - Install `mcp-vulnerabilities` from source or pip.
     - Run `mcp-vuln audit` or `mcp-vuln audit-transitive` with configured arguments.
     - Export step summary to `$GITHUB_STEP_SUMMARY` for rich PR annotations.
2. **Create Test Workflow `.github/workflows/test_action.yml`**:
   - Runs on PRs touching `action.yml` or core audit logic.
   - Tests both passing clean configs and failing vulnerable configs.
3. **Documentation**:
   - Document usage examples in `README.md` under "CI/CD Integration".

#### 4. Guardrails & Security Invariants:
* **Pin Safe Actions**: The composite action must use pinned official actions (e.g. `actions/setup-python@v5`).
* **Non-Zero Exit Gating**: If vulnerabilities meet or exceed `fail-on-severity`, the action must cleanly exit with non-zero code to block PR merges.

#### 5. Acceptance Criteria:
- [ ] `action.yml` is created at root and adheres to GitHub Actions composite specification.
- [ ] Supports both `config-path` and `manifest-path` input modes.
- [ ] Generates rich markdown annotations in `$GITHUB_STEP_SUMMARY`.
- [ ] Accurately fails or passes based on `fail-on-severity` threshold.
- [ ] Automated smoke test workflow `.github/workflows/test_action.yml` verifies action execution in CI.
