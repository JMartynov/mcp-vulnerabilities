### Task: Modern Python Lockfile Auditing (uv.lock, pyproject.toml, poetry.lock)

#### 1. Overview & Context:
`TransitiveDependencyAuditor` in `src/mcp_vulnerabilities/transitive.py` and the CLI command `audit-transitive` currently only support npm `package.json` and basic `requirements.txt`. The majority of modern Python MCP servers use `uv.lock`, PEP 621 `pyproject.toml`, and `poetry.lock`. We need to add first-class parsing for these modern Python manifest formats.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/transitive.py`:
  * Lines 83–109: `audit_manifest_file()` dispatcher.
  * Lines 111–135: `parse_package_json()` and `parse_requirements_txt()`.
* Root repository examples:
  * `uv.lock` (TOML format with `[[package]]` entries).
  * `pyproject.toml` (PEP 621 `project.dependencies`).

#### 3. Implementation Details:
1. In `src/mcp_vulnerabilities/transitive.py`:
   - Use Python's built-in `tomllib` (standard library in Python 3.11+).
   - Implement `parse_pyproject_toml(path: Path) -> List[tuple[str, Optional[str], str]]`:
     - Reads `project.dependencies` and `project.optional-dependencies`.
     - Extracts package name and pinned version/specifier.
   - Implement `parse_uv_lock(path: Path) -> List[tuple[str, Optional[str], str]]`:
     - Reads `[[package]]` tables.
     - Extracts `name` and `version` (ecosystem: `"PyPI"`).
   - Implement `parse_poetry_lock(path: Path) -> List[tuple[str, Optional[str], str]]`:
     - Reads `[[package]]` entries in poetry lock format.
   - Update `audit_manifest_file()`:
     - Check file name: if `path.name == "uv.lock"`, use `parse_uv_lock`.
     - If `path.name == "pyproject.toml"`, use `parse_pyproject_toml`.
     - If `path.name == "poetry.lock"`, use `parse_poetry_lock`.

#### 4. Strict Guardrails:
- Zero new external dependencies: use standard library `tomllib`.
- Clean error reporting if a manifest is malformed.

#### 5. Acceptance Criteria & Tests:
- [ ] `python -m mcp_vulnerabilities.cli audit-transitive --manifest pyproject.toml` parses dependencies.
- [ ] `python -m mcp_vulnerabilities.cli audit-transitive --manifest uv.lock` parses all locked packages with exact versions.
- [ ] Unit tests in `tests/test_transitive.py` cover `uv.lock` and `pyproject.toml` parsing with mock fixtures.
- [ ] All tests pass with `pytest`.
