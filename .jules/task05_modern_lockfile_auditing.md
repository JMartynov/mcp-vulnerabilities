### Task: Modern Python Lockfile Auditing (uv.lock, pyproject.toml, poetry.lock)

#### 1. Architectural Context & Problem Analysis:
[`TransitiveDependencyAuditor`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/src/mcp_vulnerabilities/transitive.py) and the CLI command `audit-transitive` provide automated supply-chain security auditing for MCP servers by scanning their bundled dependencies against OSV.

Currently, the auditor only supports:
1. npm `package.json`
2. Legacy Python `requirements.txt`

However, the vast majority of production Model Context Protocol servers are modern Python implementations leveraging:
* `uv` package manager (`uv.lock`) — e.g. Astral `uv` toolchain used across modern AI frameworks.
* PEP 621 standardized `pyproject.toml`.
* Poetry package manager (`poetry.lock`).

Without native support for these modern formats, developers running `python -m mcp_vulnerabilities.cli audit-transitive` on standard MCP repositories encounter file parsing errors or must manually export lockfiles to flat `requirements.txt`.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/transitive.py`:
  * Lines 83–109: `audit_manifest_file()` dispatcher.
  * Lines 111–135: `parse_package_json()` and `parse_requirements_txt()`.
* Root repository files:
  * `uv.lock`: TOML format containing `[[package]]` entries with pinned dependencies.
  * `pyproject.toml`: PEP 621 metadata containing `[project.dependencies]`.
* `src/mcp_vulnerabilities/cli.py`: Lines 69–72 `audit-transitive` command.

#### 3. Engineering & Implementation Blueprint:
1. In `src/mcp_vulnerabilities/transitive.py`, implement native TOML manifest parsers using standard library `tomllib`:
   ```python
   import tomllib

   @classmethod
   def parse_pyproject_toml(cls, path: Path) -> List[tuple[str, Optional[str], str]]:
       data = tomllib.loads(path.read_text(encoding="utf-8"))
       # Parse project.dependencies and optional-dependencies
       ...

   @classmethod
   def parse_uv_lock(cls, path: Path) -> List[tuple[str, Optional[str], str]]:
       data = tomllib.loads(path.read_text(encoding="utf-8"))
       # Parse [[package]] tables extracting name and version
       ...

   @classmethod
   def parse_poetry_lock(cls, path: Path) -> List[tuple[str, Optional[str], str]]:
       data = tomllib.loads(path.read_text(encoding="utf-8"))
       # Parse [[package]] tables extracting name and version
       ...
   ```
2. Update `audit_manifest_file(manifest_path)`:
   - Check `path.name`:
     - If `uv.lock`: invoke `parse_uv_lock(path)`.
     - If `pyproject.toml`: invoke `parse_pyproject_toml(path)`.
     - If `poetry.lock`: invoke `parse_poetry_lock(path)`.
     - If `.toml` (generic): inspect keys for `project` or `package`.

#### 4. Guardrails & Zero-Dependency Invariants:
* **Zero External Dependencies**: Python 3.11+ includes standard library `tomllib`. Never introduce external libraries (`toml`, `tomli`, or `tomlkit`) into runtime dependencies.
* **Version Specifier Cleaning**: Clean version specifiers (e.g. `>=1.2.0`, `~=2.0`, `^1.0`) to extract canonical base version strings for OSV querying.

#### 5. Acceptance Criteria & Test Plan:
- [ ] Running `python -m mcp_vulnerabilities.cli audit-transitive --manifest pyproject.toml` parses direct dependencies.
- [ ] Running `python -m mcp_vulnerabilities.cli audit-transitive --manifest uv.lock` parses 100% of pinned lockfile packages with exact versions.
- [ ] Unit tests in `tests/test_transitive.py` cover `uv.lock`, `pyproject.toml`, and `poetry.lock` fixtures.
- [ ] All tests pass cleanly (`pytest -v`).
