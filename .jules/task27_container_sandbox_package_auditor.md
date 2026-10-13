# Task 27 Contract: Isolated Ephemeral Container Sandbox for Dynamic Package Auditing

## Objective
Implement an isolated, ephemeral container sandbox engine (`mcp-vuln sandbox`) that allows security teams to safely download, install, and dynamically probe untrusted PyPI and npm MCP packages inside locked-down, disposable Docker or Podman containers. The sandbox captures live tool definitions and handshake metadata without risking the host development workstation.

---

## Detailed Technical Architecture & Implementation

### 1. Subsystem Location: `src/mcp_vulnerabilities/sandbox/`
Create package `src/mcp_vulnerabilities/sandbox/` with:
- `engine.py`:
  - `ContainerEngine`: Detects installed container runtimes (`docker` or `podman`) via standard subprocess discovery. Reports availability, version, and daemon status.
- `runner.py`:
  - `EphemeralSandbox`:
    - Generates disposable container instances with strict defensive hardening:
      - Memory cap (`--memory 512m`) and CPU quota (`--cpus 1.0`).
      - Process isolation (`--pids-limit 100`).
      - Dropped capabilities (`--cap-drop ALL`, `--security-opt no-new-privileges`).
      - Ephemeral execution (`--rm` ensuring immediate deletion on termination).
      - Strict timeout enforcement (default: 60s, configurable via `--timeout`).
    - Multi-ecosystem base images:
      - Python/PyPI: `python:3.12-slim`
      - Node/npm: `node:20-alpine`
    - Lifecycle execution:
      1. Initializes container with working directory in a temporary mount.
      2. Performs non-root package installation (`pip install --no-cache-dir <package>` or `npm install --no-audit <package>`).
      3. Automatically discovers package binary/entrypoint via `entry_points.txt` or `package.json#bin`.
      4. Spawns server process, pipes JSON-RPC `initialize` and `tools/list` payloads over stdio.
      5. Captures server responses, tool definitions, and standard error traces.
      6. Forcibly terminates container and returns structured `SandboxInspectionResult`.
- `models.py`:
  - `SandboxInspectionResult`: Contains `package_name`, `ecosystem`, `installed_version`, `discovered_tools`, `discovered_prompts`, `raw_stderr`, `execution_time_seconds`, and `exit_code`.

### 2. CLI Integration
- In `src/mcp_vulnerabilities/cli.py`:
  - Add subcommand `sandbox`:
    ```bash
    mcp-vuln sandbox pypi mcp-server-fetch --version 1.0.0
    mcp-vuln sandbox npm @modelcontextprotocol/server-filesystem
    ```
  - Options:
    - `--timeout <seconds>`: Container timeout (default 60).
    - `--network {bridge,none}`: Network policy during execution.
    - `--passports`: Automatically matches discovered tools against the 5,033+ passport knowledge base.
    - `--threat-check`: Automatically runs the YARA/RegEx threat engine against discovered tool descriptions.

---

## Clear Acceptance Criteria

1. **Host Isolation**:
   - Zero modifications to the host filesystem, environment variables, or local Python/Node installations.
2. **Dynamic Tool Discovery**:
   - Successfully discovers and extracts tools from real PyPI and npm MCP packages.
3. **Strict Resource Constraints**:
   - Automatically kills containers exceeding time or memory limits without hanging the CLI.
4. **Deterministic Clean-up**:
   - Ensures no dangling, exited, or orphaned containers remain after scan execution (even upon cancellation).
5. **Clear Error Reporting**:
   - Detects if container daemon is offline and provides informative diagnostic messages rather than obscure stack traces.

---

## Comprehensive Test Plan

### A. Unit Tests (`tests/test_sandbox.py`)
- Test container command string assembly and security flag injection (`--cap-drop ALL`).
- Test entrypoint discovery logic across mock `setup.cfg`, `pyproject.toml`, and `package.json`.
- Test timeout killer and zombie cleanup routines.

### B. Live Acceptance Tests (Zero Mocks — Real Container Execution)
- `test_live_container_engine_detection`: Detect real local Docker/Podman runtime, verify version querying and socket connectivity without mocking subprocess calls.
- `test_live_sandbox_pypi_execution`: When Docker is running, launch a real ephemeral container that installs a lightweight real Python package, runs a test command, and validates stdout capture. Verify container is 100% removed immediately after completion (`docker ps -a` contains zero remnant IDs).
- `test_live_sandbox_timeout_enforcement`: Run a containerized command programmed to sleep longer than the configured timeout (`--timeout 3`). Verify that the sandbox forcibly kills the container at 3 seconds and returns a clean `TimeoutExpired` diagnostic result.
