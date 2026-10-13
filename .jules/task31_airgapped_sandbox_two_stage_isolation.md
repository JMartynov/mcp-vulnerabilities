# Task Specification: Two-Stage Airgapped Container Sandbox Isolation (P0-3)

## Objective
Harden the container execution sandbox (`src/mcp_vulnerabilities/sandbox/runner.py`) against supply-chain exfiltration attacks. Currently, `EphemeralSandbox.execute()` runs `pip install` or `npm install` inside a container with standard bridge networking (`--network bridge`). Untrusted packages can execute malicious code during installation via `setup.py`, PEP 517 build hooks, or npm `preinstall` scripts and exfiltrate secrets or probe internal networks *before* static analysis completes.

Implement **Two-Stage Airgapped Sandboxing**:
- **Stage 1 (Fetch Phase)**: Run a non-executing download command (`pip download --no-deps` for PyPI; `npm pack` for npm) in an unprivileged container with network access. No build scripts or code execution are permitted.
- **Stage 2 (Isolated Probe Phase)**: Mount the downloaded package bundle (`.whl` or `.tgz`) into an ephemeral inspection container running with strict airgap flags:
  - `--network none` (complete network isolation: no egress, no ingress, no loopback interface routing)
  - `--read-only` (read-only root filesystem with restricted tmpfs mounted at `/tmp:rw,noexec,nosuid,size=64m`)
  - `--cap-drop ALL`
  - `--security-opt no-new-privileges`
  - `--user 10001:10001` (unprivileged non-root user)
  - Memory & CPU resource quotas (`--memory 512m`, `--cpus 1.0`, `--pids-limit 100`).

## Target Files
- `src/mcp_vulnerabilities/sandbox/runner.py`
- `src/mcp_vulnerabilities/sandbox/models.py`
- `tests/test_acceptance_sandbox.py`
- `tests/test_sandbox.py`

## Implementation Details
1. **In `src/mcp_vulnerabilities/sandbox/runner.py`**:
   - Refactor `EphemeralSandbox.execute(package_spec: str, ecosystem: str)` into two distinct phases:
     - `_stage1_fetch(package_spec: str, ecosystem: str, target_dir: Path)`:
       - For Python: Runs `pip download --no-deps -d /stage1_out <package_spec>`. Does not install or execute code.
       - For npm: Runs `npm pack <package_spec> --pack-destination /stage1_out`.
     - `_stage2_inspect(package_file: Path, ecosystem: str)`:
       - Runs container with `--network none`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--memory 512m`, `--cpus 1.0`, `--pids-limit 100`.
       - Installs the downloaded file locally with `--no-index` / `--offline` flags (e.g. `pip install --no-index --find-links /pkg ...`).
       - Resolves entrypoints and executes probe command with strict timeout.
   - If container runtime (Docker or Podman) is unavailable, gracefully fall back with informative `SandboxInspectionResult(status="skipped", reason="Container engine not detected")`.

## Acceptance Criteria (100% Live & Unmocked)
1. **Live Container Network Airgap Test (`tests/test_acceptance_sandbox.py`)**:
   - In live Docker/Podman environment, verify that during stage 2 inspection, network access is completely unreachable (`--network none`).
   - Run a test command attempting outbound network socket connection (e.g. connecting to `8.8.8.8:53` or `127.0.0.1`); verify connection is immediately refused/fails due to network absence.
2. Verify package installation via local `.whl` / `.tgz` works inside the offline container.
3. Verify existing unit and acceptance tests in `tests/test_sandbox.py` and `tests/test_acceptance_sandbox.py` continue to pass.

## Non-Interactive Completion Directive
Execute all changes, write tests, run the test suite, ensure all tests pass with zero errors, and commit cleanly without asking interactive questions.
