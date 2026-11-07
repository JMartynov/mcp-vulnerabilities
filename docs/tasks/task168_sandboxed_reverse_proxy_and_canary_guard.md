# Task 168: Sandboxed Reverse Proxy and Canary Secret Guard

## Objective
Harden `mcp-vuln proxy` (`src/mcp_vulnerabilities/proxy/interceptor.py`) with containerized/subprocess sandbox execution drivers, honeytoken canary leak detection, and CLI control flags.

## Background & Issues Identified
- `McpStdioProxy.run_stdio()` executes child servers directly via unconfined `subprocess.Popen` on the host machine without sandboxing.
- Canary secret leak detection (`CanarySecretGuard` in `probe/sandbox_prober.py`) is confined to `probe-safe` and not used in the live proxy path.
- `mcp-vuln proxy` lacks `--sandbox [docker|subprocess|none]` and `--canary-detection` options.

## Scope of Changes
1. `src/mcp_vulnerabilities/cli.py`:
   - Add `--sandbox` (choices: `docker`, `subprocess`, `none`, default: `none`) and `--canary-detection` flags to `proxy` subparser.
2. `src/mcp_vulnerabilities/proxy/interceptor.py`:
   - Support launching child server inside `DockerSandboxDriver` or `RestrictedSubprocessDriver` when specified.
   - Integrate `CanarySecretGuard` into outbound tool inspection: check if parameters contain injected canary tokens, block execution, and record a security violation.
3. `tests/test_mcp_proxy.py`:
   - Verify sandboxed execution configuration and canary token exfiltration blocking.

## Acceptance Criteria
- `mcp-vuln proxy --help` documents `--sandbox` and `--canary-detection`.
- Proxy blocks messages containing canary secrets with a JSON-RPC error response.
- `pytest tests/test_mcp_proxy.py` passes 100%.
