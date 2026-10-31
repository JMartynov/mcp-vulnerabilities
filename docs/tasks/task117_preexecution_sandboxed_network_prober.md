# Task 117: Pre-Execution Sandboxed Network Prober (P0)

**Subsystem:** Isolated Dynamic Probing & Sandbox (`src/mcp_vulnerabilities/probe/sandbox_prober.py`, `src/mcp_vulnerabilities/cli.py`, `tests/probe/test_sandbox_prober.py`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave22_daemon_sandbox_tui_and_web_bridge.md](master_plan_wave22_daemon_sandbox_tui_and_web_bridge.md)

---

## 1. Objective & Problem Statement

Connecting directly to an untrusted, third-party, or newly exposed network Model Context Protocol (MCP) server carries acute security risks. Malicious or compromised MCP servers can:
1. **Attempt Host Credential Theft**: During initialization or tool negotiation, a server can invoke local environment inquiries or request file access targeting sensitive files (`~/.aws/credentials`, `~/.ssh/id_rsa`, `~/.bash_history`, `.env`).
2. **Execute Untrusted Code via Tool Invocations**: Untrusted servers may register tools that invoke dangerous execution sinks (`exec`, `system`, arbitrary shell commands) on the client machine.
3. **Exfiltrate Client Environment Secrets**: When an AI client registers an MCP server, ambient environment variables (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GITHUB_TOKEN`, `AWS_SECRET_ACCESS_KEY`) are often inherited by subprocesses or exposed over handshake metadata.

Security auditors and developers require an isolated pre-execution evaluation harness before configuring an unknown server into their primary AI clients (Claude Desktop, Cursor, etc.).

This task implements **`probe-safe`**, a zero-trust **Pre-Execution Sandboxed Network Prober**:
1. Isolates the probing execution within an ephemeral sandbox—supporting Docker containers, gVisor runsc, or strict scrubbed subprocesses.
2. Injects synthetic canary secrets (honeytokens) and actively monitors for exfiltration attempts or credential queries.
3. Enforces strict network and filesystem constraints (read-only root, dropped capabilities, egress filtering).
4. Performs protocol handshakes (`initialize`, `tools/list`, `prompts/list`, `resources/list`) to extract schemas and evaluate behavioral safety before host registration.
5. Emits a structured `SandboxProbeVerdict` (CLEAN, SUSPICIOUS, MALICIOUS) with actionable evidence.

---

## 2. Detailed Technical Requirements

### 2.1 Sandbox Architecture & Drivers (`src/mcp_vulnerabilities/probe/sandbox_prober.py`)

1. **Dual Driver Isolation Framework**:
   - `DockerSandboxDriver`:
     - Launches an ephemeral, unprivileged Docker container:
       ```bash
       docker run --rm \
         --network none \
         --read-only \
         --cap-drop ALL \
         --security-opt no-new-privileges \
         --memory 512m \
         --cpus 1.0 \
         --tmpfs /tmp:rw,noexec,nosuid,size=64m \
         -e CANARY_OPENAI_KEY="sk-canary-..." \
         -e CANARY_AWS_SECRET="wJalrXUtn..." \
         mcp-probe-runner:alpine
       ```
     - For network SSE/HTTP probing where network access to the target endpoint is required: creates an isolated bridge network bound strictly to the target host/port, blocking all other public Internet egress.
   - `RestrictedSubprocessDriver`:
     - Lightweight local fallback when Docker is unavailable.
     - Strips all inherited environment variables: creates a sterile environment dict containing only minimal system variables (`PATH`, `USER`).
     - Injects synthetic canary variables.
     - Sets execution working directory to an isolated temporary scratch directory (`tempfile.TemporaryDirectory`).
     - Enforces hard execution timeouts via `asyncio.wait_for`.

2. **Canary Secret Guard & Exfiltration Detection**:
   - Class `CanarySecretGuard`:
     - Generates unique UUID-tagged honeytokens for the probe session:
       ```python
       @dataclass
       class CanaryTokens:
           openai_key: str = "sk-mcp-canary-7b8f9a0e1c2d"
           aws_secret: str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
           github_token: str = "ghp_canaryMcpTestToken9876543210"
           secret_file_marker: str = "MCP_HONEYTOKEN_VERIFICATION_MARKER_99"
       ```
     - Populates a virtual canary file system in the sandbox temporary directory:
       - `.aws/credentials`
       - `.ssh/id_rsa.pub`
       - `.env`
     - Analyzes outbound JSON-RPC payloads, tool parameter schemas, and server descriptions for reflection or extraction of canary values.
     - Detects file read requests matching canary file paths.

### 2.2 Protocol Introspection & Behavioral Safety Engine

1. **JSON-RPC Handshake & Capability Introspection**:
   - Connects to candidate endpoint over stdio or HTTP/SSE inside the sandbox.
   - Sends standard MCP `initialize` request.
   - Captures `serverInfo`, `capabilities`, `tools/list`, `prompts/list`, `resources/list`.
2. **Behavioral Safety Classification**:
   - Analyzes tool input schemas:
     - Scans for dangerous shell command parameters (e.g. `cmd`, `command`, `exec`, `script`, `bash`).
     - Scans for arbitrary path arguments permitting traversal (`/etc/passwd`, `~/.ssh`).
     - Scans tool descriptions for prompt injection or system prompt override instructions.
   - Evaluates reachability against the canonical passports catalog and known CVEs.
3. **Verdict Generation**:
   ```python
   class ThreatLevel(str, Enum):
       CLEAN = "CLEAN"
       SUSPICIOUS = "SUSPICIOUS"
       MALICIOUS = "MALICIOUS"

   @dataclass
   class SandboxProbeVerdict:
       endpoint_url: str
       driver: str
       threat_level: ThreatLevel
       canary_leaked: bool
       canary_details: list[str]
       dangerous_tools_found: list[str]
       cve_findings: list[dict[str, Any]]
       server_info: dict[str, Any]
       duration_sec: float
       remediation_recommendation: str
   ```

### 2.3 CLI Command Specification (`src/mcp_vulnerabilities/cli.py`)

```text
mcp-vuln probe-safe [OPTIONS]

Options:
  --url URL               Target MCP endpoint URL (http/sse) or command string (stdio).
  --sandbox-type TYPE     Sandbox isolation engine: docker | subprocess (default: docker).
  --timeout SECONDS       Execution timeout in seconds (default: 30).
  --canary-detection      Enable synthetic honeytoken exfiltration analysis (default: true).
  --allow-outbound        Allow outbound network access beyond target host (default: false).
  --json                  Output raw JSON verdict for automation/scripts.
```

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_117_1 (Strict Host Secret Sanitization):** Host secrets (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`) are never inherited by or exposed to the sandbox environment.
- [ ] **INVARIANT_117_2 (Canary Exfiltration Alarm):** If an untrusted server reflects or requests a canary honeytoken, `threat_level` is set to `MALICIOUS`, `canary_leaked` is set to `True`, and the command exits with code 2.
- [ ] **INVARIANT_117_3 (Ephemeral Resource Destruction):** All spawned Docker containers, network bridges, temporary scratch directories, and child processes are guaranteed to be cleaned up on success, failure, timeout, or `SIGINT`.
- [ ] **INVARIANT_117_4 (Strict Execution Quotas):** Sandbox execution strictly terminates within `--timeout` seconds, preventing server hang attacks or unbounded event stream loops.
- [ ] **INVARIANT_117_5 (Test Coverage & Mock Driver):** `tests/probe/test_sandbox_prober.py` validates canary detection, Docker command building, subprocess isolation, and threat level assignment using simulated rogue MCP servers.

---

## 4. Deliverables

1. `src/mcp_vulnerabilities/probe/sandbox_prober.py`: Implementation of `SandboxProber`, `DockerSandboxDriver`, `RestrictedSubprocessDriver`, `CanarySecretGuard`, and `SandboxProbeVerdict`.
2. `src/mcp_vulnerabilities/cli.py`: Registration of `mcp-vuln probe-safe` subcommand with arguments and output formatters.
3. `tests/probe/test_sandbox_prober.py`: Automated test suite covering Docker flag construction, canary exfiltration detection, timeout handling, and verdict models.
