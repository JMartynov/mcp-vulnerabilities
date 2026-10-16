# MCP Vulnerabilities: Security Architecture & Auditing Specification

The MCP Vulnerability Advisory Database platform provides an open-source, OSV 1.6-compliant security intelligence and vulnerability scanning engine for Model Context Protocol (MCP) ecosystems. This document details the defense-in-depth architecture covering container sandboxing, AST taint modeling, parameter injection defenses, runtime protocol verification, and automated pre-commit scanning.

---

## 1. Multi-Language AST Extraction & Zero-Execution Security

To safely inspect source code and contracts from untrusted upstream packages, the scanning pipeline employs zero-eval, zero-import static analysis:

* **Static Traversal**: Modules are never imported into the running interpreter, preventing supply-chain malware from executing arbitrary code during the discovery phase.
* **Abstract Syntax Tree (AST) Taint Analysis**: The AST engine traces user-controlled tool inputs into dangerous sinks (`subprocess`, `eval`, SQL execution, file paths, and network connections) without running the package.
* **Sanitizer Verification**: Dataflow analysis verifies that arguments passed to sensitive primitives pass through registered validation or sanitization routines before execution.

---

## 2. Tool Parameter Risk Indicators & Injection Defenses

Tools registered with MCP clients present varying levels of risk depending on capability and parameter flexibility:

| Risk Tier | Indicator Patterns | Mitigation & Parameter Defenses |
| :--- | :--- | :--- |
| **CRITICAL** | `bash`, `exec`, `shell`, `system`, arbitrary writes | Strict command whitelisting, immutable sandbox container isolation. |
| **HIGH** | `sql`, `query`, SSRF endpoints, env retrieval | Parameterized query enforcement, egress network firewalling. |
| **MEDIUM** | Scoped filesystem read/write, controlled HTTP | Sandboxed directory roots, path canonicalization against traversal. |
| **LOW** | Pure functional computations, static schemas | Schema constraint validation, enum and regex parameter bounds. |

---

## 3. Container & VM Sandbox Execution Isolation

For dynamic probe handshakes and package inspection of closed-source binaries or NPM/PyPI archives, the runtime enforces isolated execution drivers:

### 3.1 Two-Stage Dynamic Sandboxing
1. **Stage 1 (Fetch)**: Dependencies are fetched within an isolated, disposable container or ephemeral environment.
2. **Stage 2 (Airgapped Inspection)**: The fetched package is mounted into an airgapped execution container:
   * **Network Isolation**: `--network none` strictly prevents network egress.
   * **Filesystem Immutability**: `--read-only` root filesystem with temporary non-executable RAM scratch space (`--tmpfs /tmp:rw,noexec,nosuid,size=64m`).
   * **Privilege Reduction**: `--cap-drop ALL`, `--security-opt no-new-privileges`, running as non-root user `10001:10001`.
   * **Resource Throttling**: Strict memory quotas (`--memory 512m`), CPU limits (`--cpus 1.0`), and PID limits (`--pids-limit 100`).

### 3.2 Unified Drivers (`drivers.py`)
* `DockerSandboxRunner`: Standard container isolation via Docker or Podman CLI.
* `IncusSandboxRunner`: MicroVM and container containment using Canonical Incus with memory/CPU limits and automatic ephemeral instance destruction.
* `HostSandboxRunner` / `HostRunner`: Minimal fallback with aggressive environment sanitization (`AWS_*`, `GITHUB_TOKEN`, `OPENAI_API_KEY`, and `SSH_*` stripping).
* `AutoSandboxRunner`: Dynamically selects the most secure available isolation driver on the host system.

---

## 4. Subprocess Stderr Deadlock Elimination & Transport Hardening

Runtime probing over stdio streams is susceptible to OS buffer exhaustion when servers emit heavy telemetry or logs:

* **Asynchronous Drain Threads**: Dedicated background daemon threads continuously drain `process.stderr` into ring buffers (`collections.deque(maxlen=100)`), completely preventing pipe deadlocks.
* **Deterministic Timeouts**: Subprocess termination enforces a graceful `SIGTERM` followed by forceful `SIGKILL` upon timeout expiration, preventing orphaned processes.
* **Stdio Protocol Strictness**: Handshakes adhere strictly to JSON-RPC 2.0 specifications (`initialize`, `notifications/initialized`, `tools/list`).

---

## 5. Headless REST API Gateway Security

The REST daemon (`mcp-vuln serve`) exposes headless auditing endpoints with strict input validation:

* **Remote Command Execution Safeguards**: Direct CLI command execution over HTTP (`/api/v1/scan/probe` and `/api/v1/identify`) is disabled by default (`403 Forbidden`). Clients must supply explicit tool descriptors or remote SSE URLs.
* **Severity Threshold Filtering**: Configuration scans (`/api/v1/scan/config`) accept and enforce `severity_threshold` filters (LOW, MEDIUM, HIGH, CRITICAL) directly against the vulnerability matching engine.
* **Structured Error Normalization**: All errors adhere to RFC-compliant structured JSON with predictable error codes and sanitized tracebacks.

---

## 6. Continuous CI/CD & Pre-Commit Integration

Enterprise pipelines can enforce zero-vulnerability guarantees through distributed integration points:

* **Reusable GitHub Action (`action.yml`)**:
  ```yaml
  - name: Audit MCP Configuration
    uses: JMartynov/mcp-vulnerabilities@v1
    with:
      config-path: .claude/claude_desktop_config.json
      fail-on-severity: HIGH
      format: sarif
  ```
* **Pre-Commit Hooks (`.pre-commit-hooks.yaml`)**:
  Exposes `mcp-vuln-audit` and `mcp-audit-config` to automatically scan modified client settings and lockfiles before commit.

---

## 7. Tombstoning & Supply-Chain Deprecation Tracking

* **404 Tombstoning**: Upstream packages deleted or privatized on PyPI, NPM, or Smithery are permanently tombstoned in `index.json` to preserve historical security records.
* **Cryptographic Toolset Hashing**: Canonical SHA-256 hashes detect unexpected tool additions or signature mutations across versions, signaling supply chain tampering.
