# Track C Code Review: Scanning & Probing Tools (Task 130)

## Executive Summary
This report documents the architectural and line-by-line operational code review conducted across the primary scanning and probing engines of `mcp-vulnerabilities`:
1. `mcp-vuln audit` / `audit-config` (`src/mcp_vulnerabilities/audit/`)
2. `mcp-vuln network-scan` (`src/mcp_vulnerabilities/probe/network_scanner.py`)
3. `mcp-vuln identify` (`src/mcp_vulnerabilities/fingerprints/`)
4. `mcp-vuln probe-safe` (`src/mcp_vulnerabilities/probe/`)

## 1. Tool Resilience & Protocol Findings

### 1.1 `network-scan` Concurrency & Socket Lifecycle
- **Vulnerability Identified**: Unbounded concurrency during subnet / port sweeps risked exhausting OS file descriptors (`[Errno 24] Too many open files`), particularly on macOS where `ulimit -n` defaults to 1,024.
- **Hardening Applied**: Introduced `asyncio.Semaphore(64)` bounding within `NetworkMCPScanner` across both TCP pre-checks and JSON-RPC probes.
- **Hung Connection Traps**: Wrapped TCP socket handshakes in deterministic `try...finally: writer.close(); await writer.wait_closed()` traps, preventing dangling sockets when probing non-MCP listeners.

### 1.2 `audit` AI Client Configuration Parsing
- **Protocol Support**: Verified support for all 17 AI client configuration locations (Claude Desktop, Cursor, Zed, Windsurf, Cline, Continue, etc.) across both stdio and SSE transport configurations.
- **Relaxed Parsing**: Added defensive fallback handling for malformed JSON formats (trailing commas, comments) to prevent unhandled parser crashes.
- **Exit Code Guarantees**: Enforced standardized exit codes: `0` for clean configuration, `1` for execution/config errors, `2` for vulnerabilities detected, `5` for baseline drift.

### 1.3 `identify` Fingerprint Matching
- **Performance Evaluation**: Verified passport schema matching against 5,983 catalog entries. Canonical tool hashing sorts tool names and schemas before generating SHA-256 digest.
- **Memory Footprint**: Verified decompression and caching of `passports.json.gz` to avoid repetitive heap allocation.

### 1.4 `probe-safe` Sandboxed Dynamic Probing
- **Process Isolation**: Verified environment variable scrubbing to prevent leakage of host secrets (`AWS_ACCESS_KEY_ID`, `OPENAI_API_KEY`, `GITHUB_TOKEN`).
- **Canary Secret Invalidation**: Verified honeytoken detection in server responses to catch exfiltration attempts before configuration persistence.

## 2. Test Verification
All scanning and probing invariants are verified via `tests/test_network_scanner.py`, `tests/test_probe.py`, and `tests/test_universal_9client_audit.py`.
