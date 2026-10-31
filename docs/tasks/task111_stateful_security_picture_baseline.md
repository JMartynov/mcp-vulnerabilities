# Task 111: Stateful Security Picture Baseline Engine (P0)

**Subsystem:** Stateful Posture & Inventory Storage (`src/mcp_vulnerabilities/audit/picture.py`, `tests/test_security_picture.py`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave21_network_inspection_security_picture_and_cli_hub.md](master_plan_wave21_network_inspection_security_picture_and_cli_hub.md)

---

## 1. Objective & Problem Statement

Enterprises need an immutable, auditable, point-in-time snapshot of their entire Model Context Protocol (MCP) attack surface. MCP infrastructure is split across local workstation client definitions (stdio subprocesses) and live network endpoints (SSE / HTTP services).

Prior to this task, scan results existed only as transient terminal prints or stateless audit reports. Security teams could not establish a baseline of "known-good" servers, track software supply chain integrity over time, or verify whether tool contracts were maliciously tampered with between developer sessions.

This task develops the **Stateful Security Picture Baseline Engine**:
1. Captures a unified `SecurityPicture` data model encompassing both local client configurations and network-discovered MCP endpoints.
2. Persists the baseline snapshot to `~/.mcp-vuln/state/security_picture.json` (or a custom path via `--save-picture <path>`).
3. Enriches each server record with package name, installed version, canonical tool hashes, matched passport specifications, confirmed CVE/GHSA vulnerabilities, CVSS severities, tamper integrity statuses, and recommended safe versions.
4. Guarantees safe atomic file writes and secure directory permissions (0700 / 0600) to protect security state from unauthorized local processes.

---

## 2. Detailed Technical Requirements

### 2.1 Storage Location & Directory Architecture (`src/mcp_vulnerabilities/audit/picture.py`)

1. Default Path Resolution:
   - Base directory: `~/.mcp-vuln/state/`
   - Default filename: `security_picture.json`
   - Full path helper: `get_default_picture_path() -> Path`
2. Secure File Permissions:
   - On Unix systems (macOS/Linux), create directory `~/.mcp-vuln/state` with mode `0o700` (`rwx------`).
   - Write files with mode `0o600` (`rw-------`).
3. Atomic Write Pattern:
   - Write output to a temporary file in the same directory (`security_picture.json.tmp.<pid>`).
   - Atomically replace the target file using `os.replace` to eliminate race conditions and partial file corruption.

### 2.2 Data Models

```python
@dataclass
class ToolSignatureRecord:
    name: str
    description_hash: str
    input_schema_hash: str
    canonical_hash: str
    is_high_risk: bool = False
    high_risk_category: str | None = None  # "shell", "filesystem", "network", "credentials"

@dataclass
class VulnerabilityRecord:
    cve_id: str | None
    ghsa_id: str | None
    cvss_score: float
    severity: str  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    summary: str
    affected_range: str
    fixed_in: str | None

@dataclass
class SecurityServerRecord:
    id: str  # e.g., "local:claude:filesystem" or "network:127.0.0.1:3000:memory"
    origin: str  # "local" or "network"
    client_or_host: str  # "claude", "cursor", "127.0.0.1:3000"
    server_name: str
    package_name: str | None
    installed_version: str | None
    transport: str  # "stdio", "sse", "http"
    endpoint_path: str | None  # e.g., "/sse", "/mcp"
    command_args: list[str]  # Sanitized, secrets redacted
    toolset_canonical_hash: str
    tools: list[ToolSignatureRecord]
    passport_id: str | None
    tamper_status: str  # "VERIFIED", "TAMPERED", "UNVERIFIED"
    tamper_details: list[str]
    vulnerabilities: list[VulnerabilityRecord]
    recommended_safe_version: str | None
    scanned_at: str  # ISO 8601

@dataclass
class PictureSummaryStats:
    total_servers: int
    local_servers: int
    network_servers: int
    vulnerable_servers: int
    critical_cve_count: int
    high_cve_count: int
    tampered_servers: int
    clean_servers: int

@dataclass
class SecurityPicture:
    schema_version: str  # "1.0.0"
    captured_at: str  # ISO 8601
    host_os: str
    hostname: str
    scanner_version: str
    stats: PictureSummaryStats
    servers: list[SecurityServerRecord]
    digest: str = ""  # SHA-256 over canonical picture payload
```

### 2.3 Picture Compilation Pipeline

Implement `build_security_picture(local_servers, network_endpoints, matcher, tamper_detector) -> SecurityPicture`:
1. Process Local Servers:
   - Iterate through `DiscoveredClientServer` records from `UniversalClientConfigScanner`.
   - Redact all secrets in args and environment.
   - Compute tool signatures and `toolset_canonical_hash` using `mcp_fingerprints.canonicalizer`.
   - Run `matcher.match_server(package_name, version)` to retrieve CVEs and safe versions.
   - Run `tamper_detector.verify_server(...)` to determine `VERIFIED` vs `TAMPERED`.
2. Process Network Endpoints:
   - Iterate through `NetworkMcpEndpoint` records from `NetworkScanner`.
   - Match identified `server_name` / `package_name` against passports.
   - Calculate tool signatures directly from `tools/list` schema definitions.
   - Run vulnerability and tamper evaluations.
3. Compute Aggregated Stats:
   - Count critical/high CVEs, tampered tools, vulnerable vs clean servers.
4. Compute Cryptographic Picture Digest:
   - Compute SHA-256 over normalized JSON payload for tamper-evident snapshot storage.

### 2.4 Serialization & Deserialization

1. `SecurityPicture.save(path: Path | str) -> None`:
   - Serializes dataclass hierarchy to indented JSON.
   - Enforces atomic write and secure file permissions.
2. `SecurityPicture.load(path: Path | str) -> SecurityPicture`:
   - Parses JSON file.
   - Verifies `schema_version`.
   - Reconstructs nested dataclass objects.

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_111_1 (Lossless Serialization Round-Trip):** `SecurityPicture.load(p).save(p2)` produces identical JSON data with identical server records and tool hashes.
- [ ] **INVARIANT_111_2 (Dual-Origin Unification):** Local stdio servers and network SSE/HTTP endpoints are unified in `SecurityPicture.servers` with explicit `origin` and `transport` fields.
- [ ] **INVARIANT_111_3 (Secret Zero-Storage):** Persisted `security_picture.json` never contains cleartext tokens, API keys, or passwords.
- [ ] **INVARIANT_111_4 (Permission Security):** Target directory and created picture files are restricted to user-only read/write (0700 / 0600 on POSIX).
- [ ] **INVARIANT_111_5 (Atomic Write Integrity):** A simulated process termination during save leaves the original `security_picture.json` uncorrupted.
- [ ] **INVARIANT_111_6 (Automated Test Coverage):** `tests/test_security_picture.py` covers dataclass creation, JSON round-trip, permission enforcement, digest verification, and edge-case deserialization.

---

## 4. Deliverables

1. `src/mcp_vulnerabilities/audit/picture.py`: Implementation of `SecurityPicture`, `SecurityServerRecord`, atomic persistence, and compilation pipeline.
2. `tests/test_security_picture.py`: Automated pytest suite testing serialization, round-trip fidelity, secure permissions, and mixed-origin snapshotting.
