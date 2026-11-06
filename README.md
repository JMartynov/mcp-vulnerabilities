# Open-Source MCP Vulnerability Advisory Database

[![Daily MCP Vulnerability Ingestion & Sync](https://github.com/JMartynov/mcp-vulnerabilities/actions/workflows/daily_sync.yml/badge.svg)](https://github.com/JMartynov/mcp-vulnerabilities/actions/workflows/daily_sync.yml)
[![PyPI version](https://img.shields.io/pypi/v/mcp-vulnerabilities.svg)](https://pypi.org/project/mcp-vulnerabilities/)
[![Advisories Count](https://img.shields.io/badge/advisories-500%2B-red.svg)](data/vulnerabilities)
[![OSV Schema 1.6.0](https://img.shields.io/badge/schema-OSV%201.6.0-blue.svg)](https://ossf.github.io/osv-schema/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security Explorer](https://img.shields.io/badge/Security_Explorer-Live_Portal-38bdf8?style=flat-square&logo=googlechrome)](https://jmartynov.github.io/mcp-vulnerabilities/)
[![Release Updates](https://img.shields.io/badge/Release_Updates-Live_Feed-10b981?style=flat-square&logo=rss)](https://jmartynov.github.io/mcp-vulnerabilities/updates.html)

An open-source, automated **Open Source Vulnerability (OSV 1.6)** compliant security advisory database and multi-layered defense toolkit specifically curated for the **Model Context Protocol (MCP)** ecosystem.

---

## 📑 Table of Contents

- [Overview & Value Proposition](#overview--value-proposition)
- [Installation & Quickstart](#installation--quickstart)
- [Interactive Command Hub](#interactive-command-hub)
- [Practical HOWTOs & Real-World Use Cases](#practical-howtos--real-world-use-cases)
  - [HOWTO 1: Audit Local AI Client Installations (Claude Desktop, Cursor, Zed, Cline)](#howto-1-audit-local-ai-client-installations)
  - [HOWTO 2: Audit a Project Config & Auto-Remediate Vulnerabilities](#howto-2-audit-a-project-config--auto-remediate-vulnerabilities)
  - [HOWTO 3: Enforce CI/CD Security Baselines & Detect Configuration Drift](#howto-3-enforce-cicd-security-baselines--detect-configuration-drift)
  - [HOWTO 4: Detect AI-Hallucinated & Typosquatted Packages](#howto-4-detect-ai-hallucinated--typosquatted-packages)
  - [HOWTO 5: Live Network Discovery of Unauthenticated MCP Listeners](#howto-5-live-network-discovery-of-unauthenticated-mcp-listeners)
  - [HOWTO 6: AST Call-Graph Reachability Analysis for MCP Server Code](#howto-6-ast-call-graph-reachability-analysis-for-mcp-server-code)
  - [HOWTO 7: Protect Agents at Runtime with Inline MCP Reverse Proxy](#howto-7-protect-agents-at-runtime-with-inline-mcp-reverse-proxy)
  - [HOWTO 8: Automated GitOps Pull Request Remediation Bot](#howto-8-automated-gitops-pull-request-remediation-bot)
  - [HOWTO 9: Python SDK Integration for Custom Security Tooling](#howto-9-python-sdk-integration-for-custom-security-tooling)
  - [HOWTO 10: Verify Cryptographic Feed Provenance with Sigstore](#howto-10-verify-cryptographic-feed-provenance-with-sigstore)
- [CI/CD Integration](#cicd-integration)
- [CLI Subcommand Catalog](#cli-subcommand-catalog)
- [Web Explorer & Portals](#web-explorer--portals)
- [Data Sources & Ingestion Pipeline](#data-sources--ingestion-pipeline)
- [Production Readiness & Audit Benchmarks](#production-readiness--audit-benchmarks)
- [Environment Variables](#environment-variables)
- [Exit Codes Reference](#exit-codes-reference)
- [Testing & Verification](#testing--verification)
- [License](#license)

---

## Overview & Value Proposition

The Model Context Protocol (MCP) enables LLMs to invoke external tools, read resources, and interface with local databases and APIs. However, this unlocks critical attack vectors:
- **Unpinned and Vulnerable Packages**: Clients defaulting to `@latest` or unpinned packages risk executing known remote code execution (RCE) or path traversal vulnerabilities.
- **AI Hallucinations & Typosquatting**: LLMs frequently suggest misspelled or non-existent package names (e.g. `mcp-server-sqlte` instead of `mcp-server-sqlite`), leading to malicious package installations.
- **Shadow & Mutated Tools**: Compromised upstream servers can silently inject unadvertised tools into `tools/list` to hijack agent execution.
- **Exposed Local Services**: Developers inadvertently expose unauthenticated HTTP/SSE MCP endpoints on loopback and LAN interfaces.

`mcp-vulnerabilities` provides an end-to-end security solution: continuous vulnerability ingestion, automated multi-client configuration discovery, AST-based reachability filtering, runtime proxy guardrails, and 1-click automated remediation.

---

## Installation & Quickstart

### Prerequisites
- Python `>= 3.10`
- `pip` or [`uv`](https://docs.astral.sh/uv/)

### Installation

Install via PyPI:
```bash
pip install mcp-vulnerabilities
```

Or install with `uv`:
```bash
uv pip install mcp-vulnerabilities
```

For development installations:
```bash
git clone https://github.com/JMartynov/mcp-vulnerabilities.git
cd mcp-vulnerabilities
pip install -e ".[dev]"
```

### 30-Second Quickstart

Scan all installed AI desktop clients and code editors on your system with a single command:

```bash
mcp-vuln audit --all-clients
```

Search the local OSV advisory catalog for any package or keyword:

```bash
mcp-vuln search filesystem
```

Inspect a specific CVE or GHSA advisory:

```bash
mcp-vuln lookup CVE-2025-53109
```

---

## Interactive Command Hub

Launching `mcp-vuln` with zero arguments or running `mcp-vuln hub` starts an interactive terminal control dashboard:

```bash
mcp-vuln
```

```text
================================================================================
                     🛡️  MCP SECURITY COMMAND HUB  🛡️
================================================================================
 OS: macOS 15.3 (arm64)
 Local Clients Scanned: 14 / 17 detected
 Network Hosts Probed: localhost (12 ports active)
 Total Discovered Servers: 28 (22 Local Stdio, 6 Network SSE/HTTP)
 Baseline Picture Status: Saved (2026-10-31 10:00:15)
 Security Posture: ⚠️ WARNING (2 High CVEs, 1 Shadow Server)
================================================================================

  [1] 🖥️  Local Workstation Audit & Shadow MCP Discovery
  [2] 🌐 Network & Port MCP Scanner
  [3] 📸 Baseline Picture & Security Drift Analysis
  [4] 🛡️  Vulnerability Audit, Fingerprinting & Remediation
  [5] 📦 Export Reports & Compliance (SARIF / CycloneDX / JSON)
  [0] 🚪 Exit

================================================================================
```

For headless execution or CI pipelines, pass `--json` or `--batch`:
```bash
mcp-vuln hub --json
```

---

## Practical HOWTOs & Real-World Use Cases

Below are practical, step-by-step guides showing how to prepare test cases, run commands, and interpret the resulting output.

---

### HOWTO 1: Audit Local AI Client Installations

**Scenario**: You want to check all AI agents and IDEs on your workstation (Claude Desktop, Cursor, Zed, Cline, Windsurf, VS Code, JetBrains Junie, etc.) for vulnerable or unpinned MCP servers.

#### Step 1: Execute the Multi-Client Audit
```bash
mcp-vuln audit --all-clients --verify-signatures
```

#### Step 2: What You See
The scanner discovers configs across standard application data directories, redacting all sensitive environment tokens (`***REDACTED***`):

```text
2026-11-06 22:15:00 [INFO] Found client config: /Users/username/Library/Application Support/Claude/claude_desktop_config.json
2026-11-06 22:15:00 [INFO] Found client config: /Users/username/.cursor/mcp.json
2026-11-06 22:15:01 [INFO] Found client config: /Users/username/.config/zed/settings.json

======================================================================
 MCP SECURITY AUDIT REPORT: 6 servers scanned
======================================================================

[VULNERABLE SERVER] Server: postgres (@modelcontextprotocol/server-postgres)
  Client:          Claude Desktop
  Vulnerability:   CVE-2025-53108 [Severity: HIGH]
  Installed:       0.6.1
  Affected Range:  >=0, <=0.6.1
  Remediation:     Upgrade to >= 0.6.2
  Summary:         PostgreSQL MCP server exposes connection strings via logging parameters
  Authoritative Sources:
    * Official CVE: https://www.cve.org/CVERecord?id=CVE-2025-53108
    * NIST NVD:     https://nvd.nist.gov/vuln/detail/CVE-2025-53108
    * OSV Record:   https://osv.dev/vulnerability/CVE-2025-53108

[UNPINNED WARNING] Server: filesystem (@modelcontextprotocol/server-filesystem)
  Client:          Cursor
  Vulnerability:   GHSA-hc55-p739-j48w [Severity: HIGH]
  Installed:       Unpinned (latest)
  Affected Range:  >=2025.1.14, <2025.7.1
  Remediation:     Upgrade to >= 2025.7.1
  Summary:         Path validation bypass via colliding path prefix in server-filesystem

----------------------------------------------------------------------
SUMMARY: 2 vulnerability findings (CRITICAL/HIGH issues detected!).
----------------------------------------------------------------------
```

> [!NOTE]
> The command exits with `1` when vulnerabilities are detected, making it ideal for build failure gating.

---

### HOWTO 2: Audit a Project Config & Auto-Remediate Vulnerabilities

**Scenario**: You have a repository-specific or local client configuration containing an unpinned or vulnerable MCP server. You want to preview and apply automated upgrades.

#### Step 1: Prepare a Sample Configuration
Create a test configuration file `sample_claude_config.json`:
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem"]
    },
    "postgres": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-postgres@0.6.1"]
    }
  }
}
```

#### Step 2: Preview Remediation (Dry Run)
Run `fix` with `--dry-run` to generate a unified diff without touching the file:
```bash
mcp-vuln fix --config sample_claude_config.json --dry-run
```

#### Step 3: What You See
```diff
--- a/sample_claude_config.json
+++ b/sample_claude_config.json
@@ -2,7 +2,7 @@
   "mcpServers": {
     "filesystem": {
       "command": "npx",
-      "args": ["-y", "@modelcontextprotocol/server-filesystem"]
+      "args": ["-y", "@modelcontextprotocol/server-filesystem@2025.7.1"]
     },
     "postgres": {
       "command": "npx",
-      "args": ["-y", "@modelcontextprotocol/server-postgres@0.6.1"]
+      "args": ["-y", "@modelcontextprotocol/server-postgres@0.6.2"]
     }
   }
 }

======================================================================
 MCP CLIENT CONFIG REMEDIATION
======================================================================
Server: filesystem (@modelcontextprotocol/server-filesystem)
  Old version: unpinned
  New version: 2025.7.1

Server: postgres (@modelcontextprotocol/server-postgres)
  Old version: 0.6.1
  New version: 0.6.2

----------------------------------------------------------------------
DRY RUN: No files were modified.
```

#### Step 4: Apply the Fix Safely
When satisfied, execute with `--write`. The tool creates an atomic, timestamped backup (`sample_claude_config.json.bak.<timestamp>`) before writing:
```bash
mcp-vuln fix --config sample_claude_config.json --write
```

---

### HOWTO 3: Enforce CI/CD Security Baselines & Detect Configuration Drift

**Scenario**: You want to prevent developers from adding unapproved MCP servers, modifying security flags, or introducing unreviewed tools into client configurations during PR reviews.

#### Step 1: Create an Approved Baseline Snapshot
Run an audit and save the approved inventory snapshot:
```bash
mcp-vuln audit --config .cursor/mcp.json --save-baseline baseline.json
```

#### Step 2: Simulate Configuration Drift
Suppose a developer adds an unreviewed server or modifies flags in `.cursor/mcp.json`:
```json
{
  "mcpServers": {
    "approved-sqlite": {
      "command": "uvx",
      "args": ["mcp-server-sqlite==0.2.0"]
    },
    "shadow-fetch": {
      "command": "npx",
      "args": ["-y", "mcp-server-fetch@0.1.0"]
    }
  }
}
```

#### Step 3: Run Drift Detection in CI
```bash
mcp-vuln audit --config .cursor/mcp.json --diff baseline.json --fail-on-drift
```

#### Step 4: What You See
```text
======================================================================
 MCP BASELINE DRIFT REPORT
======================================================================
[DRIFT DETECTED] Server 'shadow-fetch' was ADDED to configuration.
  Client:          local
  Package:         mcp-server-fetch
  Version:         0.1.0
  Details:         Server 'shadow-fetch' added

SUMMARY: 1 unapproved configuration change(s) detected.
```
The command terminates with **exit code `2`**, failing the CI pipeline and preventing unapproved servers from reaching production.

---

### HOWTO 4: Detect AI-Hallucinated & Typosquatted Packages

**Scenario**: LLMs frequently suggest misspelled package names (e.g. `mcp-server-sqlte` instead of `mcp-server-sqlite`) or malicious homoglyphs (e.g. using Cyrillic `с` instead of Latin `c`). You want to verify package names against the authentic MCP catalog.

#### Step 1: Prepare a Configuration with a Typosquatted Package
Create `typosquat_config.json`:
```json
{
  "mcpServers": {
    "sqlite": {
      "command": "npx",
      "args": ["-y", "mcp-server-sqlte"]
    }
  }
}
```

#### Step 2: Run Typosquat Detection
```bash
mcp-vuln audit-typosquat --config typosquat_config.json
```

#### Step 3: What You See
```text
2026-11-06 22:30:15 [WARNING] Detected HIGH typosquat in server 'sqlite': mcp-server-sqlte -> mcp-server-sqlite (HIGH_RISK_TYPOSQUAT)
```

To output machine-readable JSON:
```bash
mcp-vuln audit-typosquat --config typosquat_config.json --json
```
```json
{
  "analyzed_packages": [
    {
      "server_name": "sqlite",
      "package_name": "mcp-server-sqlte",
      "canonical_name": "mcp-server-sqlite",
      "risk_tier": "HIGH",
      "reason": "HIGH_RISK_TYPOSQUAT",
      "distance": 1
    }
  ],
  "typosquats_detected": [
    {
      "server_name": "sqlite",
      "package_name": "mcp-server-sqlte",
      "canonical_name": "mcp-server-sqlite",
      "risk_tier": "HIGH",
      "reason": "HIGH_RISK_TYPOSQUAT",
      "distance": 1
    }
  ],
  "risk_summary": {
    "has_critical": false,
    "has_high": true
  }
}
```

#### Step 4: Auto-Fix Typosquats
To automatically correct detected package names to their canonical equivalents:
```bash
mcp-vuln audit-typosquat --config typosquat_config.json --fix
```

---

### HOWTO 5: Live Network Discovery of Unauthenticated MCP Listeners

**Scenario**: Developers or microservices often spin up local MCP HTTP/SSE servers on arbitrary ports (`3000`, `8000`, `8080`). You want to discover running servers, verify whether they expose tools without authentication, and inspect their capabilities.

#### Step 1: Scan Localhost or Subnet
Scan common MCP development ports on localhost:
```bash
mcp-vuln network-scan --target localhost --ports 3000,8000,8080,8765
```

Or scan an entire local development subnet with 64 concurrent workers:
```bash
mcp-vuln network-scan --cidr 192.168.1.0/24 --concurrency 64
```

#### Step 2: What You See
The prober connects across candidate paths (`/`, `/sse`, `/mcp`, `/v1/mcp`) and sends a standard JSON-RPC 2.0 `initialize` request:

```text
======================================================================
 MCP NETWORK SCAN REPORT: localhost
======================================================================
[ACTIVE LISTENER] http://localhost:8000/sse
  Reachable:       True
  MCP Handshake:   Success (Protocol: 2024-11-05)
  Server Info:     mcp-filesystem-server (v0.5.0)
  Discovered Tools:
    - read_file (Dangerous: allows arbitrary local filesystem read)
    - write_file (Dangerous: allows filesystem modification)
    - list_directory
  Discovered Prompts: 2 registered
  Discovered Resources: 5 registered
  Authentication:  ⚠️ NONE (Open unauthenticated endpoint)

----------------------------------------------------------------------
SUMMARY: 1 active MCP service identified.
----------------------------------------------------------------------
```

---

### HOWTO 6: AST Call-Graph Reachability Analysis for MCP Server Code

**Scenario**: Your server repository depends on third-party libraries (e.g. `requests` or `jinja2`). Traditional scanners flag all CVEs in dependencies, causing alert fatigue. You want to determine if the vulnerable code is **actually reachable** from an MCP tool entrypoint (`@mcp.tool()` or `server.tool()`).

#### Step 1: Prepare Sample Server Code & Dependencies
Suppose `server.py` defines:
```python
import requests
import jinja2
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")

@mcp.tool()
def fetch_url(url: str):
    return requests.get(url).text  # requests is reachable!

def unused_template():
    return jinja2.Template("...")  # jinja2 is NEVER reached from any tool
```
And `requirements.txt` specifies:
```text
requests==2.25.0
jinja2==2.11.0
```

#### Step 2: Run Transitive Audit with AST Reachability
```bash
mcp-vuln audit-transitive --manifest requirements.txt --source-dir ./src --reachable-only
```

#### Step 3: What You See
```text
======================================================================
 TRANSITIVE DEPENDENCY AUDIT: requirements.txt (2 dependencies)
======================================================================

[VULNERABLE DEPENDENCY] requests (PyPI) @ 2.25.0
  Vulnerability: GHSA-j8r2-6x86-q33q [Severity: HIGH] (CVSS 7.5)
  Remediation:   Upgrade to >= 2.31.0
  Reachability:  REACHABLE
                 From Tools: fetch_url
  Summary:       Unintended leak of Proxy-Authorization header in requests

----------------------------------------------------------------------
SUMMARY: 1 reachable transitive vulnerability (Max CVSS: 7.5).
Filtered out 1 unreachable vulnerability in 'jinja2'.
----------------------------------------------------------------------
```

---

### HOWTO 7: Protect Agents at Runtime with Inline MCP Reverse Proxy

**Scenario**: You must run an unpatched or third-party MCP server, but want to block known vulnerable tools, prevent path traversal/SQL injection payloads, and redact sensitive tokens before they return to the LLM.

#### Step 1: Run Command Through the MCP Security Proxy
Wrap the stdio server process with `mcp-vuln proxy`:
```bash
mcp-vuln proxy \
  --package @modelcontextprotocol/server-filesystem \
  --mode block \
  --block-tool delete_file \
  --audit-log proxy_audit.jsonl \
  -- npx @modelcontextprotocol/server-filesystem /tmp
```

#### Step 2: What Happens Under the Hood
1. **JSON-RPC Interception**: The proxy intercepts client-to-server and server-to-client JSON-RPC lines.
2. **Tool Blocking**: If the AI model calls `delete_file` or a tool flagged as vulnerable in OSV, the proxy intercepts the message and responds directly to the client with JSON-RPC error code `-32001`:
   ```json
   {
     "jsonrpc": "2.0",
     "id": 4,
     "error": {
       "code": -32001,
       "message": "Blocked by MCP Security Proxy: tool 'delete_file' is restricted by security policy."
     }
   }
   ```
3. **Payload Guardrails**: Path traversal patterns (`../../etc/passwd`) or SQL injection markers (`DROP TABLE`) in tool arguments are blocked before execution.
4. **Audit Log**: Every tool invocation and blocked payload is written to `proxy_audit.jsonl`.

---

### HOWTO 8: Automated GitOps Pull Request Remediation Bot

**Scenario**: You manage a repository with team client configs or templates. You want an automated bot to locate client configs, compute safe upgrade pins, and create clean, idempotent pull requests.

#### Step 1: Run Remediate PR in Dry-Run Mode
```bash
mcp-vuln remediate-pr --repo-dir . --dry-run --assignee security-team
```

#### Step 2: What You See
```text
2026-11-06 22:40:00 [INFO] Scanning repository for client configurations...
2026-11-06 22:40:01 [INFO] Identified 1 vulnerable configuration: .claude/claude_desktop_config.json
2026-11-06 22:40:01 [INFO] Proposed Branch: mcp-vuln/fix-claude-desktop-config
2026-11-06 22:40:01 [INFO] Pull Request Title: fix(security): remediate vulnerable MCP servers in claude_desktop_config.json
2026-11-06 22:40:01 [INFO] Planned Changes:
  - Upgrade @modelcontextprotocol/server-filesystem: unpinned -> 2025.7.1 (Fixes CVE-2025-53109, CVE-2025-53110)
  - Upgrade @modelcontextprotocol/server-postgres: 0.6.1 -> 0.6.2 (Fixes CVE-2025-53108)

[DRY RUN COMPLETE] Zero branches or pull requests created.
```

To create the branch and open the GitHub PR automatically:
```bash
mcp-vuln remediate-pr --repo-dir . --assignee security-team --auto-merge
```

---

### HOWTO 9: Python SDK Integration for Custom Security Tooling

**Scenario**: You want to embed MCP vulnerability audits directly into your Python scripts, custom testing harnesses, or internal security scanners.

#### Step 1: Programmatic Configuration Audit
```python
from pathlib import Path
from mcp_vulnerabilities.audit import (
    ClientConfigParser,
    VulnerabilityMatcher,
)
from mcp_vulnerabilities.snapshot import load_snapshot

# 1. Load the official advisory database snapshot
advisories = load_snapshot("vulnerabilities.json.gz")
matcher = VulnerabilityMatcher(advisories)

# 2. Parse any AI client configuration (Claude, Cursor, Zed, etc.)
config_path = Path(".cursor/mcp.json")
servers = ClientConfigParser.parse_file(config_path)

# 3. Audit servers against known OSV advisories
report = matcher.audit_servers(servers)

print(f"Total Servers Scanned: {len(servers)}")
print(f"Vulnerabilities Found: {report.total_findings}")

for finding in report.findings:
    print(f"[{finding.severity_level}] {finding.server_name} ({finding.package_name})")
    print(f"  Vulnerability: {finding.vulnerability_id}")
    print(f"  Fixed Version: {finding.fixed_version or 'No fix available'}")
    print(f"  Summary:       {finding.summary}")
```

---

### HOWTO 10: Verify Cryptographic Feed Provenance with Sigstore

**Scenario**: In air-gapped or high-security enterprise environments, you must prove the vulnerability feed (`vulnerabilities.json.gz`) was generated by GitHub Actions and has not been tampered with.

#### Step 1: Execute Feed Signature Verification
```bash
mcp-vuln verify-feed \
  --feed vulnerabilities.json.gz \
  --bundle vulnerabilities.json.gz.sigstore.json
```

#### Step 2: What You See
```text
======================================================================
 SIGSTORE KEYLESS ATTESTATION VERIFICATION
======================================================================
 Feed Asset:      vulnerabilities.json.gz
 Sigstore Bundle: vulnerabilities.json.gz.sigstore.json
 OIDC Issuer:     https://token.actions.githubusercontent.com
 Identity:        https://github.com/JMartynov/mcp-vulnerabilities/.github/workflows/sign_release.yml@refs/heads/main
 Status:          ✅ VERIFIED (Cryptographically signed and untampered)
======================================================================
```

---

## CI/CD Integration

Prevent vulnerable MCP servers from entering your codebase by adding `mcp-vulnerabilities` to your GitHub Actions workflows.

### Audit Client Configurations
```yaml
name: MCP Security Gate
on: [push, pull_request]

jobs:
  audit-mcp:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: "3.11"

      - name: Install mcp-vulnerabilities
        run: pip install mcp-vulnerabilities

      - name: Audit AI Client Configuration
        run: |
          mcp-vuln audit --config .cursor/mcp.json --severity-threshold HIGH
```

### Audit Transitive Dependencies in Server Repositories
```yaml
      - name: Audit Reachable Transitive Dependencies
        run: |
          mcp-vuln audit-transitive \
            --manifest requirements.txt \
            --source-dir ./src \
            --reachable-only \
            --severity-threshold HIGH
```

---

## CLI Subcommand Catalog

The `mcp-vuln` CLI provides 34 specialized subcommands structured into functional domains:

### 🛡️ Client Auditing & Remediation
| Subcommand | Description | Key Flags |
| :--- | :--- | :--- |
| `audit` *(alias: `audit-config`)* | Audit AI client configs or packages against OSV database | `--all-clients`, `--config`, `--package`, `--severity-threshold`, `--format`, `--save-baseline`, `--diff`, `--fail-on-drift`, `--verify-signatures` |
| `fix` *(alias: `fix-config`)* | Automatically upgrade vulnerable servers to safe pinned releases | `--config`, `--client`, `--all-clients`, `--dry-run`, `--write` |
| `audit-typosquat` | Detect AI-hallucinated and typosquatted MCP packages | `--config`, `--fix`, `--threshold`, `--json`, `--strict` |
| `remediate-pr` | Automated GitOps PR bot that opens remediation PRs | `--repo-dir`, `--dry-run`, `--auto-merge`, `--assignee`, `--json` |
| `resolve-config` | Resolve tool naming collisions and namespace configs | `config_file`, `--strategy [prefix\|priority\|report]`, `--output` |
| `export-config` | Generate pinned, hardened configs for Claude, Cursor, Zed, Cline | `package`, `--client [claude\|cursor\|cline\|zed\|windsurf\|docker]` |

### 🔍 Threat Analysis, Transitive & AST Scanning
| Subcommand | Description | Key Flags |
| :--- | :--- | :--- |
| `audit-transitive` | Audit dependencies with AST tool reachability analysis | `--manifest`, `--source-dir`, `--reachable-only`, `--severity-threshold`, `--format` |
| `scan-source` | Static AST source code taint analyzer for injection vectors | `path`, `--format [text\|json\|sarif]`, `--output`, `--fail-on [CRITICAL\|HIGH]` |
| `scan-binaries` | Scan binary assets and check for malware hashes via VirusTotal | `target_dir`, `--blocklist`, `--enable-vt`, `--fail-on-malware` |
| `lint` | Audit tool schemas and protocol contracts for production readiness | `--command`, `--url`, `--file`, `--fail-under`, `--compliance` |
| `timeline` | Display per-version vulnerability timeline for a specific server | `server`, `--target-version`, `--snapshot` |

### 🌐 Network Probing & Runtime Sandboxing
| Subcommand | Description | Key Flags |
| :--- | :--- | :--- |
| `proxy` | Inline bidirectional JSON-RPC firewall and guardrail filter | `--package`, `--mode [block\|audit]`, `--block-tool`, `--audit-log`, `-- <cmd>` |
| `network-scan` | Scan local and network TCP ports for active MCP listeners | `--target`, `--cidr`, `--ports`, `--concurrency` |
| `identify` | Probe and identify unknown servers using behavioral fingerprints | `--command`, `--url`, `--correlate`, `--min-confidence`, `--format` |
| `probe` | Live protocol probe auditing tools, prompts, and resources | `--command`, `--url`, `--surfaces`, `--analyzers`, `--compliance` |
| `probe-safe` | Pre-execution sandboxed network prober with canary exfiltration analysis | `--url`, `--sandbox-type [docker\|subprocess]`, `--timeout`, `--allow-outbound` |
| `sandbox` | Safely execute untrusted MCP packages in an isolated container | `ecosystem`, `package`, `--version`, `--timeout`, `--network [bridge\|none]` |

### 🖥️ Dashboards & Services
| Subcommand | Description | Key Flags |
| :--- | :--- | :--- |
| `hub` | Launch the interactive terminal security dashboard | `--json`, `--batch` |
| `tui` | Split-pane curses terminal dashboard for interactive browsing | `--no-color` |
| `monitor` | Background daemon to continuously detect port drift and config changes | `--interval`, `--pid-file`, `--daemonize` |
| `serve` | Run headless REST API gateway microservice | `--host`, `--port`, `--cors-origins` |
| `bridge` | Run local loopback bridge server for static web portal integration | `--port`, `--cors-origins` |

### 📦 Database Ingestion, Synchronization & Feeds
| Subcommand | Description | Key Flags |
| :--- | :--- | :--- |
| `sync` | Run multi-source vulnerability ingestion pipeline | `--live-api`, `--include-gitlab`, `--cvelistv5-dir`, `--nvd-api` |
| `search` | Search vulnerabilities by keyword, package name, or CVE ID | `query`, `--limit`, `--format` |
| `lookup` | Lookup exact advisory details by ID or alias | `id`, `--snapshot` |
| `validate` | Validate OSV 1.6 schema compliance of advisory records | `--dir` |
| `snapshot` | Compile all raw advisories into consolidated `vulnerabilities.json.gz` | `--output-gz`, `--data-dir` |
| `export-osv` | Export OSV records into standard bucket format (`all.zip` + `manifest.json`) | `--output-dir`, `--data-dir` |
| `export-airgap` | Export offline air-gapped bundle with checksums | `--output-dir`, `--bundle` |
| `verify-feed` | Verify Sigstore keyless attestation and cryptographic provenance | `--feed`, `--manifest`, `--bundle`, `--offline` |
| `discover` | Run multi-registry MCP server discovery (npm, PyPI, GitHub, Smithery, Glama) | `--catalog-file`, `--no-npm`, `--no-pypi`, `--no-github` |
| `enrich` | Enrich missing package version metadata in server catalog | `--catalog-file`, `--workers`, `--limit`, `--force` |
| `correlate` | Correlate structural server passports against vulnerability database | `--output`, `--snapshot`, `--data-dir` |
| `site-build` | Multicore parallel builder for static web security portal | `--data-dir`, `--output-dir`, `--workers`, `--benchmark` |

### 📋 Complete CLI Options & Flags Index

The following CLI options and flags are supported across all `mcp-vuln` commands:

`--all-clients`, `--allow-outbound`, `--allowed-origin`, `--analyzers`, `--assignee`, `--audit-log`, `--auth-header`, `--auto-merge`, `--batch`, `--benchmark`, `--block-tool`, `--blocklist`, `--bundle`, `--catalog-file`, `--catalog-state-file`, `--cidr`, `--client`, `--command`, `--compliance`, `--concurrency`, `--config`, `--correlate`, `--cors-origins`, `--custom-config`, `--cvelist-delta`, `--cvelistv5-dir`, `--daemon`, `--data-dir`, `--diff`, `--diff-baseline`, `--dir`, `--dry-run`, `--ecosystem`, `--enable-vt`, `--expected-identity`, `--expected-issuer`, `--fail-on`, `--fail-on-drift`, `--fail-on-malware`, `--fail-on-non-compliant`, `--fail-under`, `--feed`, `--file`, `--fix`, `--force`, `--format`, `--gitlab-dir`, `--global`, `--header`, `--host`, `--include-gitlab`, `--install-service`, `--interval`, `--json`, `--limit`, `--live-api`, `--log-file`, `--manifest`, `--markdown-dir`, `--max-files`, `--min-confidence`, `--min-epss`, `--min-severity`, `--mock`, `--mode`, `--network`, `--no-auth`, `--no-cache`, `--no-canary-detection`, `--no-color`, `--no-github`, `--no-glama`, `--no-npm`, `--no-payload-guardrails`, `--no-pypi`, `--no-registries`, `--no-smithery`, `--notify`, `--notify-webhooks`, `--nvd-api`, `--offline`, `--open-browser`, `--output`, `--output-dir`, `--output-gz`, `--output-json`, `--package`, `--passports`, `--pid-file`, `--port`, `--ports`, `--reachable-only`, `--readiness`, `--repo-dir`, `--reset-state`, `--sandbox-type`, `--save-baseline`, `--servers-catalog`, `--severity-threshold`, `--simulate`, `--snapshot`, `--source-dir`, `--state-file`, `--status`, `--stop`, `--strategy`, `--strict`, `--strict-integrity`, `--strict-passport`, `--surfaces`, `--target`, `--target-version`, `--targets`, `--theme`, `--threat-check`, `--threshold`, `--timeout`, `--url`, `--verify-signatures`, `--version`, `--webhook`, `--workers`, `--write`

---

## Web Explorer & Portals

The project includes three zero-install, client-side web portals hosted on GitHub Pages:

- **[Unified MCP Security Explorer](https://jmartynov.github.io/mcp-vulnerabilities/)** (`docs/index.html`):
  - **Directory Infinite Scroll & Virtualization**: 6,280+ indexed MCP servers rendered at 60 FPS.
  - **Safe Config Basket & Drawer**: Multi-server selection basket with 1-click config exporter for Claude Desktop, Cursor, Zed, Windsurf, Cline, and Continue.
  - **Tool Collision Warnings**: Flags identical tool names across chosen servers to prevent prompt hijacking and tool shadowing.
  - **In-Browser Audit Dropzone**: Drag and drop any client config to audit and export markdown reports right in the browser.
- **[Release Updates & Delta Feed](https://jmartynov.github.io/mcp-vulnerabilities/updates.html)** (`docs/updates.html`):
  - **Velocity Sparklines**: Tracks server growth and advisory volume across releases.
  - **Toolset Evolution**: Side-by-side delta visualization of added/removed tools and SHA-256 fingerprint transitions.
  - **Syndication**: Available via [Atom Feed](https://jmartynov.github.io/mcp-vulnerabilities/data/feed.atom) and [JSON Feed](https://jmartynov.github.io/mcp-vulnerabilities/data/feed.json).
- **[Multi-Dimensional Analytics](https://jmartynov.github.io/mcp-vulnerabilities/analytics.html)** (`docs/analytics.html`):
  - Quantifies patched vs. unpatched zero-days across the MCP ecosystem.
  - Interactive drilldowns across OWASP MCP Top 10 risk categories.

---

## Data Sources & Ingestion Pipeline

Advisories are continuously updated and normalized to **OSV 1.6**:
1. **CVE List v5**: Official CVE JSON 5.0 records.
2. **GitHub Security Advisories (GHSA)**: Live GraphQL/REST security alerts.
3. **OSV.dev**: Unified open-source vulnerability database.
4. **National Vulnerability Database (NVD)**: CVE 2.0 vulnerability metrics and CVSS scores.
5. **GitLab Advisory Database**: High-fidelity open vulnerability feed curated by GitLab's Vulnerability Research Team.
6. **PyPA Advisory Database**: Python Packaging Authority advisories with PEP 440 OSV normalization.
7. **OpenSSF Malicious Packages**: Threat feed tracking backdoors, credential stealers, and typosquats.

---

## Production Readiness & Audit Benchmarks

`mcp-vulnerabilities` has undergone extensive empirical invariant testing across all subsystems:

| Report | Purpose & Scope | Link |
| :--- | :--- | :---: |
| **Cumulative Technical Audit Report** | Synthesis of all 8 empirical audits (Tasks 59–66); 26/26 invariants verified; subsystem health scorecards. | [**`CUMULATIVE_TECHNICAL_AUDIT_REPORT.md`**](docs/audit/CUMULATIVE_TECHNICAL_AUDIT_REPORT.md) |
| **Competitive Gap Analysis & Roadmap** | Grand Unified Feature Matrix across 10 industry tools (Verity, Anthropic, Cursor, Smithery, Snyk, Semgrep, Trivy). | [**`CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md`**](docs/audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md) |
| **Wave 14 Portal & Analytics Review** | In-depth review of visual styling, zero-day gap analytics, and config auditor dropzone. | [**`code_review_wave14_portal_and_analytics.md`**](docs/reports/code_review_wave14_portal_and_analytics.md) |

---

## Environment Variables

| Variable | Purpose | Default |
| :--- | :--- | :--- |
| `GITHUB_TOKEN` / `GH_TOKEN` | Authenticates GitHub API queries (5,000 req/hr quota) | None |
| `NVD_API_KEY` | Authenticates NIST NVD 2.0 API queries | None |
| `VIRUSTOTAL_API_KEY` | Enables binary hash threat intelligence lookups (`scan-binaries`) | None |
| `MCP_VULN_STATE_DIR` | Custom directory for baseline security pictures and snapshots | `~/.mcp-vuln/state/` |
| `MCP_VULN_HOST` | Host interface to bind API daemon (`mcp-vuln serve`) | `127.0.0.1` |
| `MCP_VULN_PORT` | Port to bind API daemon (`mcp-vuln serve`) | `8080` |
| `NO_COLOR` | Disables ANSI color codes across CLI terminal output | None |

---

## Exit Codes Reference

| Exit Code | Meaning | Typical Trigger |
| :---: | :--- | :--- |
| `0` | **Success / Clean** | Scan clean; no vulnerabilities found; drift check passed. |
| `1` | **Security Failure** | Vulnerabilities detected; malware found; compliance violations. |
| `2` | **Baseline Drift / Syntax Error** | Baseline drift detected (`--fail-on-drift`); missing required arguments. |
| `3` | **Operational Error** | File not found; network connection timeout; corrupt input. |
| `5` | **Review State Lock** | Git review branch merge blocked due to active interactive state. |

---

## Testing & Verification

The test suite enforces 100% runnable pass rates across both regression suites and empirical invariant audits:

```bash
# Run complete test suite
pytest -q

# Run empirical subsystem invariant audit tests
pytest -q tests/audit/

# Run acceptance tests
pytest -q tests/test_acceptance_*.py
```

---

## License

This project is licensed under the [MIT License](LICENSE).
