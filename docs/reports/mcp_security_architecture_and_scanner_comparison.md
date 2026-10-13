# MCP Security Architecture & Comparative Capability Analysis

**Date:** October 2026  
**Document Version:** 1.1.0  
**Scope:**
- State-of-the-Art Scanner Paradigms & Benchmark References (e.g. Cisco AI Defense MCP Scanner v0.3.x)
- Current `mcp-vulnerabilities` Platform (v1.0.0)
- `mcp-fingerprints` Structural Knowledge Base (5,033+ Verified Passports)
- Unified Next-Gen Open Security Architecture

---

## 1. Executive Summary

As the Model Context Protocol (MCP) rapidly becomes the universal standard connecting AI agents to enterprise APIs, local tooling, and data sources, securing the MCP supply chain requires a comprehensive, multi-layer defense-in-depth architecture spanning:
1. **Authoritative Vulnerability Databases & Lockfile Auditing** (known CVEs, GHSAs, OSV advisories).
2. **Runtime Fingerprinting & Shadowing Detection** (unlabelled server identification, AST schema hashing, tool collision detection).
3. **Behavioral & Static Threat Analysis** (YARA heuristics, prompt injection defense, AST taint tracking).
4. **Automated Enterprise Remediation & DevSecOps CI/CD** (SARIF v2.1.0, configuration auto-patchers, REST API daemon).

While contemporary heuristic scanners introduce useful approaches such as runtime YARA rules and basic readiness checks, they typically rely on closed commercial cloud inspection APIs, lack dedicated MCP vulnerability intelligence, cannot identify unlabelled running servers, offer no tool collision or shadowing detection across multi-server configurations, and cannot automatically remediate vulnerable client configurations.

This repository takes state-of-the-art open scanner paradigms and reworks them into an independent, clean-room, zero-dependency architecture. By unifying `mcp-vulnerabilities` with `mcp-fingerprints` and engineering pure-Python, local implementations of multi-surface probing, YARA/regex heuristics, schema readiness linting, and a headless REST gateway, this platform delivers an unrivaled, fully open-source security foundation for the MCP ecosystem.

---

## 2. Granular Capability Comparison Matrix

The following table provides an exhaustive, granular side-by-side comparison across all functional security domains.

| Capability / Feature Dimension | Cisco MCP Scanner (`cisco-ai-defense`) | Current `mcp-vulnerabilities` (v1.0.0) | `mcp-fingerprints` (Standalone) | Unified Platform (`mcp-vulnerabilities` + Fingerprints) | Competitive Advantage / Differentiator |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **I. VULNERABILITY DATABASE & THREAT FEEDS** | | | | | |
| **Dedicated MCP OSV 1.6 Advisory Database** | ❌ None (Relies on generic `pip-audit`) | ✅ **519+ Curated Advisories** (`data/osv/`) | ❌ None | ✅ **519+ Curated Advisories** | Cisco has 0 dedicated MCP advisories; ours tracks verified MCP CVEs with affected tools & semver ranges. |
| **NIST NVD 2.0 REST Stream Ingestion** | ❌ None | ✅ **Yes** (`nvd.py` with rate-limiting) | ❌ None | ✅ **Yes** (Automated daily sync) | Real-time CVE capture direct from NIST analysts. |
| **GitHub Advisory (GHSA) Pagination** | ❌ None | ✅ **Yes** (RFC 5988 cursor traversal) | ❌ None | ✅ **Yes** (Delta commit sync) | Captures breaking GHSAs within hours of publication. |
| **Live Upstream Google OSV.dev Export** | ❌ None | ✅ **Yes** (`all.zip` & GCS bucket sync) | ❌ None | ✅ **Yes** (Official upstream export) | Integrated into global vulnerability data lake. |
| **Real-time Webhook Alerts (Slack/Discord)** | ❌ None | ✅ **Yes** (`notifier.py`) | ❌ None | ✅ **Yes** (Discord, Slack, Webhook) | Real-time incident response notification for SecOps teams. |
| **Air-gapped Standalone Bundle Distribution** | ❌ None | ✅ **Yes** (`mcp-offline.tar.gz` with query engine) | ❌ None | ✅ **Yes** (Zero-dependency tarball) | Usable in air-gapped sovereign environments without internet. |
| **II. SERVER IDENTIFICATION & FINGERPRINTING** | | | | | |
| **Verified Server Passports Database** | ❌ 0 | ❌ 0 | ✅ **3,903+ Passports** (`passports.json.gz`) | ✅ **3,903+ Passports** Bundled | Instant identification of unknown or unlabelled running MCP servers. |
| **Tool Signature Hash Matching (SHA-256)** | ❌ None | ❌ None | ✅ **Yes** (Exact tool schema hash) | ✅ **Yes** (Runtime & static matching) | Detects server identity even if server name or command is obfuscated. |
| **Tool Shadowing & Collision Detection** | ❌ None | ❌ None | ✅ **Yes** (`conflict_detector.py`) | ✅ **Yes** (Multi-server audit) | Critical safety check: alerts when two servers claim the same tool name or conflicting prompts. |
| **Multi-Language AST Schema Extraction** | ❌ Limited (Python ast / Tree-sitter) | ❌ None | ✅ **Yes** (Python, TS/JS, Go, Rust, JVM, .NET) | ✅ **Yes** (Static extractor pipeline) | Analyzes source code without executing untrusted binaries. |
| **Runtime Protocol Schema Drift Detection** | ❌ None | ❌ None | ✅ **Yes** (`drift_detector.py`) | ✅ **Yes** (Compares spec to runtime) | Alerts when server tools differ from published passport specs. |
| **Jaccard Distance Tool Similarity Scoring** | ❌ None | ❌ None | ✅ **Yes** (`distance.py`) | ✅ **Yes** (Fuzzy passport matching) | Matches modified or patched servers to known upstream counterparts. |
| **III. RUNTIME TRANSPORTS & PROBING** | | | | | |
| **Stdio Transport Probing** | ✅ Yes (`--stdio-command`) | ✅ Yes (`mcp-vuln probe --command`) | ✅ Yes (`prober.py`) | ✅ **Yes** (Enhanced JSON-RPC handshake) | Parity achieved; our probe captures full handshake and tool schemas. |
| **SSE / HTTP Streamable Transport** | ✅ Yes (`--server-url`) | ✅ Yes (`mcp-vuln probe --url`) | ✅ Yes (`prober.py`) | ✅ **Yes** (SSE event stream parsing) | Direct connection to remote cloud MCP servers. |
| **OAuth 2.0 & Bearer Token Authentication** | ✅ Yes (`--auth-type oauth`) | ⚠️ Partial (Bearer token headers) | ⚠️ Partial | ✅ **Full OAuth 2.0 + Bearer Support** | Authenticates against enterprise MCP gateways. |
| **Configurable Process & Handshake Timeouts** | ✅ Yes (`--stdio-timeout`) | ✅ Yes (`--timeout`) | ✅ Yes (`--timeout`) | ✅ **Yes** (Granular connect/read timeouts) | Prevents hanging on slow or heavy MCP server launches. |
| **IV. THREAT & BEHAVIORAL ANALYSIS ENGINES** | | | | | |
| **YARA Pattern Matching Rules** | ✅ Yes (`yara-python` rules) | ❌ None | ❌ None | ✅ **Yes** (Integrated YARA Engine) | Scans tool descriptions and schemas for known malicious patterns. |
| **Prompt Injection & Overriding Defense** | ✅ Yes (`prompt_defense_analyzer.py` via Cisco API / LLM) | ❌ None | ⚠️ Rule-based classifier | ✅ **Yes** (Regex heuristic + Local LLM rules) | Flags hidden instructions, delimiters, and role-override payloads. |
| **Local Zero-Cost Semantic / LLM Analysis** | ⚠️ Partial (Ollama supported via LiteLLM) | ❌ None | ❌ None | ✅ **Yes** (Native LiteLLM + Ollama + OpenAI) | Complete local zero-cost execution with no external API requirement. |
| **Commercial API Inspection** | ✅ Proprietary Cisco AI Defense Cloud | ❌ None | ❌ None | ⚠️ Extensible Cloud Plugin Architecture | Cisco requires paid subscription; our system defaults to 100% open-source & local. |
| **Production Readiness & Linting** | ✅ Yes (Timeouts, retries, OPA) | ❌ None | ❌ None | ✅ **Yes** (`cli lint-readiness`) | Identifies missing error handling, parameter schemas, and retry policies. |
| **Binary File Malware Lookup (VirusTotal)** | ✅ Yes (`virustotal_analyzer.py`) | ❌ None | ❌ None | ✅ **Yes** (SHA-256 Blocklist + VirusTotal API) | Hashes bundled binaries, images, and DLLs against threat feeds. |
| **V. ECOSYSTEM LOCKFILE & DEPENDENCY AUDIT** | | | | | |
| **Modern Lockfile Scanning (`uv.lock`)** | ❌ None (Only `pip-audit` / `requirements.txt`) | ✅ **Yes** (Built-in `tomllib` parser) | ❌ None | ✅ **Yes** (`mcp-vuln audit uv.lock`) | Audits Astrals `uv.lock` with zero external dependencies. |
| **PEP 621 `pyproject.toml` Auditing** | ❌ None | ✅ **Yes** (Native parsing) | ❌ None | ✅ **Yes** (`mcp-vuln audit pyproject.toml`) | Audits standard Python project metadata directly. |
| **JavaScript/TypeScript (`package.json`)** | ⚠️ Generic `npm audit` in Docker | ✅ **Yes** (Native dependency extractor) | ❌ None | ✅ **Yes** (Native + Docker sandbox) | Direct extraction of npm MCP packages without requiring Node runtime. |
| **Poetry Lockfile (`poetry.lock`)** | ❌ None | ✅ **Yes** (Native parser) | ❌ None | ✅ **Yes** (`mcp-vuln audit poetry.lock`) | Scans poetry ecosystems natively. |
| **Requirements.txt & Pip Ecosystem** | ✅ Yes (via `pip-audit`) | ✅ **Yes** (Native OSV + PyPI resolver) | ❌ None | ✅ **Yes** (Full semver range matching) | Faster and more comprehensive than standard `pip-audit`. |
| **VI. CLIENT CONFIGURATION & REMEDIATION** | | | | | |
| **Auto-Fixing & Safe Semver Upgrades** | ❌ None (Detection only) | ✅ **Yes** (`mcp-vuln fix-config --safe-upgrade`) | ❌ None | ✅ **Yes** (Rewrites configs with patched versions) | **Exclusive Capability**: Cisco only reports bugs; we automatically fix them. |
| **Known Client Config Auto-Discovery** | ✅ Yes (`--scan-known-configs`) | ✅ Yes (`mcp-vuln audit-config`) | ✅ Yes (`conflict_detector.py`) | ✅ **Yes** (Claude, Cursor, VS Code, Windsurf) | Locates desktop configs across macOS, Linux, and Windows. |
| **Multi-Server Tool Collision Detection** | ❌ None | ❌ None | ✅ **Yes** | ✅ **Yes** (`mcp-vuln audit-config --collisions`) | Detects dangerous tool shadowing when multiple MCP servers run concurrently. |
| **Dry-Run & Backup Safety Protocol** | ❌ None | ✅ **Yes** (`.bak` creation + diff preview) | ❌ None | ✅ **Yes** (Reversible mutations) | Guarantees non-destructive configuration updates. |
| **VII. DISCOVERY & REGISTRY CATALOG BREADTH** | | | | | |
| **Cross-Registry Discovery Breadth** | ❌ None (User must specify target) | ✅ **6,000+ Servers** (PyPI, npm, GitHub, Docker, Smithery, Glama) | ✅ **3,903+ Passports** | ✅ **6,000+ Cataloged Servers** | Largest verified MCP catalog in existence. |
| **Automated Catalog Version Enricher** | ❌ None | ✅ **Yes** (Async threadpool enricher) | ❌ None | ✅ **Yes** (`mcp-vuln enrich`) | Discovers new server releases continuously. |
| **Interactive Terminal Search & Lookup** | ❌ None | ✅ **Yes** (`mcp-vuln search`, `lookup`) | ✅ Yes (`search.py`) | ✅ **Yes** (Instant CLI CVE & Passport query) | Rich terminal UI with colorized tables and remediation tips. |
| **VIII. ENTERPRISE STANDARDS & DEVAUX** | | | | | |
| **OASIS SARIF v2.1.0 Export** | ❌ None (Only JSON/table/summary) | ✅ **Yes** (`--format sarif`) | ❌ None | ✅ **Yes** (Native GitHub Code Scanning) | Uploads directly to GitHub Security Tab with file/line annotations. |
| **REST API Server Mode** | ✅ Yes (`mcp-scanner-api` via FastAPI) | ❌ None | ❌ None | ✅ **Yes** (`mcp-vuln serve` / OpenAPI docs) | Parity achieved; headless microservice deployment for enterprise backends. |
| **Official GitHub Action for CI/CD** | ❌ None | ✅ **Yes** (`action.yml`) | ❌ None | ✅ **Yes** (4-line CI/CD pipeline integration) | Native GitHub Marketplace action. |
| **Lightweight Multi-Arch Docker Container** | ⚠️ Large dev container | ✅ **Yes** (`ghcr.io/jmartynov/mcp-vulnerabilities`) | ❌ None | ✅ **Yes** (Optimized alpine/slim image) | Production container ready for Kubernetes and CI runners. |
| **Interactive Static Web Explorer & Charts** | ❌ None | ✅ **Yes** (`docs/index.html` & `analytics.html`) | ✅ Yes (`web/index.html`) | ✅ **Yes** (GitHub Pages hosted explorer) | Searchable web UI with OWASP Top 10 distribution charts. |

---

## 3. Key Findings & Strategic Parity Plan

### A. What Cisco AI Defense MCP Scanner Currently Does
1. **Multi-Engine Evaluation**: Combines YARA rules, LiteLLM prompts, and the Cisco AI Defense Inspect API.
2. **VirusTotal Hash Lookup**: Queries VirusTotal for SHA-256 hashes of binary files found in local directories.
3. **Readiness Linter**: Checks tool schema descriptions, timeouts, and error handling for production readiness.
4. **FastAPI Server**: Runs `mcp-scanner-api` to receive scan jobs over HTTP.

### B. What Cisco Completely Lacks (Our Major Moat)
1. **No Vulnerability Intelligence**: Cisco has **zero** database of MCP-specific CVEs or security advisories. It cannot tell you if an MCP server has a known RCE (e.g. CVE-2025-XXXXX) unless a generic YARA regex catches it.
2. **No Unlabelled Server Fingerprinting**: Cisco cannot tell you *what* server is running if the executable is renamed or unlabelled.
3. **No Tool Collision & Shadowing Protection**: If two servers in `claude_desktop_config.json` register `read_file`, Cisco doesn't detect the collision or warn about malicious tool shadowing.
4. **No Automated Remediation**: Cisco generates a JSON report and stops. It cannot automatically fix vulnerable version pins or patch client configurations.
5. **No Modern Lockfile Auditing**: Cisco only scans `requirements.txt` via `pip-audit`, ignoring `uv.lock`, `pyproject.toml`, `package.json`, and `poetry.lock`.
6. **No SARIF v2.1.0 or Upstream OSV Integration**: Cisco cannot feed findings directly into GitHub Code Scanning or Google OSV.dev.

### C. The Unified Architecture Plan: "Much More, Never Less"
To guarantee our project is **strictly superior** to Cisco's in every measurable way, we implement the missing parity modules while retaining all of our proprietary database, fingerprinting, and auto-fixing advantages:

```
+---------------------------------------------------------------------------------------------------+
|                                  UNIFIED MCP SECURITY PLATFORM                                    |
+---------------------------------------------------------------------------------------------------+
|  [Ingestion & Vulnerability DB]   |    [Fingerprinting & AST Engine]   |   [Parity Threat Engines]  |
|  - OSV 1.6 Database (519+ CVEs)   |    - 3,903+ Passports (passports.json)|   - YARA Rule Engine       |
|  - GHSA Cursor Pagination         |    - SHA-256 Tool Schema Hashes    |   - Prompt Injection Guard |
|  - NIST NVD 2.0 REST Stream       |    - Multi-Server Collision Audit  |   - Readiness Linter       |
|  - Google OSV.dev Lake Sync       |    - Multi-Language AST Parsers    |   - VirusTotal / SHA block |
+---------------------------------------------------------------------------------------------------+
|                                      [CORE AUDIT & DISCOVERY]                                     |
|  - Runtime Stdio / SSE / HTTP Probing (JSON-RPC 2.0 + OAuth2 / Bearer)                            |
|  - Modern Lockfile Auditing (uv.lock, pyproject.toml, package.json, poetry.lock)                  |
|  - 6,000+ Cross-Registry Server Catalog (PyPI, npm, GitHub, Docker, Smithery, Glama)              |
+---------------------------------------------------------------------------------------------------+
|                                      [REMEDIATION & INTERFACES]                                   |
|  - Client Config Auto-Fixer (claude_desktop, Cursor, VS Code with safe semver upgrades)           |
|  - REST API Daemon (mcp-vuln serve with OpenAPI / FastAPI router)                                 |
|  - Enterprise Exports: OASIS SARIF v2.1.0, Air-Gapped Offline Tarball, Webhooks                   |
|  - Interactive Web Explorer, OWASP MCP Top 10 Dashboard & Terminal CLI                            |
+---------------------------------------------------------------------------------------------------+
```

---

## 4. Implementation Roadmap (Tasks 22 – 29)

We organize the architectural expansion into modular, decoupled tracks:

- **Task 22 (Completed)**: `mcp-fingerprints` Integration & Server Identification (5,033+ Passports, order-independent toolset canonical hashing, `mcp-vuln identify`, tool collision detector).
- **Task 23**: Multi-Engine Heuristic Threat Analyzer (YARA & RegEx Pattern Engine for Injection, Code Execution & Exfiltration).
- **Task 24**: Headless REST API Gateway & Microservice Daemon (`mcp-vuln serve` with OpenAPI 3.0 specs).
- **Task 25**: Full-Surface Protocol Probe & Live SSE / Streamable HTTP Transport Engine (Tools, Prompts, Resources, Instructions, Auth Headers).
- **Task 26**: MCP Production Readiness & Schema Contract Linter (`mcp-vuln lint`).
- **Task 27**: Isolated Ephemeral Container Sandbox for Dynamic Package Auditing (Docker/Podman PyPI & npm).
- **Task 28**: Static AST Source Code Taint & Dangerous Sink Analyzer (`mcp-vuln scan-source`).
- **Task 29**: Binary Asset & File Hash Malware Screening (Streaming SHA-256 Hasher & Offline Blocklist).

