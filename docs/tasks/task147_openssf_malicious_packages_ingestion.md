# Task 147: OpenSSF Malicious Packages Ingestion, Backdoor Detection & Quarantine (P0)

**Subsystem:** Supply Chain Defense & Threat Intelligence (`src/mcp_vulnerabilities/threat_intel/openssf_malicious.py`, `src/mcp_vulnerabilities/converters/openssf.py`, `src/mcp_vulnerabilities/pipeline.py`, `src/mcp_vulnerabilities/analyzers/typosquat/detector.py`, `src/mcp_vulnerabilities/cli.py`, `docs/app.js`, `docs/style.css`)  
**Priority:** `P0`  
**Target Wave:** Wave 27 (Threat Intelligence, Exploit Prediction & Multi-Source Deduplication)  
**Parent Plan:** [master_plan_wave27_threat_intel_exploit_prediction_and_deduplication.md](master_plan_wave27_threat_intel_exploit_prediction_and_deduplication.md)

---

## 1. Objective & Problem Statement

Model Context Protocol (MCP) servers run with high privileges on developer workstations and enterprise infrastructure, executing tools, issuing shell commands, and accessing local files and databases. Consequently, they represent an extraordinarily attractive target for supply chain poisoning.

Unlike conventional software bugs or vulnerabilities (which are unintentional coding errors cataloged in CVEs and GHSAs), **malicious packages** are deliberately planted malware:
- Infostealers exfiltrating `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, AWS credentials, and SSH keys.
- Reverse shells and remote access trojans (RATs) embedded in setup scripts (`setup.py`, `postinstall`).
- Typosquatted packages designed to impersonate popular MCP tools (e.g. `mcp-server-git-hub` vs `mcp-server-github`).

The **OpenSSF (Open Source Security Foundation) Malicious Packages repository** (`github.com/ossf/malicious-packages`) is the authoritative industry database documenting thousands of confirmed malicious releases across npm, PyPI, RubyGems, and other registries using the OSV schema with `MAL-*` identifiers.

Currently, `mcp-vulnerabilities`:
1. Focuses primarily on accidental CVE/GHSA flaws, leaving users and automated AI agents exposed to actual malware.
2. Allows malicious packages that match discovery keywords to potentially enter catalog listings without an immediate quarantine filter.
3. Lacks unbypassable blocking in CLI configuration generators and web portal basket exporters.

Task 147 implements an end-to-end **OpenSSF Malicious Packages Synchronization, Backdoor Detection, and Active Quarantine Subsystem**.

---

## 2. Detailed Technical Requirements

### 2.1 OpenSSF Ingestion & Normalization (`src/mcp_vulnerabilities/threat_intel/openssf_malicious.py`, `converters/openssf.py`)

Implement `OpenSsfMaliciousSync`:

1. **Upstream Ingestion Channels**:
   - Primary: Daily sync from OSV Google Cloud Storage ecosystem feeds (`https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip`, `PyPI/all.zip`) filtering records matching `id.startswith("MAL-")`.
   - Secondary: Git shallow clone or archive download from `https://github.com/ossf/malicious-packages` (`osv/malicious/npm/` and `osv/malicious/pypi/`).
   - Store local normalized index in `data/malicious_packages.json`.
2. **Schema Normalization (`converters/openssf.py`)**:
   - Parse OpenSSF OSV records into `MaliciousPackageRecord`:
     ```python
     @dataclass(frozen=True)
     class MaliciousPackageRecord:
         id: str                      # "MAL-2026-1042"
         ecosystem: str               # "npm" | "PyPI"
         package_name: str
         summary: str
         details: str
         published: str
         modified: str
         source_origin: str           # "ghsa_malware" | "checkmarx" | "reversinglabs" | "datadog"
         affected_versions: list[str]
         ranges: list[dict]
         aliases: list[str]
     ```
   - Extract threat origin telemetry from `database_specific.malicious-packages-origins`.
3. **Lookup Engine**:
   - `is_malicious_package(ecosystem: str, package_name: str, version: str | None = None) -> bool`:
     - Checks if package name matches a known malicious package.
     - If `version` is specified, checks if the specific version falls within affected ranges. If affected ranges are omitted or universal (`0.0.0` to `*`), all versions are considered poisoned.

---

### 2.2 Catalog Quarantine & Pipeline Defense (`src/mcp_vulnerabilities/pipeline.py`)

1. **Catalog Screening**:
   - During `VulnerabilityPipeline.sync_all()`:
     - Run candidate MCP packages discovered via npm and PyPI against `OpenSsfMaliciousSync`.
     - If a package is flagged as malicious:
       - **NEVER** recommend or list it in `docs/data/mcp_catalog_index.json` as a healthy server.
       - Quarantine the record in `data/quarantined_malicious_servers.json`.
       - Record an unbypassable tombstone in `McpCatalogState` with `reason="malicious_package"`.
2. **Attestation & Passports**:
   - Any server in `passports.json.gz` with a matching malicious record must have:
     ```json
     "is_malicious": true,
     "quarantine_tier": "MALICIOUS",
     "composite_risk_score": 10.0,
     "malicious_advisory_id": "MAL-2026-1042"
     ```

---

### 2.3 Hardened CLI Defense (`src/mcp_vulnerabilities/cli.py`, `src/mcp_vulnerabilities/audit/reporters.py`)

1. **Critical Policy Violation Exit Code (Exit Code 2)**:
   - When running `mcp-vuln audit` against local configuration files:
     - If ANY package is flagged as a known malicious package, output a high-visibility terminal banner and exit with status code `2` (Policy Violation):
       ```
       ================================================================================
       ☠️ CRITICAL ALERT: MALICIOUS SUPPLY CHAIN PACKAGE DETECTED
       ================================================================================
       The following installed package is flagged as deliberate MALWARE by OpenSSF:
         Package:   mcp-tool-stealer (npm)
         Advisory:  MAL-2026-1042
         Origin:    ReversingLabs Threat Intelligence
         Details:   Contains embedded reverse shell harvesting AWS and Anthropic keys.
       ACTION REQUIRED: Immediately terminate all processes and revoke credentials!
       ================================================================================
       ```
2. **Auto-Fixer Quarantine Refusal (`mcp-vuln fix-config`)**:
   - `mcp-vuln fix-config` must refuse to update or keep malicious servers in AI client configurations.
   - It must automatically comment out or remove the malicious entry from `claude_desktop_config.json`, appending a `# QUARANTINED: MALICIOUS PACKAGE` notice.

---

### 2.4 Web Portal Visualization (`docs/app.js`, `docs/style.css`)

1. **Quarantine Block on Configuration Basket**:
   - In `docs/app.js`: If a server is marked `is_malicious: true`:
     - Disable the `+ Add to Basket` button completely, rendering a disabled `<button class="btn btn-quarantined" disabled>☠️ Malicious (Quarantined)</button>`.
     - Clicking the card opens a prominent modal alert explaining the malware classification and displaying OpenSSF/ReversingLabs disclosure notes.
2. **Dark Crimson Styling (`docs/style.css`)**:
   - `.btn-quarantined`: Deep red/crimson background (`#991b1b`), white text, cursor `not-allowed`.
   - `.malicious-callout`: Border `2px solid #ef4444`, background `rgba(239, 68, 68, 0.20)`.

---

## 3. Invariant Requirements & Verification Plan

### 3.1 Verification Invariants

- [ ] **INVARIANT_147_1 (Absolute Catalog Quarantine)**: Any package confirmed in OpenSSF Malicious Packages must NEVER appear as an active recommended server in `mcp_catalog_index.json`.
- [ ] **INVARIANT_147_2 (Maximal Composite Score Override)**: A confirmed malicious package MUST receive an unconditional composite risk score of `10.0` and tier `MALICIOUS`.
- [ ] **INVARIANT_147_3 (CLI Exit Code 2 Enforcement)**: Running `mcp-vuln audit` against a configuration containing a malicious package MUST output the red alert banner and terminate with exit code `2`.
- [ ] **INVARIANT_147_4 (Export Basket Neutralization)**: The web portal basket exporter and `mcp-vuln fix-config` MUST NOT generate executable client JSON configurations containing malicious servers.
- [ ] **INVARIANT_147_5 (Deterministic Ecosystem Scoping)**: Package name matching must be strictly scoped to ecosystem (e.g. an npm malicious package named `foo` does not quarantine PyPI `foo` unless also listed on PyPI).

### 3.2 Automated Test Suite (`tests/test_openssf_malicious_ingestion.py`)

Author a dedicated test suite with the following tests:
1. `test_openssf_osv_normalization`: Parses a real OpenSSF OSV JSON record and verifies all attributes map into `MaliciousPackageRecord`.
2. `test_ecosystem_scoped_lookup`: Verifies `is_malicious_package` distinguishes between npm and PyPI namespaces.
3. `test_pipeline_quarantine_exclusion`: Simulates discovery of a malicious npm package and asserts it is written to `quarantined_malicious_servers.json` and excluded from `mcp_catalog_index.json`.
4. `test_cli_audit_exit_code_2_on_malware`: Mocks a client configuration referencing a malicious package and asserts `mcp-vuln audit` exits with code 2.
5. `test_fix_config_quarantine_removal`: Verifies `mcp-vuln fix-config` strips malicious packages from client JSON configs.
6. `test_web_basket_quarantine_disabled`: Verifies `docs/app.js` renders a disabled button and blocks adding malicious servers to the basket.

---

## 4. Deliverables & Integration Checklist

- [ ] Implement `src/mcp_vulnerabilities/threat_intel/openssf_malicious.py` (`OpenSsfMaliciousSync`).
- [ ] Implement `src/mcp_vulnerabilities/converters/openssf.py` (OSV `MAL-*` normalizer).
- [ ] Integrate malicious screening and quarantine tombstones into `src/mcp_vulnerabilities/pipeline.py`.
- [ ] Add exit code 2 handling and malware alert formatting in `src/mcp_vulnerabilities/cli.py` and `reporters.py`.
- [ ] Harden `src/mcp_vulnerabilities/audit/fixer.py` to remove malicious packages during configuration repair.
- [ ] Implement quarantined button styling and modal warning in `docs/app.js` and `docs/style.css`.
- [ ] Add nightly OpenSSF sync step to `.github/workflows/daily_sync.yml`.
- [ ] Author test suite `tests/test_openssf_malicious_ingestion.py` and verify all tests pass.
- [ ] Update `docs/SPECIFICATION.md` and `README.md` reflecting supply chain malware defenses.
