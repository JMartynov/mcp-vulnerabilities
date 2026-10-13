# Task Specification: CycloneDX 1.6 & SPDX 3.0 AI-BOM Exporter (P1-2)

## Objective
Implement an enterprise Software Bill of Materials (SBOM) generator supporting **CycloneDX 1.6** and **SPDX 3.0 AI profiles**. Enables security teams to export comprehensive AI-BOMs documenting all active MCP servers, tools, input schemas, cryptographic hashes, dependency packages, licenses, and Vulnerability Exploitability eXchange (VEX) statuses via `mcp-vuln audit-config --format cyclonedx` and `mcp-vuln probe --format cyclonedx`.

## Target Files
- `src/mcp_vulnerabilities/sbom/` (`__init__.py`, `cyclonedx.py`, `models.py`)
- `src/mcp_vulnerabilities/cli.py`
- `tests/test_cyclonedx_sbom.py`
- `tests/test_acceptance_sbom.py`

## Implementation Details
1. **Create `src/mcp_vulnerabilities/sbom/cyclonedx.py`**:
   - Implement `CycloneDxBomBuilder`:
     - Generates valid CycloneDX 1.6 JSON specification (`bomFormat: "CycloneDX"`, `specVersion: "1.6"`).
     - Models MCP servers as `service` components (`type: "application"` or `type: "framework"`).
     - Models individual MCP tools as `endpoints` under services or distinct `tool` components.
     - Includes cryptographic hashes (SHA-256 canonical toolset hashes from passport matcher).
     - Embeds Vulnerability Exploitability eXchange (VEX) elements under `vulnerabilities` array, citing OSV IDs, CVSS scores, and analysis status (`affects`, `not_affected`, `fixed`).
     - Includes software components (PyPI packages, npm packages) discovered from client configuration files or runtime inspection.
2. **CLI Integration**:
   - Add `--format cyclonedx` (and alias `--format sbom`) to `mcp-vuln audit-config`, `mcp-vuln probe`, and `mcp-vuln identify`.
   - Output valid, formatted JSON.
3. **Validation**:
   - Verify output contains mandatory CycloneDX 1.6 fields (`serialNumber`, `version`, `metadata`, `components`, `services`, `dependencies`, `vulnerabilities`).

## Acceptance Criteria (100% Live & Unmocked)
1. **Live CycloneDX Generation Test (`tests/test_acceptance_sbom.py`)**:
   - Run `mcp-vuln audit-config --format cyclonedx` against a real multi-server client configuration (e.g. Claude Desktop config with 3+ servers).
   - Parse the JSON output and verify:
     - Top-level schema matches `http://cyclonedx.org/schema/bom-1.6.schema.json`.
     - Declares `services` with tool endpoints.
     - Lists discovered vulnerabilities under `vulnerabilities` array with valid OSV/CVE references.
2. **Deterministic Hash Invariant**:
   - Ensure the SHA-256 component hashes in the BOM match the canonical toolset hashes from `data/passports.json.gz`.
3. All unit tests in `tests/test_cyclonedx_sbom.py` pass.

## Non-Interactive Completion Directive
Execute all changes, write tests, run the test suite, ensure all tests pass with zero errors, and commit cleanly without asking interactive questions.
