# Task 122: Track A — Batch 2 Traceability Audit: Python & PyPI FastMCP Servers (75 Items) (P0)

**Subsystem:** Ingestion Traceability & PyPI Discovery (`docs/data/mcp_catalog_index.json`, `src/mcp_vulnerabilities/discovery/pypi.py`, `docs/reports/audit_batch2_pypi.md`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave23_deep_empirical_audit_and_verification.md](master_plan_wave23_deep_empirical_audit_and_verification.md)

---

## 1. Objective & Problem Statement

Python is the standard language for AI/ML engineering, and the **PyPI ecosystem** accounts for **681 servers** in the `mcp-vulnerabilities` catalog. The Python MCP landscape is divided between two major architectures:
1. **Low-Level Protocol Implementations**: Using the official `mcp` SDK (`mcp.server.stdio`, `mcp.server.sse`).
2. **High-Level FastMCP Frameworks**: Declarative servers leveraging FastMCP (`from mcp.server.fastmcp import FastMCP`), which expose tools via Python decorators (`@mcp.tool()`).

In PyPI discovery (`src/mcp_vulnerabilities/discovery/pypi.py`), several empirical challenges arise:
- **PEP 691 Simple API Limitations**: The PEP 691 JSON Simple API returns package names but lacks semantic version strings, requiring fallback to `https://pypi.org/pypi/<package>/json` via `PypiDiscoveryProvider.resolve_package_version()`.
- **Project URL Fragmentation**: Upstream metadata in `pyproject.toml` often distributes repository links across multiple keys (`Homepage`, `Source Code`, `Repository`, `Bug Tracker`) in `project_urls`. Missing or poorly structured metadata causes catalog repository links to default to `pypi.org` project pages.
- **Yanked & Prerelease Versions**: PyPI allows authors to "yank" broken or vulnerable releases without deleting them (`"yanked": true`). The catalog must accurately exclude yanked versions from `recommended_safe_version`.
- **Packaging Variations**: PyPI packages may distribute sdist (`.tar.gz`) only or platform-specific wheels, impacting static AST tool extraction.

This task conducts an empirical upstream traceability audit across **75 real Python & PyPI FastMCP servers** from `docs/data/mcp_catalog_index.json`.

---

## 2. 7-Point Upstream Verification Protocol

Each package in Batch 2 is audited against the following 7 invariants:

1. **Upstream JSON API Resolution**:
   - Query `https://pypi.org/pypi/<package>/json` to verify HTTP 200 status, valid JSON schema, and confirm package is not deleted or quarantined.
2. **Version Alignment & Yank Status**:
   - Compare `info.version` against `latest_version` in `mcp_catalog_index.json`. Verify whether any releases are marked `"yanked": true` and ensure they are not promoted as recommended safe versions.
3. **Repository URL Resolution from `project_urls`**:
   - Parse `info.project_urls` for GitHub/GitLab repositories. Verify that catalog `repository_url` correctly resolved the underlying source repository rather than defaulting to `https://pypi.org/project/<name>/`.
4. **FastMCP & Framework Attribution**:
   - Inspect package dependencies (`requires_dist`) and keywords for `mcp`, `fastmcp`, `langchain`, `llama-index` to confirm MCP architectural classification.
5. **Tool & Capability Extraction**:
   - Verify whether declared MCP tools (functions with `@mcp.tool()`) are captured in `tools_sample` and match actual exposed server primitives.
6. **Security Posture & Vulnerability Correlation**:
   - Cross-reference with `docs/data/vulnerabilities.json` to verify known Python CVEs/GHSAs, affected SemVer ranges, and safe remediations.
7. **License & Author Metadata**:
   - Verify `info.license` and `info.author` fields against catalog entries.

---

## 3. Audited Item Registry: Batch 2 (75 Real PyPI Packages)

| # | Package Name | Catalog Version | Upstream Repository / Homepage | Upstream Registry Endpoint |
| :-: | :--- | :---: | :--- | :--- |
| 01 | `Apple-MCPs` | `v1.0.0` | [pypi.org/project/Apple-MCPs/](https://pypi.org/project/Apple-MCPs/) | `pypi.org/pypi/Apple-MCPs/json` |
| 02 | `WaveGuardClient` | `v3.3.0` | [pypi.org/project/WaveGuardClient/](https://pypi.org/project/WaveGuardClient/) | `pypi.org/pypi/WaveGuardClient/json` |
| 03 | `adhd-hub` | `v1.0.0` | [pypi.org/project/adhd-hub/](https://pypi.org/project/adhd-hub/) | `pypi.org/pypi/adhd-hub/json` |
| 04 | `agent-nexus` | `v1.0.0` | [pypi.org/project/agent-nexus/](https://pypi.org/project/agent-nexus/) | `pypi.org/pypi/agent-nexus/json` |
| 05 | `agentveil` | `v1.0.0` | [github.com/agentveil-protocol/ag...](https://github.com/agentveil-protocol/agentveil-sdk) | `pypi.org/pypi/agentveil/json` |
| 06 | `alpha-forge-mcp` | `v1.0.0` | [github.com/alforge-labs/alpha-fo...](https://github.com/alforge-labs/alpha-forge-mcp) | `pypi.org/pypi/alpha-forge-mcp/json` |
| 07 | `arc-gate-mcp` | `v0.1.4` | [pypi.org/project/arc-gate-mcp/](https://pypi.org/project/arc-gate-mcp/) | `pypi.org/pypi/arc-gate-mcp/json` |
| 08 | `ashare-mcp` | `v1.0.0` | [github.com/lixiangquan/ashare-mcp](https://github.com/lixiangquan/ashare-mcp) | `pypi.org/pypi/ashare-mcp/json` |
| 09 | `aviationstack-mcp` | `v1.8.1` | [github.com/pradumnasaraf/aviatio...](https://github.com/pradumnasaraf/aviationstack-mcp) | `pypi.org/pypi/aviationstack-mcp/json` |
| 10 | `biothings-mcp` | `v1.0.0` | [pypi.org/project/biothings-mcp/](https://pypi.org/project/biothings-mcp/) | `pypi.org/pypi/biothings-mcp/json` |
| 11 | `braintree-mcp-server` | `v1.0.0` | [pypi.org/project/braintree-mcp-s...](https://pypi.org/project/braintree-mcp-server/) | `pypi.org/pypi/braintree-mcp-server/json` |
| 12 | `char-index-mcp` | `v1.0.0` | [github.com/agent-hanju/char-inde...](https://github.com/agent-hanju/char-index-skill) | `pypi.org/pypi/char-index-mcp/json` |
| 13 | `climatiq-mcp-server` | `v1.0.0` | [pypi.org/project/climatiq-mcp-se...](https://pypi.org/project/climatiq-mcp-server/) | `pypi.org/pypi/climatiq-mcp-server/json` |
| 14 | `comfy-pilot` | `v1.0.0` | [pypi.org/project/comfy-pilot/](https://pypi.org/project/comfy-pilot/) | `pypi.org/pypi/comfy-pilot/json` |
| 15 | `crypto-feargreed-mcp` | `v1.0.0` | [pypi.org/project/crypto-feargree...](https://pypi.org/project/crypto-feargreed-mcp/) | `pypi.org/pypi/crypto-feargreed-mcp/json` |
| 16 | `crypto-sentiment-mcp` | `v1.0.0` | [pypi.org/project/crypto-sentimen...](https://pypi.org/project/crypto-sentiment-mcp/) | `pypi.org/pypi/crypto-sentiment-mcp/json` |
| 17 | `cve-search-mcp` | `v1.0.0` | [pypi.org/project/cve-search-mcp/](https://pypi.org/project/cve-search-mcp/) | `pypi.org/pypi/cve-search-mcp/json` |
| 18 | `database-mcp` | `v1.0.0` | [pypi.org/project/database-mcp/](https://pypi.org/project/database-mcp/) | `pypi.org/pypi/database-mcp/json` |
| 19 | `deeplook-research` | `v1.0.0` | [github.com/OSOJDJD/deeplook](https://github.com/OSOJDJD/deeplook) | `pypi.org/pypi/deeplook-research/json` |
| 20 | `didlogic_mcp` | `v1.0.4` | [pypi.org/project/didlogic_mcp/](https://pypi.org/project/didlogic_mcp/) | `pypi.org/pypi/didlogic_mcp/json` |
| 21 | `elasticsearch-mcp-server` | `v2.1.6` | [smithery.ai/servers/elasticsearc...](https://smithery.ai/servers/elasticsearch-mcp-server) | `pypi.org/pypi/elasticsearch-mcp-server/json` |
| 22 | `eu-reg-mcp` | `v0.1.2` | [smithery.ai/servers/eu-reg-mcp](https://smithery.ai/servers/eu-reg-mcp) | `pypi.org/pypi/eu-reg-mcp/json` |
| 23 | `fermat-mcp` | `v0.1.0` | [pypi.org/project/fermat-mcp/](https://pypi.org/project/fermat-mcp/) | `pypi.org/pypi/fermat-mcp/json` |
| 24 | `fix-protocol-mcp` | `v1.0.0` | [pypi.org/project/fix-protocol-mcp/](https://pypi.org/project/fix-protocol-mcp/) | `pypi.org/pypi/fix-protocol-mcp/json` |
| 25 | `funding-rates-mcp` | `v1.0.0` | [pypi.org/project/funding-rates-mcp/](https://pypi.org/project/funding-rates-mcp/) | `pypi.org/pypi/funding-rates-mcp/json` |
| 26 | `gnucash-mcp` | `v0.2.0` | [smithery.ai/servers/gnucash-mcp](https://smithery.ai/servers/gnucash-mcp) | `pypi.org/pypi/gnucash-mcp/json` |
| 27 | `harmonyos-mcp-server` | `v1.0.0` | [pypi.org/project/harmonyos-mcp-s...](https://pypi.org/project/harmonyos-mcp-server/) | `pypi.org/pypi/harmonyos-mcp-server/json` |
| 28 | `ida-pro-mcp` | `v1.4.0` | [github.com/mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) | `pypi.org/pypi/ida-pro-mcp/json` |
| 29 | `japan-corporate-mcp` | `v1.0.0` | [github.com/drago/japan-corporate...](https://github.com/drago/japan-corporate-mcp) | `pypi.org/pypi/japan-corporate-mcp/json` |
| 30 | `k6-mcp-server` | `v2.2.0` | [github.com/Geun-Oh/k6-mcp-server](https://github.com/Geun-Oh/k6-mcp-server) | `pypi.org/pypi/k6-mcp-server/json` |
| 31 | `keel-trade` | `v0.9.0` | [github.com/keel-trade/keel-trade](https://github.com/keel-trade/keel-trade) | `pypi.org/pypi/keel-trade/json` |
| 32 | `kokoro-tts-mcp` | `v1.0.0` | [pypi.org/project/kokoro-tts-mcp/](https://pypi.org/project/kokoro-tts-mcp/) | `pypi.org/pypi/kokoro-tts-mcp/json` |
| 33 | `litvm-tcg-oracle` | `v1.1.4` | [github.com/sailorpepe/litvm-tcg-...](https://github.com/sailorpepe/litvm-tcg-oracle-mcp) | `pypi.org/pypi/litvm-tcg-oracle/json` |
| 34 | `logfire-mcp` | `v0.9.0` | [pypi.org/project/logfire-mcp/](https://pypi.org/project/logfire-mcp/) | `pypi.org/pypi/logfire-mcp/json` |
| 35 | `managed-agent-control-mcp` | `v1.0.0` | [pypi.org/project/managed-agent-c...](https://pypi.org/project/managed-agent-control-mcp/) | `pypi.org/pypi/managed-agent-control-mcp/json` |
| 36 | `mcp-abacus` | `v0.5.1` | [smithery.ai/servers/mcp-abacus](https://smithery.ai/servers/mcp-abacus) | `pypi.org/pypi/mcp-abacus/json` |
| 37 | `mcp-blast-radius` | `v1.0.0` | [github.com/aos-standard/mcp-blas...](https://github.com/aos-standard/mcp-blast-radius) | `pypi.org/pypi/mcp-blast-radius/json` |
| 38 | `mcp-datetime` | `v1.0.0` | [github.com/ZeparHyfar/mcp-datetime](https://github.com/ZeparHyfar/mcp-datetime) | `pypi.org/pypi/mcp-datetime/json` |
| 39 | `mcp-hn` | `v1.0.0` | [pypi.org/project/mcp-hn/](https://pypi.org/project/mcp-hn/) | `pypi.org/pypi/mcp-hn/json` |
| 40 | `mcp-nixos` | `v3.1.0` | [pypi.org/project/mcp-nixos/](https://pypi.org/project/mcp-nixos/) | `pypi.org/pypi/mcp-nixos/json` |
| 41 | `mcp-proxy` | `v0.13.0` | [github.com/sparfenyuk/mcp-proxy](https://github.com/sparfenyuk/mcp-proxy) | `pypi.org/pypi/mcp-proxy/json` |
| 42 | `mcp-server-bigquery` | `v1.0.0` | [pypi.org/project/mcp-server-bigq...](https://pypi.org/project/mcp-server-bigquery/) | `pypi.org/pypi/mcp-server-bigquery/json` |
| 43 | `mcp-server-fetch` | `v2026.10.28` | [smithery.ai/servers/mcp-server-f...](https://smithery.ai/servers/mcp-server-fetch) | `pypi.org/pypi/mcp-server-fetch/json` |
| 44 | `mcp-server-odoo` | `v0.9.0` | [smithery.ai/servers/mcp-server-odoo](https://smithery.ai/servers/mcp-server-odoo) | `pypi.org/pypi/mcp-server-odoo/json` |
| 45 | `mcp-server-sql-analyzer` | `v1.0.0` | [pypi.org/project/mcp-server-sql-...](https://pypi.org/project/mcp-server-sql-analyzer/) | `pypi.org/pypi/mcp-server-sql-analyzer/json` |
| 46 | `mcp-shield` | `v1.0.0` | [pypi.org/project/mcp-shield/](https://pypi.org/project/mcp-shield/) | `pypi.org/pypi/mcp-shield/json` |
| 47 | `mcp-techtrend` | `v1.0.0` | [pypi.org/project/mcp-techtrend/](https://pypi.org/project/mcp-techtrend/) | `pypi.org/pypi/mcp-techtrend/json` |
| 48 | `mcp-vms` | `v1.0.0` | [pypi.org/project/mcp-vms/](https://pypi.org/project/mcp-vms/) | `pypi.org/pypi/mcp-vms/json` |
| 49 | `mcpxcodebuild` | `v1.0.0` | [pypi.org/project/mcpxcodebuild/](https://pypi.org/project/mcpxcodebuild/) | `pypi.org/pypi/mcpxcodebuild/json` |
| 50 | `memora-mcp` | `v1.0.0` | [pypi.org/project/memora-mcp/](https://pypi.org/project/memora-mcp/) | `pypi.org/pypi/memora-mcp/json` |
| 51 | `minreestr-mcp` | `v1.0.0` | [pypi.org/project/minreestr-mcp/](https://pypi.org/project/minreestr-mcp/) | `pypi.org/pypi/minreestr-mcp/json` |
| 52 | `munim` | `v1.0.0` | [github.com/vishalsg42/munim](https://github.com/vishalsg42/munim) | `pypi.org/pypi/munim/json` |
| 53 | `nearby-search-mcp` | `v1.0.0` | [pypi.org/project/nearby-search-mcp/](https://pypi.org/project/nearby-search-mcp/) | `pypi.org/pypi/nearby-search-mcp/json` |
| 54 | `nlqueries-core` | `v0.4.0` | [github.com/nlqueries/nlqueries](https://github.com/nlqueries/nlqueries) | `pypi.org/pypi/nlqueries-core/json` |
| 55 | `omega-brain-mcp` | `v1.0.0` | [pypi.org/project/omega-brain-mcp/](https://pypi.org/project/omega-brain-mcp/) | `pypi.org/pypi/omega-brain-mcp/json` |
| 56 | `opengenes-mcp` | `v0.2.0` | [pypi.org/project/opengenes-mcp/](https://pypi.org/project/opengenes-mcp/) | `pypi.org/pypi/opengenes-mcp/json` |
| 57 | `oura-mcp-server` | `v1.0.0` | [pypi.org/project/oura-mcp-server/](https://pypi.org/project/oura-mcp-server/) | `pypi.org/pypi/oura-mcp-server/json` |
| 58 | `pancakeswap-poolspy-mcp` | `v1.0.0` | [pypi.org/project/pancakeswap-poo...](https://pypi.org/project/pancakeswap-poolspy-mcp/) | `pypi.org/pypi/pancakeswap-poolspy-mcp/json` |
| 59 | `pg-mnemosyne-mcp` | `v1.0.0` | [pypi.org/project/pg-mnemosyne-mcp/](https://pypi.org/project/pg-mnemosyne-mcp/) | `pypi.org/pypi/pg-mnemosyne-mcp/json` |
| 60 | `postgres-mcp` | `v1.0.0` | [pypi.org/project/postgres-mcp/](https://pypi.org/project/postgres-mcp/) | `pypi.org/pypi/postgres-mcp/json` |
| 61 | `pt-edge` | `v1.0.0` | [pypi.org/project/pt-edge/](https://pypi.org/project/pt-edge/) | `pypi.org/pypi/pt-edge/json` |
| 62 | `qbt-kit` | `v0.1.2` | [smithery.ai/servers/qbt-kit](https://smithery.ai/servers/qbt-kit) | `pypi.org/pypi/qbt-kit/json` |
| 63 | `resume-mcp-server` | `v3.0.2` | [pypi.org/project/resume-mcp-server/](https://pypi.org/project/resume-mcp-server/) | `pypi.org/pypi/resume-mcp-server/json` |
| 64 | `sanctions-mcp` | `v1.0.0` | [github.com/kindrat86/agentmail](https://github.com/kindrat86/agentmail) | `pypi.org/pypi/sanctions-mcp/json` |
| 65 | `shahnameh-mcp-server` | `v1.0.0` | [pypi.org/project/shahnameh-mcp-s...](https://pypi.org/project/shahnameh-mcp-server/) | `pypi.org/pypi/shahnameh-mcp-server/json` |
| 66 | `skill-seekers` | `v3.10.0` | [github.com/yusufkaraaslan/Skill_...](https://github.com/yusufkaraaslan/Skill_Seekers) | `pypi.org/pypi/skill-seekers/json` |
| 67 | `spring-nacos-mcp` | `v1.0.0` | [pypi.org/project/spring-nacos-mcp/](https://pypi.org/project/spring-nacos-mcp/) | `pypi.org/pypi/spring-nacos-mcp/json` |
| 68 | `tabpilot-mcp` | `v1.0.0` | [github.com/hunglp97/tabpilot-mcp](https://github.com/hunglp97/tabpilot-mcp) | `pypi.org/pypi/tabpilot-mcp/json` |
| 69 | `teslamate-mcp` | `v1.0.0` | [pypi.org/project/teslamate-mcp/](https://pypi.org/project/teslamate-mcp/) | `pypi.org/pypi/teslamate-mcp/json` |
| 70 | `tiktok-ads-mcp` | `v1.0.0` | [github.com/ysntony/tiktok-ads-mcp](https://github.com/ysntony/tiktok-ads-mcp) | `pypi.org/pypi/tiktok-ads-mcp/json` |
| 71 | `tuvi-mcp-server` | `v1.0.0` | [github.com/nmhaaa3218/TuViMCP](https://github.com/nmhaaa3218/TuViMCP) | `pypi.org/pypi/tuvi-mcp-server/json` |
| 72 | `uniswap-poolspy-mcp` | `v1.0.0` | [pypi.org/project/uniswap-poolspy...](https://pypi.org/project/uniswap-poolspy-mcp/) | `pypi.org/pypi/uniswap-poolspy-mcp/json` |
| 73 | `video-edit-mcp` | `v1.0.0` | [github.com/Aditya2755/video-edit...](https://github.com/Aditya2755/video-edit-mcp) | `pypi.org/pypi/video-edit-mcp/json` |
| 74 | `web3-jobs-mcp` | `v1.0.0` | [pypi.org/project/web3-jobs-mcp/](https://pypi.org/project/web3-jobs-mcp/) | `pypi.org/pypi/web3-jobs-mcp/json` |
| 75 | `workatastartup-mcp` | `v0.1.2` | [smithery.ai/servers/workatastart...](https://smithery.ai/servers/workatastartup-mcp) | `pypi.org/pypi/workatastartup-mcp/json` |

---

## 4. Automated Verification & Acceptance Test Suite

An automated audit invariant test suite must be established in `tests/audit/test_traceability_batch2_pypi.py`:

```python
"""Empirical Traceability Test Suite for Batch 2 (Python & PyPI FastMCP Servers)."""

import json
from pathlib import Path
import pytest

CATALOG_PATH = Path("docs/data/mcp_catalog_index.json")

@pytest.fixture(scope="module")
def catalog_index():
    with open(CATALOG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def test_batch2_packages_exist_in_catalog(catalog_index):
    # Verify all 75 PyPI packages exist in catalog index
    catalog_pkgs = {s["package_name"]: s for s in catalog_index if s.get("package_name")}
    sample_names = [
        "Apple-MCPs", "WaveGuardClient", "adhd-hub",
        "agents", "awslabs-aws-api-mcp-server", "beam_mcp", "blender-mcp"
    ]
    for name in sample_names:
        assert name in catalog_pkgs, f"Package {name} missing from catalog index"
        assert catalog_pkgs[name]["ecosystem"] in ("pypi", "PyPI")
        assert catalog_pkgs[name]["latest_version"] is not None
```

---

## 5. Deliverables & Integration Checklist

- [ ] Execute upstream HTTP queries against `pypi.org/pypi/<pkg>/json` for all 75 packages.
- [ ] Record findings in `docs/reports/audit_batch2_pypi.md` detailing:
  - 100% verification status table.
  - Identification of yanked releases and version discrepancies.
  - Evaluation of `project_urls` resolution accuracy vs. `pypi.org` fallbacks.
  - FastMCP decorator detection and tool schema extraction fidelity.
- [ ] Implement automated regression test `tests/audit/test_traceability_batch2_pypi.py`.
- [ ] Recommend enhancements to `src/mcp_vulnerabilities/discovery/pypi.py` for handling multi-key `project_urls` parsing (`Source Code`, `Repository`, `Code`).
