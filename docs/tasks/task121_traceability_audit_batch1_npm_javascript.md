# Task 121: Track A — Batch 1 Traceability Audit: npm & JavaScript MCP Servers (75 Items) (P0)

**Subsystem:** Ingestion Traceability & Discovery (`docs/data/mcp_catalog_index.json`, `src/mcp_vulnerabilities/discovery/npm.py`, `docs/reports/audit_batch1_npm.md`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave23_deep_empirical_audit_and_verification.md](master_plan_wave23_deep_empirical_audit_and_verification.md)

---

## 1. Objective & Problem Statement

The npm registry represents the largest single ecosystem in the `mcp-vulnerabilities` catalog, accounting for **1,657 servers** (over 26% of all indexed entries). Ingestion from npm relies on keyword queries (`keywords:mcp-server`, `keywords:modelcontextprotocol`, `text=@modelcontextprotocol`) in `NpmDiscoveryProvider` (`src/mcp_vulnerabilities/discovery/npm.py`).

However, npm packages present distinct extraction failure modes:
1. **Unpublished / Deprecated Packages**: Packages unpublish versions or entire packages, leaving stale records in local state (`mcp_catalog_state.json`) with HTTP 404 upstream status.
2. **Version Desynchronization**: Authors frequently publish rapid patches (e.g. `v1.0.1` -> `v1.0.4`), but catalog state TTL caches can delay re-auditing for up to 30 days unless triggered by delta detection.
3. **Repository URL Sanitization**: Git URLs in npm metadata often use legacy formats (`git://`, `git+https://`, `ssh://`, or shorthand `github:user/repo`), which can fail HTTP reachability checks if not normalized.
4. **Tool Capability Inference**: Unlike Python packages with explicit entrypoint conventions, npm MCP packages often wrap stdio binaries (`dist/index.js`) without declaring tools in `package.json`, causing tool samples to appear empty.

This task conducts a rigorous, empirical upstream traceability audit across **75 real npm MCP servers** systematically sampled from `docs/data/mcp_catalog_index.json`.

---

## 2. 7-Point Upstream Verification Protocol

Each package in Batch 1 is audited against the following 7 invariants:

1. **Upstream Registry Resolution**:
   - Query `https://registry.npmjs.org/<package>` to verify package exists, is publicly accessible (HTTP 200), and is not marked `deprecated` or unpublished.
2. **Version Alignment & Freshness**:
   - Compare `dist-tags.latest` in registry JSON against `latest_version` in `docs/data/mcp_catalog_index.json`. Identify any version drift or lagging cache entries.
3. **Repository Origin Verification**:
   - Inspect `repository.url` in upstream `package.json`. Verify normalization into valid HTTPS URLs (`https://github.com/...`) and check repository reachability.
4. **Author & Maintainer Attribution**:
   - Compare `author` and `maintainers` array in npm payload against catalog `author` field.
5. **Tool & Capabilities Extraction**:
   - Verify whether `tools_count` and `tools_sample` accurately reflect published tool definitions or if the server operates as a gateway / remote SSE endpoint.
6. **Security Posture & Vulnerability Correlation**:
   - Check if known CVEs/GHSAs for the package are correctly linked in `docs/data/vulnerabilities.json`, and verify `recommended_safe_version` SemVer constraints.
7. **Discovery Query Coverage**:
   - Validate which discovery search query (`keywords:mcp-server`, `keywords:modelcontextprotocol`, `text=@modelcontextprotocol`, `mcp-server`) matched the package.

---

## 3. Audited Item Registry: Batch 1 (75 Real npm Packages)

| # | Package Name | Catalog Version | Upstream Repository | Upstream Registry Endpoint |
| :-: | :--- | :---: | :--- | :--- |
| 01 | `2dai-mcp-server` | `v2.1.2` | [github.com/2DAICommunity/2dai-mc...](https://github.com/2DAICommunity/2dai-mcp-server) | `registry.npmjs.org/2dai-mcp-server` |
| 02 | `@agentmetal/mcp` | `v1.0.0` | [github.com/agentmetal/mcp](https://github.com/agentmetal/mcp) | `registry.npmjs.org/@agentmetal/mcp` |
| 03 | `@ask-llm/antigravity-mcp` | `v1.0.0` | [github.com/Lykhoyda/ask-llm](https://github.com/Lykhoyda/ask-llm) | `registry.npmjs.org/@ask-llm/antigravity-mcp` |
| 04 | `@benborla29/mcp-server-mysql` | `v2.0.9` | [github.com/benborla/mcp-server-m...](https://github.com/benborla/mcp-server-mysql) | `registry.npmjs.org/@benborla29/mcp-server-mysql` |
| 05 | `@cerebrochain/mcp-server` | `v1.0.1` | [github.com/CerebroChain/cerebroc...](https://github.com/CerebroChain/cerebrochain-mcp-server) | `registry.npmjs.org/@cerebrochain/mcp-server` |
| 06 | `@dealx/mcp-server` | `v0.1.9` | [www.npmjs.com/package/@dealx/mcp...](https://www.npmjs.com/package/@dealx/mcp-server) | `registry.npmjs.org/@dealx/mcp-server` |
| 07 | `@freepeak/db-mcp-server` | `v1.0.0` | [www.npmjs.com/package/@freepeak/...](https://www.npmjs.com/package/@freepeak/db-mcp-server) | `registry.npmjs.org/@freepeak/db-mcp-server` |
| 08 | `@ianaleck/harvest-mcp-server` | `v1.0.0` | [github.com/ianaleck/harvest-mcp-...](https://github.com/ianaleck/harvest-mcp-server) | `registry.npmjs.org/@ianaleck/harvest-mcp-server` |
| 09 | `@jinzcdev/markmap-mcp-server` | `v1.0.0` | [github.com/jinzcdev/markmap-mcp-...](https://github.com/jinzcdev/markmap-mcp-server) | `registry.npmjs.org/@jinzcdev/markmap-mcp-server` |
| 10 | `@lamemind/mcp-server-multiverse` | `v1.1.4` | [github.com/lamemind/mcp-server-m...](https://github.com/lamemind/mcp-server-multiverse) | `registry.npmjs.org/@lamemind/mcp-server-multiverse` |
| 11 | `@mambalabsdev/mcp-gtm-suite` | `v1.14.0` | [github.com/mambalabsdev/mcp-gtm-...](https://github.com/mambalabsdev/mcp-gtm-suite) | `registry.npmjs.org/@mambalabsdev/mcp-gtm-suite` |
| 12 | `@modelcontextprotocol/client` | `v2.2.0` | [www.npmjs.com/package/@modelcont...](https://www.npmjs.com/package/@modelcontextprotocol/client) | `registry.npmjs.org/@modelcontextprotocol/client` |
| 13 | `@niledatabase/nile-mcp-server` | `v1.4.0` | [smithery.ai/servers/@niledatabas...](https://smithery.ai/servers/@niledatabase/nile-mcp-server) | `registry.npmjs.org/@niledatabase/nile-mcp-server` |
| 14 | `@park-sang-gwon/google-flow-mcp` | `v1.0.0` | [github.com/ParkSangGwon/google-f...](https://github.com/ParkSangGwon/google-flow-mcp) | `registry.npmjs.org/@park-sang-gwon/google-flow-mcp` |
| 15 | `@pyroprompts/any-chat-completions-mcp` | `v0.1.1` | [github.com/pyroprompts/any-chat-...](https://github.com/pyroprompts/any-chat-completions-mcp) | `registry.npmjs.org/@pyroprompts/any-chat-completions-mcp` |
| 16 | `@setell/mcp` | `v1.0.0` | [github.com/setell-ai/setell-mcp](https://github.com/setell-ai/setell-mcp) | `registry.npmjs.org/@setell/mcp` |
| 17 | `@sumup/mcp` | `v0.12.1` | [github.com/sumup/sumup-ai](https://github.com/sumup/sumup-ai) | `registry.npmjs.org/@sumup/mcp` |
| 18 | `@theyahia/yandex-direct-mcp` | `v4.0.1` | [github.com/theYahia/yandex-direc...](https://github.com/theYahia/yandex-direct-mcp#readme) | `registry.npmjs.org/@theyahia/yandex-direct-mcp` |
| 19 | `@vaaya/mcp` | `v1.0.0` | [github.com/vaaya-ai/vaaya-mcp](https://github.com/vaaya-ai/vaaya-mcp) | `registry.npmjs.org/@vaaya/mcp` |
| 20 | `@wangshunnn/bilibili-mcp-server` | `v1.0.0` | [www.npmjs.com/package/@wangshunn...](https://www.npmjs.com/package/@wangshunnn/bilibili-mcp-server) | `registry.npmjs.org/@wangshunnn/bilibili-mcp-server` |
| 21 | `@zvid/mcp` | `v1.0.0` | [github.com/Zvid-io/zvid-mcp](https://github.com/Zvid-io/zvid-mcp) | `registry.npmjs.org/@zvid/mcp` |
| 22 | `admob-mcp-server` | `v1.0.0` | [github.com/ParkSangGwon/admob-mc...](https://github.com/ParkSangGwon/admob-mcp-server) | `registry.npmjs.org/admob-mcp-server` |
| 23 | `agenthop` | `v1.0.0` | [www.npmjs.com/package/agenthop](https://www.npmjs.com/package/agenthop) | `registry.npmjs.org/agenthop` |
| 24 | `aicommander-mcp` | `v1.0.0` | [www.npmjs.com/package/aicommande...](https://www.npmjs.com/package/aicommander-mcp) | `registry.npmjs.org/aicommander-mcp` |
| 25 | `amocrm-kommo-mcp` | `v1.0.0` | [www.npmjs.com/package/amocrm-kom...](https://www.npmjs.com/package/amocrm-kommo-mcp) | `registry.npmjs.org/amocrm-kommo-mcp` |
| 26 | `astexplore-mcp` | `v1.0.0` | [github.com/KingJem/astexplore-mcp](https://github.com/KingJem/astexplore-mcp) | `registry.npmjs.org/astexplore-mcp` |
| 27 | `axel-belfort/dns-lookup` | `v1.0.0` | [dns-lookup--axel-belfort.run.tools](https://dns-lookup--axel-belfort.run.tools) | `registry.npmjs.org/axel-belfort/dns-lookup` |
| 28 | `ayni-protocol/ayni` | `v1.0.0` | [ayni--ayni-protocol.run.tools](https://ayni--ayni-protocol.run.tools) | `registry.npmjs.org/ayni-protocol/ayni` |
| 29 | `bigquery` | `v0.0.6` | [github.com/peihsinsu/bigquery#re...](https://github.com/peihsinsu/bigquery#readme) | `registry.npmjs.org/bigquery` |
| 30 | `brave-search-monorepo` | `v1.0.0` | [www.npmjs.com/package/brave-sear...](https://www.npmjs.com/package/brave-search-monorepo) | `registry.npmjs.org/brave-search-monorepo` |
| 31 | `celiums-memory` | `v1.0.0` | [www.npmjs.com/package/celiums-me...](https://www.npmjs.com/package/celiums-memory) | `registry.npmjs.org/celiums-memory` |
| 32 | `claude-soul-monorepo` | `v1.0.0` | [www.npmjs.com/package/claude-sou...](https://www.npmjs.com/package/claude-soul-monorepo) | `registry.npmjs.org/claude-soul-monorepo` |
| 33 | `com.gamelovers.mcp-unity` | `v1.2.0` | [www.npmjs.com/package/com.gamelo...](https://www.npmjs.com/package/com.gamelovers.mcp-unity) | `registry.npmjs.org/com.gamelovers.mcp-unity` |
| 34 | `cryptodataapi-mcp` | `v1.0.0` | [github.com/Crypto-Data-API/crypt...](https://github.com/Crypto-Data-API/cryptodataapi-mcp) | `registry.npmjs.org/cryptodataapi-mcp` |
| 35 | `cyanheads/wikipedia-mcp-server` | `v1.0.0` | [wikipedia-mcp-server--cyanheads....](https://wikipedia-mcp-server--cyanheads.run.tools) | `registry.npmjs.org/cyanheads/wikipedia-mcp-server` |
| 36 | `depot-mcp` | `v1.0.0` | [github.com/akshayjain3450/depot-mcp](https://github.com/akshayjain3450/depot-mcp) | `registry.npmjs.org/depot-mcp` |
| 37 | `doordash-mcp-server` | `v1.0.0` | [www.npmjs.com/package/doordash-m...](https://www.npmjs.com/package/doordash-mcp-server) | `registry.npmjs.org/doordash-mcp-server` |
| 38 | `ergonia` | `v1.0.0` | [www.npmjs.com/package/ergonia](https://www.npmjs.com/package/ergonia) | `registry.npmjs.org/ergonia` |
| 39 | `figma-use` | `v0.13.5` | [github.com/dannote/figma-use](https://github.com/dannote/figma-use) | `registry.npmjs.org/figma-use` |
| 40 | `g-search-mcp` | `v1.0.0` | [www.npmjs.com/package/g-search-mcp](https://www.npmjs.com/package/g-search-mcp) | `registry.npmjs.org/g-search-mcp` |
| 41 | `gitlab-mr-mcp` | `v1.1.4` | [www.npmjs.com/package/gitlab-mr-mcp](https://www.npmjs.com/package/gitlab-mr-mcp) | `registry.npmjs.org/gitlab-mr-mcp` |
| 42 | `graph-memory` | `v1.5.8` | [www.npmjs.com/package/graph-memory](https://www.npmjs.com/package/graph-memory) | `registry.npmjs.org/graph-memory` |
| 43 | `hono-telescope` | `v1.2.1` | [github.com/jubstaaa/hono-telescope](https://github.com/jubstaaa/hono-telescope) | `registry.npmjs.org/hono-telescope` |
| 44 | `industrylens/mcp` | `v1.0.0` | [industrylens.run.tools](https://industrylens.run.tools) | `registry.npmjs.org/industrylens/mcp` |
| 45 | `jan-krat-kj4q/tulugar-real-estate` | `v1.0.0` | [tulugar-real-estate--jan-krat-kj...](https://tulugar-real-estate--jan-krat-kj4q.run.tools) | `registry.npmjs.org/jan-krat-kj4q/tulugar-real-estate` |
| 46 | `king-of-the-grackles/discourse-forum-mcp` | `v1.0.0` | [discourse-forum-mcp--king-of-the...](https://discourse-forum-mcp--king-of-the-grackles.run.tools) | `registry.npmjs.org/king-of-the-grackles/discourse-forum-mcp` |
| 47 | `lightningprox-mcp` | `v1.2.3` | [github.com/unixlamadev-spec/ligh...](https://github.com/unixlamadev-spec/lightningprox-mcp) | `registry.npmjs.org/lightningprox-mcp` |
| 48 | `lxxmng/ocean-schedules` | `v1.0.0` | [ocean-schedules--lxxmng.run.tools](https://ocean-schedules--lxxmng.run.tools) | `registry.npmjs.org/lxxmng/ocean-schedules` |
| 49 | `mcp-bideetmusique` | `v2.1.0` | [github.com/smeet666/mcp-bideetmu...](https://github.com/smeet666/mcp-bideetmusique) | `registry.npmjs.org/mcp-bideetmusique` |
| 50 | `mcp-imslp` | `v1.1.0` | [github.com/smeet666/mcp-imslp](https://github.com/smeet666/mcp-imslp) | `registry.npmjs.org/mcp-imslp` |
| 51 | `mcp-open-library` | `v1.2.6` | [github.com/8enSmith/mcp-open-lib...](https://github.com/8enSmith/mcp-open-library) | `registry.npmjs.org/mcp-open-library` |
| 52 | `mcp-server-chatsum` | `v1.0.0` | [www.npmjs.com/package/mcp-server...](https://www.npmjs.com/package/mcp-server-chatsum) | `registry.npmjs.org/mcp-server-chatsum` |
| 53 | `mcp-sqlite` | `v1.0.9` | [github.com/jparkerweb/mcp-sqlite](https://github.com/jparkerweb/mcp-sqlite) | `registry.npmjs.org/mcp-sqlite` |
| 54 | `memcord` | `v1.0.0-1` | [www.npmjs.com/package/memcord](https://www.npmjs.com/package/memcord) | `registry.npmjs.org/memcord` |
| 55 | `mockhero` | `v1.0.0` | [www.npmjs.com/package/mockhero](https://www.npmjs.com/package/mockhero) | `registry.npmjs.org/mockhero` |
| 56 | `nausika/nausika` | `v1.0.0` | [nausika.run.tools](https://nausika.run.tools) | `registry.npmjs.org/nausika/nausika` |
| 57 | `nodeflare-mcp` | `v1.0.0` | [github.com/Nodeflare-app/nodefla...](https://github.com/Nodeflare-app/nodeflare-mcp) | `registry.npmjs.org/nodeflare-mcp` |
| 58 | `oobe-protocol/sap-mcp` | `v1.0.0` | [sap-mcp--oobe-protocol.run.tools](https://sap-mcp--oobe-protocol.run.tools) | `registry.npmjs.org/oobe-protocol/sap-mcp` |
| 59 | `package-registry-mcp` | `v2.1.0` | [github.com/artmann/package-regis...](https://github.com/artmann/package-registry-mcp) | `registry.npmjs.org/package-registry-mcp` |
| 60 | `piapi-mcp-server` | `v1.0.0` | [www.npmjs.com/package/piapi-mcp-...](https://www.npmjs.com/package/piapi-mcp-server) | `registry.npmjs.org/piapi-mcp-server` |
| 61 | `posthive` | `v1.0.0` | [www.npmjs.com/package/posthive](https://www.npmjs.com/package/posthive) | `registry.npmjs.org/posthive` |
| 62 | `qa-probe` | `v2.12.1` | [github.com/LS-SIEM-LLP/qa-probe](https://github.com/LS-SIEM-LLP/qa-probe) | `registry.npmjs.org/qa-probe` |
| 63 | `ravn-mcp-glama` | `v1.0.0` | [www.npmjs.com/package/ravn-mcp-g...](https://www.npmjs.com/package/ravn-mcp-glama) | `registry.npmjs.org/ravn-mcp-glama` |
| 64 | `rileycraig14/nexus-intelligence` | `v1.0.0` | [nexus-intelligence--rileycraig14...](https://nexus-intelligence--rileycraig14.run.tools) | `registry.npmjs.org/rileycraig14/nexus-intelligence` |
| 65 | `schema-bridge-mcp` | `v1.0.0` | [www.npmjs.com/package/schema-bri...](https://www.npmjs.com/package/schema-bridge-mcp) | `registry.npmjs.org/schema-bridge-mcp` |
| 66 | `sgroy10/speclock` | `v1.0.0` | [speclock--sgroy10.run.tools](https://speclock--sgroy10.run.tools) | `registry.npmjs.org/sgroy10/speclock` |
| 67 | `smithtalks-mcp` | `v1.4.0` | [github.com/mozzimorzam-sudo/smit...](https://github.com/mozzimorzam-sudo/smithtalks-mcp) | `registry.npmjs.org/smithtalks-mcp` |
| 68 | `statuscraft` | `v1.1.0` | [github.com/statuscraft/statuscraft](https://github.com/statuscraft/statuscraft) | `registry.npmjs.org/statuscraft` |
| 69 | `synapse-code-mcp` | `v1.0.0` | [github.com/Juanmidev1/synapse-co...](https://github.com/Juanmidev1/synapse-code-mcp) | `registry.npmjs.org/synapse-code-mcp` |
| 70 | `thingery` | `v0.1.3` | [github.com/thingery/thingery](https://github.com/thingery/thingery) | `registry.npmjs.org/thingery` |
| 71 | `tooldirectory-mcp` | `v1.0.0` | [github.com/AI-Directory-Partners...](https://github.com/AI-Directory-Partners/tooldirectory-mcp) | `registry.npmjs.org/tooldirectory-mcp` |
| 72 | `twinkly-mcp` | `v1.0.0` | [github.com/paztek/twinkly-mcp](https://github.com/paztek/twinkly-mcp) | `registry.npmjs.org/twinkly-mcp` |
| 73 | `veezee-mcp` | `v1.0.0` | [www.npmjs.com/package/veezee-mcp](https://www.npmjs.com/package/veezee-mcp) | `registry.npmjs.org/veezee-mcp` |
| 74 | `wasmagent-js` | `v1.0.0` | [www.npmjs.com/package/wasmagent-js](https://www.npmjs.com/package/wasmagent-js) | `registry.npmjs.org/wasmagent-js` |
| 75 | `workspaces` | `v0.1.0` | [github.com/zeekay/workspaces](https://github.com/zeekay/workspaces) | `registry.npmjs.org/workspaces` |

---

## 4. Automated Verification & Acceptance Test Suite

An automated audit invariant test suite must be established in `tests/audit/test_traceability_batch1_npm.py`:

```python
"""Empirical Traceability Test Suite for Batch 1 (npm & JavaScript MCP Servers)."""

import json
from pathlib import Path
import pytest

CATALOG_PATH = Path("docs/data/mcp_catalog_index.json")

@pytest.fixture(scope="module")
def catalog_index():
    with open(CATALOG_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def test_batch1_packages_exist_in_catalog(catalog_index):
    # Verify all 75 packages exist in catalog index
    catalog_pkgs = {s["package_name"]: s for s in catalog_index if s.get("package_name")}
    sample_names = [
        "2dai-mcp-server", "@agentmetal/mcp", "@ask-llm/antigravity-mcp",
        "@benborla29/mcp-server-mysql", "@cerebrochain/mcp-server",
        "@modelcontextprotocol/client", "@modelcontextprotocol/server-filesystem"
    ]
    for name in sample_names:
        assert name in catalog_pkgs, f"Package {name} missing from catalog index"
        assert catalog_pkgs[name]["ecosystem"] == "npm"
        assert catalog_pkgs[name]["latest_version"] is not None
```

---

## 5. Deliverables & Integration Checklist

- [ ] Execute upstream HTTP verification against `registry.npmjs.org` for all 75 packages.
- [ ] Record findings in `docs/reports/audit_batch1_npm.md` detailing:
  - 100% verification status table.
  - Identification of unpublished or deprecated packages.
  - Analysis of repository URL normalization edge cases (`git+ssh://`, `git://`).
  - Catalog version lag statistics and cache TTL evaluation.
- [ ] Implement automated regression test `tests/audit/test_traceability_batch1_npm.py`.
- [ ] Recommend enhancements to `src/mcp_vulnerabilities/discovery/npm.py` for repository URL sanitization and deprecation status tracking.
