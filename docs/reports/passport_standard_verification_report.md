# MCP Server Passport Standard & Dual-Axis Assessment Verification Report

**Verification Timestamp:** `2026-11-06 06:48:34 UTC`  
**Total Records Evaluated:** `6,010` MCP Servers  
**Audit Status:** `5,907` OK (98.29%), `103` Deficient (1.71%)  

## 1. Executive Summary

Each and every available MCP server registered in the central registry (`data/passports.json.gz`) was individually evaluated against the standard MCP Passport schema specification and the newly introduced Dual-Axis security metrics (`protocol_trust` + `supply_chain_hygiene`).

| Metric | Value | Proportion |
| :--- | :--- | :--- |
| **Total Processed Passports** | `6,010` | `100.0%` |
| **Standard Compliant (Mark: OK)** | `5,907` | `98.29%` |
| **Deficient Passports (Mark: DEFICIENT)** | `103` | `1.71%` |
| └─ Fully Scanned with Dual-Axis Telemetry | `2,831` | `47.10%` |
| └─ Offline / Archived / Unreachable | `3,179` | `52.90%` |

## 2. Dual-Axis Field Completeness Analysis

All **6,010** MCP servers contain an active `dual_axis_assessment` record:
- **Active & Scanned (`SCANNED`)**: `2,831` servers.
- **Unreachable / Private / Removed (`OFFLINE_OR_UNREACHABLE`)**: `3,179` servers.

### Missing Required Fields Breakdown across Deficient Records

| Missing Field | Deficient Servers Count |
| :--- | :--- |
| `dual_axis_assessment.has_vulnerabilities` | `100` |
| `passport_schema_version` | `3` |

## 3. Detailed Deficient Server Listing

The following servers are flagged with **DEFICIENT** due to missing mandatory schema attributes:

| Server Name | Ecosystem | Status Category | Missing Required Fields |
| :--- | :--- | :--- | :--- |
| `hejdar-mcp` | `pypi` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `@modelcontextprotocol/server-postgres` | `npm` | `OFFLINE_OR_UNREACHABLE` | `passport_schema_version` |
| `@modelcontextprotocol/server-sqlite` | `npm` | `OFFLINE_OR_UNREACHABLE` | `passport_schema_version` |
| `iai-pme` | `pypi` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hocr` | `pypi` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `github_Yanyutin753_mcp-weather` | `github` | `OFFLINE_OR_UNREACHABLE` | `passport_schema_version` |
| `hanshs474/kavel-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `haoming-luo/agentfem-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `haomingkoo/japan-seasons-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `happyc0der/garmin-connect-api` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hardeyhemy/revnuvo-dev` | `github` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `harrison/ai-counsel` | `github` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `haruodev/tamperlens-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hashicorp/terraform-mcp-server` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `headlessherm-creator/polymath-megablaster-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `health-export-mcp` | `npm` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `healthchainai/HealthChain` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hechtcarmel/jetbrains-debugger-mcp-plugin` | `github` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hechtcarmel/jetbrains-index-mcp-plugin` | `github` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `helbertparanhos/cloudflare-mcp-pro` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `helbertparanhos/n8n-pro-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `helbertparanhos/postforme-mcp-pro` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `helbertparanhos/resend-email-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hello-oipe/Geppetto-Robot-Directory` | `npm` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `helpful-AIs/triplyfy-mcp` | `github` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `henfrydls/actual-budget-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `henilcalagiya/google-sheets-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `henilcalagiya/mcp-apple-notes` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `henry-ships/sparkforge` | `npm` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `herbertkokholm/cite-caddy` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hermes-labs-ai/fidelis` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hermoso-ai/hermoso` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hernaninverso/eleata-einvoice-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hernaninverso/eleata-verify-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hernaninverso/eleion-scanner-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `heymrun/heym` | `github` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hi-10f9/vetted-consumer` | `npm` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hidai25/eval-view` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hifriendbot/agentwallet-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hifriendbot/cogmemai-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hikmahtech/drwhome` | `github` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hiroata/meltbook` | `github` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hithereiamaliff/mcp-malaysiatransit` | `npm` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hive-intel/hive-crypto-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hivemindunit/llmintel-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hjbaard/SolidWorks-MCP` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hjqcan/GoodMemory` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hjsh200219/fortuneteller` | `npm` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hloiseaufcms/mcp-gopls` | `golang` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hoainho/podium-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hoklims/stacksfinder-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `homespunapps/homespun` | `github` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `honeylabshq/honeylabs-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hoornet/agentdocs-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hope1026/weppy-roblox-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hoqqun/stooq-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `horustechltd/horus-flow-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hostodo/hostodo-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hostsmith/mcp-server` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `housingassist/tokyo-housing` | `npm` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `huangdun/tempmd-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `huanglizhuo/OctoCounts` | `github` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `human-beyond/mainbook-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `human-pages-ai/humanpages` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `humanforai/humanforai-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `humanpen/humanpen-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `huseyinstif/klaket` | `github` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hushvert/mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hypawave/mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hypeprinter007-stack/anchor-x402-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hypeprinter007-stack/signalfuse-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hyperionxmota/cook-county-property-mcp` | `github` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `hypnosis/ssh-mcp-server` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `iFan6oy/flash-props-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ia-qa/api` | `npm` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `icohangar-ops/codesentinel` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `icosaedro/toolsnap-mcp` | `npm` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ictinnovations/ictbroadcast-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ictinnovations/ictcrm-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ictinnovations/ictexam-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ictinnovations/ictfax-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ictinnovations/ictpbx-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ictinnovations/pbx-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `icyberdeveloper/tbank-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ieranama/discomcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ignaciohermosillacornejo/copilot-money-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `igorolv/jdbc-mcp-server` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `igorolv/loki-mcp-server` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `igorolv/redmine-mcp-server` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `igorolv/sonar-mcp-server` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `igorsaevets/page2ai-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ihorponom/agentpack` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ihuzaifashoukat/x-use` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `iksnerd/adb-mcp` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ilia-sokolov/OfficeAgent.NET` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ilien-dev/svipall` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `illodev/workfile` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ilovevideoeditor/mcp-server` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ilyautov/chestny-znak-mcp-ru` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ilyautov/diadoc-mcp-ru` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ilyautov/hh-mcp-ru` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ilyautov/marketplaces-mcp-ru` | `generic` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |
| `ida-pro-mcp` | `pypi` | `SCANNED` | `dual_axis_assessment.has_vulnerabilities` |

## 4. Verification Dataset Reference

The comprehensive verification outcome for each of the 6,010 MCP servers is materialized in:
- [`docs/reports/full_passport_verification_matrix.json`](docs/reports/full_passport_verification_matrix.json)
- [`docs/reports/passport_standard_verification_report.md`](docs/reports/passport_standard_verification_report.md)
