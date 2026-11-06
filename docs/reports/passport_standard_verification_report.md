# MCP Server Passport Standard & Dual-Axis Assessment Verification Report

**Verification Timestamp:** `2026-11-06 07:16:08 UTC`  
**Total Records Evaluated:** `6,010` MCP Servers  
**Audit Status:** `6,010` OK (100.00%), `0` Deficient (0.00%)  

## 1. Executive Summary

Each and every available MCP server registered in the central registry (`data/passports.json.gz`) was individually evaluated against the standard MCP Passport schema specification and the newly introduced Dual-Axis security metrics (`protocol_trust` + `supply_chain_hygiene`).

| Metric | Value | Proportion |
| :--- | :--- | :--- |
| **Total Processed Passports** | `6,010` | `100.0%` |
| **Standard Compliant (Mark: OK)** | `6,010` | `100.00%` |
| **Deficient Passports (Mark: DEFICIENT)** | `0` | `0.00%` |
| └─ Fully Scanned with Dual-Axis Telemetry | `2,831` | `47.10%` |
| └─ Offline / Archived / Unreachable | `3,179` | `52.90%` |

## 2. Dual-Axis Field Completeness Analysis

All **6,010** MCP servers contain an active `dual_axis_assessment` record:
- **Active & Scanned (`SCANNED`)**: `2,831` servers.
- **Unreachable / Private / Removed (`OFFLINE_OR_UNREACHABLE`)**: `3,179` servers.

### Missing Required Fields Breakdown across Deficient Records

## 3. Deficient Server Listing

🎉 **Zero Deficiencies Found!** Every single record is 100% compliant.

## 4. Verification Dataset Reference

The comprehensive verification outcome for each of the 6,010 MCP servers is materialized in:
- [`docs/reports/full_passport_verification_matrix.json`](docs/reports/full_passport_verification_matrix.json)
- [`docs/reports/passport_standard_verification_report.md`](docs/reports/passport_standard_verification_report.md)
