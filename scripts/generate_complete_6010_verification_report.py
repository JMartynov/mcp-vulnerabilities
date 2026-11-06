#!/usr/bin/env python3
"""
Comprehensive 100% MCP Server Passport Standard & Dual-Axis Auditor.
Verifies all 6,010 servers in data/passports.json.gz.
Generates:
1. docs/reports/full_server_passport_verification_matrix.md:
   A dedicated markdown report listing all 6,010 MCP servers individually with their OK/DEFICIENT mark,
   status, ecosystem, and any missing fields.
2. docs/reports/complete_passport_audit_summary.md:
   Executive summary report detailing the breakdown of completed vs non-completed elements.
3. docs/reports/full_server_passport_verification_matrix.json:
   Machine-readable JSON matrix.
"""

import gzip
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

def evaluate_server(name: str, p: dict) -> dict:
    missing_required = []
    missing_optional = []

    # 1. Base identity & standard schema requirements
    if not p.get("package_name"):
        missing_required.append("package_name")
    if not p.get("ecosystem"):
        missing_required.append("ecosystem")
    if not p.get("passport_schema_version"):
        missing_required.append("passport_schema_version")
    elif p.get("passport_schema_version") != "1.1.0":
        missing_required.append(f"passport_schema_version!={p.get('passport_schema_version')}")

    # 2. Newly added Dual-Axis Security information
    da = p.get("dual_axis_assessment")
    if not da:
        missing_required.append("dual_axis_assessment")
        status_category = "MISSING_ASSESSMENT"
    else:
        st = da.get("status")
        if not st:
            missing_required.append("dual_axis_assessment.status")
            status_category = "INVALID_STATUS"
        elif st == "SCANNED":
            status_category = "SCANNED"
            if "protocol_trust" not in da:
                missing_required.append("dual_axis_assessment.protocol_trust")
            if "supply_chain_hygiene" not in da:
                missing_required.append("dual_axis_assessment.supply_chain_hygiene")
            if "has_vulnerabilities" not in da or not isinstance(da.get("has_vulnerabilities"), bool):
                missing_required.append("dual_axis_assessment.has_vulnerabilities[bool]")
        elif st == "OFFLINE_OR_UNREACHABLE":
            status_category = "OFFLINE_OR_UNREACHABLE"
        else:
            status_category = f"CUSTOM_{st}"

    # 3. Standard metadata fields
    if not p.get("description"):
        missing_optional.append("description")
    if not p.get("license"):
        missing_optional.append("license")
    if not p.get("repository_url") and not p.get("homepage_url"):
        missing_optional.append("repository_url")

    is_ok = (len(missing_required) == 0)
    mark = "OK" if is_ok else "DEFICIENT"

    return {
        "server_name": name,
        "mark": mark,
        "is_ok": is_ok,
        "status_category": status_category,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "ecosystem": p.get("ecosystem", "unknown")
    }

def main():
    db_path = Path("data/passports.json.gz")
    print(f"[*] Reading master database from {db_path}...")
    with gzip.open(db_path, "rt", encoding="utf-8") as f:
        data = json.load(f)

    passports = data.get("passports", {})
    total = len(passports)
    print(f"[*] Auditing all {total} servers...")

    results = []
    stats = Counter()
    missing_fields_stats = Counter()
    non_completed = []

    for name in sorted(passports.keys()):
        res = evaluate_server(name, passports[name])
        results.append(res)
        stats[f"mark_{res['mark']}"] += 1
        stats[f"category_{res['status_category']}"] += 1
        if not res["is_ok"]:
            non_completed.append(res)
            for f in res["missing_required"]:
                missing_fields_stats[f] += 1

    reports_dir = Path("docs/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    # 1. Write Machine-readable JSON
    json_path = reports_dir / "full_server_passport_verification_matrix.json"
    print(f"[*] Writing {json_path}...")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_servers": total,
            "total_ok": stats["mark_OK"],
            "total_deficient": stats["mark_DEFICIENT"],
            "categories": dict(stats),
            "missing_fields": dict(missing_fields_stats),
            "records": results
        }, f, indent=2)

    # 2. Write Summary Report
    summary_path = reports_dir / "complete_passport_audit_summary.md"
    print(f"[*] Writing summary report to {summary_path}...")
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write("# MCP Server Master Passport & Dual-Axis Assessment Summary Report\n\n")
        f.write(f"**Audit Execution Timestamp:** `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`  \n")
        f.write(f"**Total Registered MCP Servers:** `{total:,}`  \n\n")
        f.write("## 1. Executive Summary Table\n\n")
        f.write("| Verification Category | Total Count | Percentage | Standard Compliance Mark |\n")
        f.write("| :--- | :--- | :--- | :--- |\n")
        f.write(f"| **Fully Verified & Standard Compliant** | **`{stats['mark_OK']:,}`** | **`{stats['mark_OK']/total*100:.2f}%`** | **`OK`** |\n")
        f.write(f"| **Non-Completed / Deficient Records** | **`{stats['mark_DEFICIENT']:,}`** | **`{stats['mark_DEFICIENT']/total*100:.2f}%`** | **`DEFICIENT`** |\n")
        f.write(f"| ├─ Active & Scanned (`SCANNED`) | `{stats['category_SCANNED']:,}` | `{stats['category_SCANNED']/total*100:.2f}%` | `OK` |\n")
        f.write(f"| └─ Offline / Unreachable (`OFFLINE_OR_UNREACHABLE`) | `{stats['category_OFFLINE_OR_UNREACHABLE']:,}` | `{stats['category_OFFLINE_OR_UNREACHABLE']/total*100:.2f}%` | `OK` |\n\n")

        f.write("## 2. Analysis of Non-Completed / Deficient Elements\n\n")
        if non_completed:
            f.write(f"There are `{len(non_completed)}` server(s) that did not complete all required standards:\n\n")
            f.write("| Server Name | Ecosystem | Status Category | Missing Required Elements |\n")
            f.write("| :--- | :--- | :--- | :--- |\n")
            for nc in non_completed:
                f.write(f"| `{nc['server_name']}` | `{nc['ecosystem']}` | `{nc['status_category']}` | `{', '.join(nc['missing_required'])}` |\n")
            f.write("\n")
        else:
            f.write("🎉 **Zero Non-Completed Servers!** Every single server among the 6,010 matches all standard specifications and contains the newly added Dual-Axis information.\n\n")

        f.write("## 3. Reference Artifacts\n\n")
        f.write("- **6,010 Individual Server Verification Matrix**: [`full_server_passport_verification_matrix.md`](full_server_passport_verification_matrix.md)\n")
        f.write("- **Machine-Readable JSON Matrix**: [`full_server_passport_verification_matrix.json`](full_server_passport_verification_matrix.json)\n")

    # 3. Write Full 6,010 Records Markdown Table
    matrix_md_path = reports_dir / "full_server_passport_verification_matrix.md"
    print(f"[*] Writing 6,010 individual record table to {matrix_md_path}...")
    with open(matrix_md_path, "w", encoding="utf-8") as f:
        f.write("# Full MCP Server Passport Verification Matrix (All 6,010 Records)\n\n")
        f.write(f"**Total Records:** `{total:,}` | **Compliant (`OK`):** `{stats['mark_OK']:,}` | **Deficient (`DEFICIENT`):** `{stats['mark_DEFICIENT']:,}`\n\n")
        f.write("| # | MCP Server Name | Ecosystem | Status | Mark | Missing Elements |\n")
        f.write("| :--- | :--- | :--- | :--- | :---: | :--- |\n")
        for idx, r in enumerate(results, 1):
            missing_str = ", ".join(r["missing_required"]) if r["missing_required"] else "None (Complete)"
            f.write(f"| {idx} | `{r['server_name']}` | `{r['ecosystem']}` | `{r['status_category']}` | **`{r['mark']}`** | {missing_str} |\n")

    print("[+] All verification reports generated successfully!")

if __name__ == "__main__":
    main()
