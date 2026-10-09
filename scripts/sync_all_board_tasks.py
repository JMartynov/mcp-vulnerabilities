"""Synchronize all foundational and new roadmap tasks with GitHub Project 4."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

PROJECT_NUMBER = "4"
PROJECT_ID = "PVT_kwHOD-xmQM4BmPcA"
STATUS_FIELD_ID = "PVTSSF_lAHOD-xmQM4BmPcAzhk5OIE"
STATUS_TODO = "f75ad846"
STATUS_DONE = "98236657"

NEW_TASKS = [
    # Foundational tasks (Completed & 100% tested in earlier phases)
    (
        "GHSA Stream Cursor Pagination & Commit Delta Traversal (Foundational 00-A)",
        ".jules/task00a_ghsa_cursor_pagination.md",
        STATUS_DONE,
    ),
    (
        "PyPI Lazy Version Resolution & Version Cache Invalidation (Foundational 00-B)",
        ".jules/task00b_pypi_lazy_version_resolution.md",
        STATUS_DONE,
    ),
    (
        "Historical Advisory Pre-Loading & Index Preservation (Foundational 00-C)",
        ".jules/task00c_index_preservation.md",
        STATUS_DONE,
    ),
    (
        "OSV 1.6 Range Integrity & Deduplicator Event Grouping (Foundational 00-D)",
        ".jules/task00d_range_integrity_event_grouping.md",
        STATUS_DONE,
    ),
    (
        "400-URL Empirical Data Integrity Master Audit (Foundational 00-E)",
        ".jules/task00e_400_url_empirical_audit.md",
        STATUS_DONE,
    ),
    # New upcoming roadmap tasks
    (
        "Direct Vulnerability Search & Inspection CLI (cli search & lookup)",
        ".jules/task14_cli_search_lookup.md",
        STATUS_TODO,
    ),
    (
        "Reusable GitHub Action for CI/CD Pipeline Scanning (action.yml)",
        ".jules/task15_github_action_ci.md",
        STATUS_TODO,
    ),
    (
        "Upstream OSV.dev Exporter & Ecosystem Contribution Pipeline",
        ".jules/task16_osv_export_pipeline.md",
        STATUS_TODO,
    ),
]

def main() -> None:
    for title, contract_file, target_status in NEW_TASKS:
        body = Path(contract_file).read_text(encoding="utf-8")
        print(f"Creating item: {title} ...")
        create_cmd = [
            "gh", "project", "item-create", PROJECT_NUMBER,
            "--owner", "JMartynov",
            "--title", title,
            "--body", body,
            "--format", "json",
        ]
        res = subprocess.run(create_cmd, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"  [ERROR] Failed to create item {title}: {res.stderr}")
            continue

        try:
            item_data = json.loads(res.stdout)
            item_id = item_data.get("id")
            print(f"  -> Created Item ID: {item_id}")
        except Exception as e:
            print(f"  [ERROR] Parsing JSON for {title}: {e}. stdout: {res.stdout}")
            continue

        # Set status
        edit_cmd = [
            "gh", "project", "item-edit",
            "--project-id", PROJECT_ID,
            "--id", item_id,
            "--field-id", STATUS_FIELD_ID,
            "--single-select-option-id", target_status,
        ]
        edit_res = subprocess.run(edit_cmd, capture_output=True, text=True)
        status_name = "Done" if target_status == STATUS_DONE else "Todo"
        if edit_res.returncode == 0:
            print(f"  -> Successfully set status to '{status_name}'")
        else:
            print(f"  [ERROR] Failed to set status: {edit_res.stderr}")

    print("\nAll tasks synchronized with private GitHub project board!")

if __name__ == "__main__":
    main()
