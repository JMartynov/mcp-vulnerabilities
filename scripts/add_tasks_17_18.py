"""Add Tasks 17 and 18 to GitHub Project 4."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

PROJECT_NUMBER = "4"
PROJECT_ID = "PVT_kwHOD-xmQM4BmPcA"
STATUS_FIELD_ID = "PVTSSF_lAHOD-xmQM4BmPcAzhk5OIE"
STATUS_TODO = "f75ad846"

TASKS = [
    (
        "SARIF Export for GitHub Code Scanning (--format sarif)",
        ".jules/task17_sarif_export.md",
    ),
    (
        "Live MCP Protocol Probe & Tool Auditor (cli probe)",
        ".jules/task18_live_mcp_probe.md",
    ),
]

for title, path_str in TASKS:
    body = Path(path_str).read_text(encoding="utf-8")
    print(f"Adding task to Project 4: {title} ...")
    create_cmd = [
        "gh", "project", "item-create", PROJECT_NUMBER,
        "--owner", "JMartynov",
        "--title", title,
        "--body", body,
        "--format", "json",
    ]
    res = subprocess.run(create_cmd, capture_output=True, text=True)
    if res.returncode != 0:
        print(f"  [ERROR] {res.stderr}")
        continue

    item_data = json.loads(res.stdout)
    item_id = item_data.get("id")
    print(f"  -> Created Item ID: {item_id}")

    edit_cmd = [
        "gh", "project", "item-edit",
        "--project-id", PROJECT_ID,
        "--id", item_id,
        "--field-id", STATUS_FIELD_ID,
        "--single-select-option-id", STATUS_TODO,
    ]
    edit_res = subprocess.run(edit_cmd, capture_output=True, text=True)
    if edit_res.returncode == 0:
        print(f"  -> Set status to 'Todo'")
    else:
        print(f"  [ERROR] Failed to set status: {edit_res.stderr}")

print("Tasks 17 and 18 added to project board!")
