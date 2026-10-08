"""Enrich task descriptions and update project board items using content IDs."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

# Mapping of titles to files and enriched bodies
FILES_MAP = {
    "GitHub API Token & Rate-Limit Protection": ".jules/task01_github_token_rate_limit.md",
    "Pull Request Continuous Integration (ci.yml)": ".jules/task02_pr_ci_workflow.md",
    "Async Catalog Version Enricher": ".jules/task03_async_catalog_enricher.md",
    "OSV Batch Version Stamping (currently_vulnerable)": ".jules/task04_osv_version_stamping.md",
    "Modern Lockfile Auditing (uv.lock, pyproject.toml, poetry.lock)": ".jules/task05_modern_lockfile_auditing.md",
    "Web Explorer UI Enhancements (OSV 1.6 Extensions)": ".jules/task06_web_explorer_ui_enhancements.md",
}

# Fetch live items from Project 4
res = subprocess.run(
    ["gh", "project", "item-list", "4", "--owner", "JMartynov", "--format", "json"],
    capture_output=True,
    text=True,
    check=True,
)
data = json.loads(res.stdout)

for item in data.get("items", []):
    title = item.get("title")
    content_id = item.get("content", {}).get("id")
    if not title or not content_id:
        continue
    
    file_rel = FILES_MAP.get(title)
    if not file_rel:
        continue
    
    body = Path(file_rel).read_text(encoding="utf-8")
    cmd = [
        "gh", "project", "item-edit",
        "--id", content_id,
        "--title", title,
        "--body", body,
    ]
    edit_res = subprocess.run(cmd, capture_output=True, text=True)
    if edit_res.returncode == 0:
        print(f"Successfully enriched Project 4 card: {title} ({content_id})")
    else:
        print(f"Failed to edit {title}: {edit_res.stderr}")

print("All Project 4 task cards updated with deep architectural specifications!")
