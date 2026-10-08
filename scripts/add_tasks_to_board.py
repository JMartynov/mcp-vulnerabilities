"""Add Tasks 08 to 13 to private GitHub Project 4."""

from __future__ import annotations

import subprocess
from pathlib import Path

TASKS = [
    ("Automated Catalog Enrichment Cron in CI", ".jules/task08_daily_sync_enrich_cron.md"),
    ("AI Client Config Auto-Fixer (cli fix-config)", ".jules/task09_client_config_autofixer.md"),
    ("Real-Time Threat Feed Webhook Dispatcher", ".jules/task10_threat_feed_webhook_notifier.md"),
    ("Offline Air-Gapped Enterprise Export Bundle", ".jules/task11_airgap_export_bundle.md"),
    ("OWASP MCP Top 10 & CWE Analytics Dashboard", ".jules/task12_owasp_analytics_dashboard.md"),
    ("Official Lightweight Docker Image & GHCR Publish", ".jules/task13_docker_ghcr_container.md"),
]

for title, path_str in TASKS:
    body = Path(path_str).read_text(encoding="utf-8")
    cmd = [
        "gh", "project", "item-create", "4",
        "--owner", "JMartynov",
        "--title", title,
        "--body", body,
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode == 0:
        print(f"Successfully added to Project 4: {title}")
    else:
        print(f"Failed to add {title}: {res.stderr}")

print("All upcoming roadmap tasks added to private board!")
