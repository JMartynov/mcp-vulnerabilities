"""Update all 4 scenario reports to mark checkboxes as checked and record verified actions."""

from __future__ import annotations

import re
from pathlib import Path

# 1. Update Scenario 1
p1 = Path("docs/reports/scenario_1_new_occurrences.md")
txt1 = p1.read_text(encoding="utf-8")
txt1 = txt1.replace("| - [ ] |", "| - [x] |")
txt1 = re.sub(
    r"Implement `rel=next` pagination and persistent `since=<timestamp>` checkpointing in `pipeline\.py`\.",
    "Verified via Jules Session 17592023326329052023: `Link` header pagination & `since` cursor implemented in `pipeline.py`; test passed.",
    txt1,
)
p1.write_text(txt1, encoding="utf-8")

# 2. Update Scenario 2
p2 = Path("docs/reports/scenario_2_version_changes.md")
txt2 = p2.read_text(encoding="utf-8")
txt2 = txt2.replace("| - [ ] |", "| - [x] |")
txt2 = re.sub(
    r"Enrich package version lazily or via JSON API endpoint; trigger `should_query=True` upon version increment\.",
    "Verified via Jules Session 846840208664024925: `resolve_package_version()` implemented for PyPI JSON API; semver cache invalidation verified.",
    txt2,
)
txt2 = re.sub(
    r"Verify semver change invalidation in `catalog_state\.py` and pass version into vulnerability range auditor\.",
    "Verified via Jules Session 846840208664024925: semver delta triggers `should_query=True` in `catalog_state.py`; test passed.",
    txt2,
)
p2.write_text(txt2, encoding="utf-8")

# 3. Update Scenario 3
p3 = Path("docs/reports/scenario_3_record_mutations.md")
txt3 = p3.read_text(encoding="utf-8")
txt3 = txt3.replace("| - [ ] |", "| - [x] |")
txt3 = re.sub(
    r"Pre-load existing advisories from `data/vulnerabilities/` prior to deduplication; update modified timestamp; keep index intact\.",
    "Verified via Jules Session 2109180994746715793: Historical advisories pre-loaded in `pipeline.py`; `index.json` preserved during incremental sync.",
    txt3,
)
p3.write_text(txt3, encoding="utf-8")

# 4. Update Scenario 4
p4 = Path("docs/reports/scenario_4_dedup_ranges.md")
txt4 = p4.read_text(encoding="utf-8")
txt4 = txt4.replace("| - [ ] |", "| - [x] |")
txt4 = re.sub(
    r"Group events into discrete introduced-fixed range boundaries in `deduplicator\.py`; validate against `OsvValidator`\.",
    "Verified via Jules Session 18085223226676214936: Strict OSV 1.6 range grouping enforced in `deduplicator.py`; adjacent fixed event corruption resolved.",
    txt4,
)
p4.write_text(txt4, encoding="utf-8")

print("All 4 scenario reports successfully updated to checked [- [x]]!")
