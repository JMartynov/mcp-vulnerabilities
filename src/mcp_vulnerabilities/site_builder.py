"""Site builder exporting the vulnerability database into static assets for GitHub Pages."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


def build_site_data(
    data_dir: str | Path = "data/vulnerabilities",
    output_dir: str | Path = "docs/data",
) -> Path:
    """Consolidates OSV records into docs/data/vulnerabilities.json for static site searching."""
    in_dir = Path(data_dir)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    advisories: list[dict[str, Any]] = []
    for f in sorted(in_dir.glob("*.json")):
        if f.name in (
            "sync_state.json",
            "index.json",
            "mcp_catalog_state.json",
            "mcp_servers.json",
        ):
            continue
        try:
            adv = json.loads(f.read_text(encoding="utf-8"))
            if isinstance(adv, dict) and "id" in adv:
                advisories.append(adv)
        except Exception as exc:
            logger.debug("Skipping %s: %s", f, exc)

    out_file = out_dir / "vulnerabilities.json"
    out_file.write_text(
        json.dumps(advisories, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info(
        "Exported %d advisories for web explorer -> %s", len(advisories), out_file
    )
    return out_file


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    build_site_data()
