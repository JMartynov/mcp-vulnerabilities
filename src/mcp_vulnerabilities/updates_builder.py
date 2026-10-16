"""Builds per-update release delta feeds and historical updates datasets."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any

from mcp_vulnerabilities import __version__
from mcp_vulnerabilities.catalog import build_unified_mcp_security_catalog

logger = logging.getLogger(__name__)


def build_updates_data(
    output_dir: str | Path = "docs/data/updates",
    version: str | None = None,
    vulnerabilities_dir: str | Path = "data/vulnerabilities",
    passports_path: str | Path | None = None,
) -> dict[str, Path]:
    """
    Computes delta of newly added/updated security advisories and MCP server releases,
    producing:
    - docs/data/updates/latest_update.json
    - docs/data/updates/v<version>.json
    - docs/data/updates/updates_history.json
    """
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    rel_version = version or __version__
    now_iso = datetime.now(timezone.utc).isoformat()

    in_vuln_dir = Path(vulnerabilities_dir)
    advisories: list[dict[str, Any]] = []
    if in_vuln_dir.exists():
        for f in sorted(in_vuln_dir.glob("*.json")):
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

    # Load unified catalog
    raw_catalog = build_unified_mcp_security_catalog(
        passports_path=passports_path,
        vulnerabilities_dir=in_vuln_dir,
    )
    catalog = {
        k: v for k, v in raw_catalog.items()
        if k not in ("unknown", "", "none") and v.package_name not in ("unknown", "", "none")
    }

    # Filter to updated/vulnerable servers for release delta
    updated_servers: list[dict[str, Any]] = []
    for rec in catalog.values():
        if not rec.is_vulnerable and not rec.recommended_safe_version:
            continue

        change_type = "NEW_VULNERABILITY" if rec.is_vulnerable else "PATCHED_VERSION"
        rec_dict = rec.to_dict()
        rec_dict["change_type"] = change_type

        # Optimize advisories
        for v in rec_dict.get("versions", []):
            new_advs = []
            for adv in v.get("advisories", []):
                if isinstance(adv, dict):
                    db_spec = adv.get("database_specific", {})
                    new_advs.append({
                        "id": adv.get("id"),
                        "summary": adv.get("summary", ""),
                        "severity": db_spec.get("severity", "UNKNOWN"),
                        "cvss_score": db_spec.get("cvss_score"),
                        "owasp_mcp_category": db_spec.get("owasp_mcp_category"),
                        "vulnerable_tools": db_spec.get("vulnerable_tools", []),
                        "remediation_guidance": db_spec.get("remediation_guidance", ""),
                    })
                else:
                    new_advs.append({"id": str(adv)})
            v["advisories"] = new_advs

        updated_servers.append(rec_dict)

    # Sort updated servers deterministically
    updated_servers.sort(key=lambda s: (not s.get("is_vulnerable", False), s.get("package_name", "").lower()))

    # Summary counts
    total_new_advs = len(advisories)
    total_updated_servers = len(updated_servers)
    total_versions_tracked = sum(len(s.get("versions", [])) for s in updated_servers)

    summary_counts = {
        "new_advisories": total_new_advs,
        "updated_advisories": total_new_advs,
        "new_mcp_servers": total_updated_servers,
        "updated_mcp_versions": total_versions_tracked,
    }

    # Format release bundle
    release_bundle = {
        "release_version": rel_version,
        "timestamp_utc": now_iso,
        "summary_counts": summary_counts,
        "updated_servers": updated_servers,
        "updated_advisories": advisories[:100],  # sample most relevant
    }

    # Write latest_update.json
    latest_file = out_dir / "latest_update.json"
    latest_file.write_text(
        json.dumps(release_bundle, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info("Exported latest release updates -> %s", latest_file)

    # Write versioned bundle v<version>.json
    version_file = out_dir / f"v{rel_version}.json"
    version_file.write_text(
        json.dumps(release_bundle, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info("Exported versioned release update -> %s", version_file)

    # Update updates_history.json
    history_file = out_dir / "updates_history.json"
    history: list[dict[str, Any]] = []
    if history_file.exists():
        try:
            history = json.loads(history_file.read_text(encoding="utf-8"))
        except Exception:
            history = []

    # Update or prepend current release in history
    history = [h for h in history if h.get("release_version") != rel_version]
    history.insert(0, {
        "release_version": rel_version,
        "timestamp_utc": now_iso,
        "summary_counts": summary_counts,
        "data_file": f"v{rel_version}.json",
    })

    history_file.write_text(
        json.dumps(history, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info("Updated release history (%d releases) -> %s", len(history), history_file)

    return {
        "latest": latest_file,
        "versioned": version_file,
        "history": history_file,
    }


def main():
    parser = argparse.ArgumentParser(description="Build per-release update delta feeds and historical updates datasets.")
    parser.add_argument("--output-dir", default="docs/data/updates", help="Output directory for updates data")
    parser.add_argument("--version", default=None, help="Release version (defaults to mcp_vulnerabilities.__version__)")
    parser.add_argument("--vulnerabilities-dir", default="data/vulnerabilities", help="Directory of OSV advisories")
    parser.add_argument("--passports-path", default=None, help="Path to passports.json.gz")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO)
    build_updates_data(
        output_dir=args.output_dir,
        version=args.version,
        vulnerabilities_dir=args.vulnerabilities_dir,
        passports_path=args.passports_path,
    )


if __name__ == "__main__":
    main()
