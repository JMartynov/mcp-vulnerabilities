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
        # Only include servers with is_vulnerable == True OR genuinely updated records 
        # where we might determine change_type
        if not rec.is_vulnerable and not any(v.is_vulnerable for v in rec.versions):
            continue

        change_type = "NEW_VULNERABILITY" if rec.is_vulnerable else "PATCHED_VERSION"
        if change_type not in ("NEW_VULNERABILITY", "NEW_SERVER", "NEW_VERSION", "PATCHED_VERSION"):
            continue

        rec_dict = rec.to_dict()
        rec_dict["change_type"] = change_type

        # Optimize versions: keep recommended safe version, latest version, and recent versions (up to 2)
        all_vers = rec_dict.get("versions", [])
        if len(all_vers) > 2:
            keep_vers = set()
            if rec_dict.get("recommended_safe_version"):
                keep_vers.add(rec_dict["recommended_safe_version"])
            if rec_dict.get("latest_version"):
                keep_vers.add(rec_dict["latest_version"])
            for v in all_vers[-2:]:
                keep_vers.add(v.get("version"))
            rec_dict["versions"] = [v for v in all_vers if v.get("version") in keep_vers]

        # Optimize advisories
        for v in rec_dict.get("versions", []):
            new_advs = []
            for adv in v.get("advisories", []):
                if isinstance(adv, dict):
                    db_spec = adv.get("database_specific", {})
                    adv_item: dict[str, Any] = {
                        "id": adv.get("id"),
                        "summary": (adv.get("summary") or "")[:100],
                        "severity": db_spec.get("severity", "UNKNOWN"),
                    }
                    if db_spec.get("cvss_score"):
                        adv_item["cvss_score"] = db_spec.get("cvss_score")
                    if db_spec.get("owasp_mcp_category"):
                        adv_item["owasp_mcp_category"] = db_spec.get("owasp_mcp_category")
                    if db_spec.get("vulnerable_tools"):
                        adv_item["vulnerable_tools"] = db_spec.get("vulnerable_tools")
                    if db_spec.get("remediation_guidance"):
                        adv_item["remediation_guidance"] = db_spec.get("remediation_guidance")
                    new_advs.append(adv_item)
                else:
                    new_advs.append({"id": str(adv)})
            v["advisories"] = new_advs

        updated_servers.append(rec_dict)

    # Sort updated servers deterministically
    updated_servers.sort(key=lambda s: (not s.get("is_vulnerable", False), s.get("package_name", "").lower()))

    history_file = out_dir / "updates_history.json"
    history: list[dict[str, Any]] = []
    if history_file.exists():
        try:
            history = json.loads(history_file.read_text(encoding="utf-8"))
        except Exception:
            history = []

    prev_history = [h for h in history if h.get("release_version") != rel_version]
    
    current_total_advs = len(advisories)
    current_total_servers = len(catalog)
    current_total_versions = sum(len(s.versions) for s in catalog.values())
    
    new_advisories = current_total_advs
    updated_advisories = 0
    new_mcp_servers = current_total_servers
    updated_mcp_versions = current_total_versions
    
    if prev_history:
        prev_entry = prev_history[0]
        if "cumulative_totals" in prev_entry:
            prev_total_advs = prev_entry["cumulative_totals"].get("total_advisories", 0)
            prev_total_servers = prev_entry["cumulative_totals"].get("total_servers", 0)
            prev_total_versions = prev_entry["cumulative_totals"].get("total_versions", 0)
        else:
            prev_counts = prev_entry.get("summary_counts", {})
            prev_total_advs = prev_counts.get("new_advisories", 0)
            prev_total_servers = prev_counts.get("new_mcp_servers", 0)
            prev_total_versions = prev_counts.get("updated_mcp_versions", 0)
        
        new_advisories = max(0, current_total_advs - prev_total_advs)
        new_mcp_servers = max(0, current_total_servers - prev_total_servers)
        updated_mcp_versions = max(0, current_total_versions - prev_total_versions)

    summary_counts = {
        "new_advisories": new_advisories,
        "updated_advisories": updated_advisories,
        "new_mcp_servers": new_mcp_servers,
        "updated_mcp_versions": updated_mcp_versions,
    }
    
    cumulative_totals = {
        "total_advisories": current_total_advs,
        "total_servers": current_total_servers,
        "total_versions": current_total_versions,
    }

    # Format release bundle
    release_bundle = {
        "release_version": rel_version,
        "timestamp_utc": now_iso,
        "summary_counts": summary_counts,
        "updated_servers": updated_servers,
        "updated_advisories": advisories[:30],  # sample most relevant
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

    # Update or prepend current release in history
    history = [h for h in history if h.get("release_version") != rel_version]
    history.insert(0, {
        "release_version": rel_version,
        "timestamp_utc": now_iso,
        "summary_counts": summary_counts,
        "cumulative_totals": cumulative_totals,
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
