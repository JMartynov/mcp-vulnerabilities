"""Site builder exporting the unified vulnerability and MCP server catalog into static assets for GitHub Pages."""

from __future__ import annotations

import gzip
import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.catalog import (
    UnifiedMcpSecurityRecord,
    build_unified_mcp_security_catalog,
)

logger = logging.getLogger(__name__)


def build_static_site_data(
    data_dir: str | Path = "data/vulnerabilities",
    output_dir: str | Path = "docs/data",
    passports_path: str | Path | None = None,
    num_shards: int = 32,
) -> dict[str, Any]:
    """
    Compiles static data assets for the web explorer:
    1. docs/data/vulnerabilities.json: Consolidated OSV advisories.
    2. docs/data/analytics.json: Ecosystem metrics, risk tier distributions, and OWASP MCP stats.
    3. docs/data/mcp_catalog_index.json: Fast, lightweight search index of all known MCP servers.
    4. docs/data/shards/shard_<00..1f>.json: Partitioned deep records with version-separated vulnerability
       timelines, capability risk scores, and tool parameter schemas.
    """
    in_dir = Path(data_dir)
    out_dir = Path(output_dir)
    shards_dir = out_dir / "shards"
    shards_dir.mkdir(parents=True, exist_ok=True)

    # 1. Consolidate OSV Advisories
    advisories: list[dict[str, Any]] = []
    if in_dir.exists():
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

    vuln_file = out_dir / "vulnerabilities.json"
    vuln_file.write_text(
        json.dumps(advisories, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info("Exported %d advisories -> %s", len(advisories), vuln_file)

    # 2. Build Unified MCP Security Catalog
    raw_catalog = build_unified_mcp_security_catalog(
        passports_path=passports_path,
        vulnerabilities_dir=in_dir,
    )
    catalog = {
        k: v for k, v in raw_catalog.items()
        if k not in ("unknown", "", "none") and v.package_name not in ("unknown", "", "none")
    }
    logger.info("Built unified MCP catalog with %d server records", len(catalog))

    # 3. Partition Catalog into Shards and Build Index
    shards: dict[str, dict[str, Any]] = {
        f"{i:02x}": {} for i in range(num_shards)
    }
    catalog_index: list[dict[str, Any]] = []

    risk_tier_counts: dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    vuln_servers_count = 0
    safe_servers_count = 0

    for rec_key, record in catalog.items():
        if record.is_vulnerable:
            vuln_servers_count += 1
        else:
            safe_servers_count += 1

        tier = record.static_risk_tier.upper() if record.static_risk_tier else "LOW"
        risk_tier_counts[tier] = risk_tier_counts.get(tier, 0) + 1

        # Shard calculation (SHA256 hex mod num_shards)
        norm_key = f"{record.ecosystem}:{record.package_name}".lower()
        shard_num = int(hashlib.sha256(norm_key.encode("utf-8")).hexdigest()[:8], 16) % num_shards
        shard_id = f"{shard_num:02x}"
        shard_file = f"shard_{shard_id}.json"

        rec_dict = record.to_dict()
        # Optimize version advisories for browser payload efficiency
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

        shards[shard_id][record.package_name] = rec_dict

        tools_count = len(record.versions[0].tools) if record.versions else 0
        tools_sample = [t.name for t in (record.versions[0].tools[:5] if record.versions else [])]

        catalog_index.append({
            "id": f"{record.ecosystem}:{record.package_name}",
            "package_name": record.package_name,
            "ecosystem": record.ecosystem,
            "purl": record.purl,
            "display_name": record.display_name or record.package_name,
            "description": record.description or "",
            "author": record.author or "",
            "license": record.license or "",
            "repository_url": record.repository_url or "",
            "homepage_url": record.homepage_url or "",
            "latest_version": record.latest_version,
            "recommended_safe_version": record.recommended_safe_version,
            "is_vulnerable": record.is_vulnerable,
            "vulnerable_versions_count": sum(1 for v in record.versions if v.is_vulnerable),
            "total_versions_count": len(record.versions),
            "security_summary": record.security_summary,
            "static_risk_score": record.static_risk_score,
            "static_risk_tier": record.static_risk_tier,
            "tools_count": tools_count,
            "tools_sample": tools_sample,
            "shard_id": shard_id,
            "shard_file": shard_file,
        })

    # Sort index deterministically: vulnerable first, then alphabetical by package_name
    catalog_index.sort(key=lambda x: (not x["is_vulnerable"], x["package_name"].lower()))

    index_file = out_dir / "mcp_catalog_index.json"
    index_file.write_text(
        json.dumps(catalog_index, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info("Exported MCP catalog index (%d records) -> %s", len(catalog_index), index_file)

    # Write each shard file
    shard_paths: list[Path] = []
    for s_id, s_data in shards.items():
        s_file = shards_dir / f"shard_{s_id}.json"
        s_file.write_text(
            json.dumps(s_data, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        shard_paths.append(s_file)
    logger.info("Exported %d shards to %s", len(shard_paths), shards_dir)

    # 4. Calculate Analytics
    tools_stats: dict[str, Any] = {}
    owasp_stats: dict[str, Any] = {}
    ecosystems: dict[str, int] = {}

    for adv in advisories:
        adv_tools = set()
        adv_owasp = set()
        adv_ecosystems = set()
        adv_cvss = None
        adv_severity = None

        for affected in adv.get("affected", []):
            pkg = affected.get("package", {})
            eco = pkg.get("ecosystem")
            if eco:
                adv_ecosystems.add(eco)

            db_spec = affected.get("database_specific", {})
            for t in db_spec.get("vulnerable_tools", []):
                adv_tools.add(t)

            owasp = db_spec.get("owasp_mcp_category")
            if owasp:
                adv_owasp.add(owasp)

            if adv_cvss is None:
                adv_cvss = db_spec.get("cvss_score")
            if adv_severity is None:
                adv_severity = db_spec.get("severity")

        for t in adv_tools:
            if t not in tools_stats:
                tools_stats[t] = {"count": 0, "cvss_sum": 0.0, "cvss_count": 0}
            tools_stats[t]["count"] += 1
            if adv_cvss is not None:
                try:
                    tools_stats[t]["cvss_sum"] += float(adv_cvss)
                    tools_stats[t]["cvss_count"] += 1
                except (ValueError, TypeError):
                    pass

        for o in adv_owasp:
            if o not in owasp_stats:
                owasp_stats[o] = {"count": 0, "severities": {}}
            owasp_stats[o]["count"] += 1
            sev = adv_severity or "UNKNOWN"
            owasp_stats[o]["severities"][sev] = owasp_stats[o]["severities"].get(sev, 0) + 1

        for eco in adv_ecosystems:
            ecosystems[eco] = ecosystems.get(eco, 0) + 1

    top_tools = []
    for t, stats in tools_stats.items():
        avg_cvss = (stats["cvss_sum"] / stats["cvss_count"]) if stats["cvss_count"] > 0 else 0.0
        top_tools.append({
            "tool": t,
            "count": stats["count"],
            "avg_cvss": round(avg_cvss, 1),
        })
    top_tools = sorted(top_tools, key=lambda x: x["count"], reverse=True)[:10]

    total_owasp = sum(stat["count"] for stat in owasp_stats.values())
    owasp_breakdown = []
    for cat, stats in owasp_stats.items():
        pct = (stats["count"] / total_owasp * 100) if total_owasp > 0 else 0.0
        owasp_breakdown.append({
            "category": cat,
            "count": stats["count"],
            "percentage": round(pct, 1),
            "severities": stats["severities"],
        })
    owasp_breakdown = sorted(owasp_breakdown, key=lambda x: x["count"], reverse=True)

    analytics_data = {
        "total_advisories": len(advisories),
        "total_servers": len(catalog_index),
        "vulnerable_servers_count": vuln_servers_count,
        "safe_servers_count": safe_servers_count,
        "risk_tier_counts": risk_tier_counts,
        "top_tools": top_tools,
        "owasp_breakdown": owasp_breakdown,
        "ecosystems": ecosystems,
    }

    analytics_file = out_dir / "analytics.json"
    analytics_file.write_text(
        json.dumps(analytics_data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info("Exported analytics metrics -> %s", analytics_file)

    return {
        "vulnerabilities": vuln_file,
        "mcp_catalog_index": index_file,
        "analytics": analytics_file,
        "shards": shard_paths,
    }


def build_site_data(
    data_dir: str | Path = "data/vulnerabilities",
    output_dir: str | Path = "docs/data",
    passports_path: str | Path | None = None,
    num_shards: int = 32,
) -> Path:
    """Backward-compatible wrapper returning the Path to vulnerabilities.json."""
    res = build_static_site_data(
        data_dir=data_dir,
        output_dir=output_dir,
        passports_path=passports_path,
        num_shards=num_shards,
    )
    return res["vulnerabilities"]


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    build_static_site_data()
