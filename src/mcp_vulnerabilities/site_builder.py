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
    
    # Calculate analytics
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
            
            tools = db_spec.get("vulnerable_tools", [])
            for t in tools:
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
                tools_stats[t]["cvss_sum"] += float(adv_cvss)
                tools_stats[t]["cvss_count"] += 1
                
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
            "avg_cvss": round(avg_cvss, 1)
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
            "severities": stats["severities"]
        })
    owasp_breakdown = sorted(owasp_breakdown, key=lambda x: x["count"], reverse=True)
    
    analytics_data = {
        "top_tools": top_tools,
        "owasp_breakdown": owasp_breakdown,
        "ecosystems": ecosystems
    }
    
    analytics_file = out_dir / "analytics.json"
    analytics_file.write_text(
        json.dumps(analytics_data, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    logger.info("Exported analytics metrics -> %s", analytics_file)

    return out_file


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    build_site_data()
