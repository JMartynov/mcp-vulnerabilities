"""Site builder exporting the unified vulnerability and MCP server catalog into static assets for GitHub Pages."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import os
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path
from typing import Any

from mcp_fingerprints.models import ServerPackageSpec
from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher
from mcp_vulnerabilities.catalog import (
    UnifiedMcpSecurityRecord,
    VersionSecurityRecord,
    ToolSecurityAssessment,
    _load_passports,
    _parse_sort_version,
    compute_remediation_target,
    generate_upgrade_command,
    build_unified_mcp_security_catalog,
)
from mcp_vulnerabilities.analyzers.capability_classifier import (
    analyze_tool_security,
    classify_server_security_profile,
    generate_server_security_summary,
    generate_tool_security_comment,
)
from mcp_vulnerabilities.models import OsvVulnerability
from mcp_vulnerabilities.cache import TwoTierVulnerabilityCache

logger = logging.getLogger(__name__)


def _process_server_batch(
    servers: dict[str, Any],
    vulnerabilities_dir: str,
    use_cache: bool,
) -> dict[str, dict[str, Any]]:
    """
    Worker function to process a batch of servers and evaluate vulnerabilities.
    Returns serialized dict representations of UnifiedMcpSecurityRecords.
    """
    try:
        matcher = VulnerabilityMatcher.from_directory(Path(vulnerabilities_dir))
    except Exception:
        # Fallback if it's a snapshot or file
        matcher = VulnerabilityMatcher.from_snapshot(Path(vulnerabilities_dir))
        
    cache = TwoTierVulnerabilityCache() if use_cache else None

    results = {}
    warnings = []

    for pkg_name, raw_spec in servers.items():
        try:
            if isinstance(raw_spec, dict):
                spec = ServerPackageSpec.from_dict(raw_spec)
            else:
                spec = raw_spec
            norm_name = VulnerabilityMatcher._normalize_package_name(spec.package_name)
            candidate_advs = matcher._package_index.get(norm_name, [])

            # Compute OSV index hash
            advs_json = json.dumps(candidate_advs, sort_keys=True)
            osv_index_hash = hashlib.sha256(advs_json.encode("utf-8")).hexdigest()
            passport_canonical_hash = hashlib.sha256(json.dumps(spec.to_dict(), sort_keys=True).encode("utf-8")).hexdigest()

            cached_data = None
            if cache:
                cached_data = cache.get(passport_canonical_hash, osv_index_hash)

            if cached_data:
                results[pkg_name] = cached_data
                continue

            version_records: list[VersionSecurityRecord] = []
            all_tools_for_scoring: list[dict[str, Any]] = []

            for vf in spec.versions:
                ver_str = vf.version
                is_vuln = False
                matching_advs: list[OsvVulnerability] = []

                for adv_dict in candidate_advs:
                    for affected in adv_dict.get("affected", []):
                        pkg_meta = affected.get("package", {})
                        if (
                            VulnerabilityMatcher._normalize_package_name(pkg_meta.get("name", ""))
                            != norm_name
                        ):
                            continue

                        eco = pkg_meta.get("ecosystem", "").lower()
                        if eco and spec.ecosystem:
                            spec_eco = spec.ecosystem.lower()
                            if eco != spec_eco:
                                if eco == "pypi" and spec_eco in ("pypi", "pip") or eco == "golang" and spec_eco in ("go", "golang"):
                                    pass
                                else:
                                    continue

                        ranges = affected.get("ranges", [])
                        versions = affected.get("versions", [])
                        if matcher._is_version_in_ranges(ver_str, ranges, versions):
                            is_vuln = True
                            try:
                                matching_advs.append(OsvVulnerability.from_dict(adv_dict))
                            except Exception:
                                pass

                tool_assessments: list[ToolSecurityAssessment] = []
                for tool in vf.tool_signatures:
                    tool_dict = tool.to_dict()
                    all_tools_for_scoring.append(tool_dict)
                    analysis = analyze_tool_security(tool_dict)
                    comment = generate_tool_security_comment(
                        tool=tool_dict,
                        analysis=analysis,
                        affecting_advisories=[a.id for a in matching_advs],
                    )
                    assessment = ToolSecurityAssessment(
                        name=tool.name,
                        canonical_hash=tool.canonical_hash,
                        description=tool.description,
                        risk_score=float(analysis.get("risk_score", 0.0)),
                        risk_tier=analysis.get("risk_tier", "LOW"),
                        security_comment=comment,
                        parameters=tool.parameters,
                        annotations=tool.annotations,
                    )
                    tool_assessments.append(assessment)

                v_record = VersionSecurityRecord(
                    version=ver_str,
                    is_vulnerable=is_vuln,
                    advisories=matching_advs,
                    toolset_canonical_hash=vf.toolset_canonical_hash,
                    tools=tool_assessments,
                    prompts=list(vf.prompt_signatures),
                    resources=list(vf.resource_signatures),
                    release_date=vf.release_date,
                    required_env_vars=vf.required_env_vars,
                )
                version_records.append(v_record)

            version_records.sort(key=lambda r: _parse_sort_version(r.version))

            for v_rec in version_records:
                if v_rec.is_vulnerable:
                    rec_ver = compute_remediation_target(v_rec.version, version_records)
                    v_rec.recommended_update_version = rec_ver
                    if rec_ver:
                        v_rec.upgrade_command = generate_upgrade_command(
                            spec.ecosystem,
                            spec.package_name,
                            rec_ver,
                        )
                    else:
                        v_rec.no_fix_available = True

            latest_version = version_records[-1].version if version_records else ""
            recommended_safe_version: str | None = None
            for r in reversed(version_records):
                if not r.is_vulnerable:
                    recommended_safe_version = r.version
                    break

            overall_vuln = any(r.is_vulnerable for r in version_records)

            profile = classify_server_security_profile(all_tools_for_scoring)
            vuln_count = sum(1 for r in version_records if r.is_vulnerable)
            safe_count = len(version_records) - vuln_count
            sec_summary = generate_server_security_summary(
                package_name=spec.package_name,
                profile=profile,
                vuln_versions_count=vuln_count,
                safe_versions_count=safe_count,
            )

            record = UnifiedMcpSecurityRecord(
                package_name=spec.package_name,
                ecosystem=spec.ecosystem,
                purl=spec.purl,
                display_name=spec.display_name or spec.package_name,
                description=spec.description,
                author=spec.author,
                repository_url=spec.repository_url,
                homepage_url=spec.homepage_url,
                license=spec.license,
                latest_version=latest_version,
                recommended_safe_version=recommended_safe_version,
                is_vulnerable=overall_vuln,
                security_summary=sec_summary,
                static_risk_score=float(profile.get("overall_risk_score", 0.0)),
                static_risk_tier=profile.get("risk_tier", "LOW"),
                versions=version_records,
            )
            
            record_dict = record.to_dict()
            results[pkg_name] = record_dict
            
            if cache:
                cache.set(passport_canonical_hash, osv_index_hash, record_dict)
                
        except Exception as e:
            msg = f"Error processing server {pkg_name}: {e}"
            logger.warning(msg)
            warnings.append(msg)
            
    return results, warnings


def build_site_parallel(
    passports_path: str | Path | None = None,
    vuln_path: str | Path | None = None,
    output_dir: str | Path = "docs/data",
    workers: int = 4,
    use_cache: bool = True,
    num_shards: int = 32,
    benchmark: bool = False,
) -> dict[str, Any]:
    """Parallel implementation of site builder."""
    t0 = time.time()
    
    in_dir = Path(vuln_path) if vuln_path else Path("data/vulnerabilities")
    out_dir = Path(output_dir)
    shards_dir = out_dir / "shards"
    shards_dir.mkdir(parents=True, exist_ok=True)

    # 1. Consolidate OSV Advisories
    advisories: list[dict[str, Any]] = []
    if in_dir.exists() and in_dir.is_dir():
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
    t1 = time.time()

    # 2. Build Unified MCP Security Catalog in Parallel
    if passports_path:
        p = Path(passports_path)
        if p.exists():
            if p.suffix == ".gz":
                with gzip.open(p, "rt", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                data = json.loads(p.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                passports = data.get("passports", data)
            elif isinstance(data, list):
                passports = {item.get("package_name", str(i)): item for i, item in enumerate(data) if isinstance(item, dict)}
            else:
                passports = _load_passports(passports_path)
        else:
            passports = _load_passports(passports_path)
    else:
        passports = _load_passports(passports_path)
    
    # Split passports into chunks
    items = list(passports.items())
    chunk_size = max(1, len(items) // workers)
    chunks = [dict(items[i:i + chunk_size]) for i in range(0, len(items), chunk_size)]
    
    catalog_dicts: dict[str, Any] = {}
    
    all_warnings = []
    with ProcessPoolExecutor(max_workers=workers) as executor:
        futures = [
            executor.submit(_process_server_batch, chunk, str(in_dir), use_cache)
            for chunk in chunks
        ]
        for future in as_completed(futures):
            try:
                res = future.result()
                if isinstance(res, tuple):
                    result, batch_warnings = res
                    for w in batch_warnings:
                        logger.warning(w)
                    all_warnings.extend(batch_warnings)
                else:
                    result = res
                catalog_dicts.update(result)
            except BaseException as e:
                msg = f"Worker batch exception: A process in the process pool was terminated abruptly or failed: {type(e).__name__}"
                logger.error(msg)
                all_warnings.append(msg)
                
    if all_warnings:
        errors_file = out_dir / "build_errors.json"
        errors_file.write_text(json.dumps(all_warnings, indent=2), encoding="utf-8")
                
    # Also handle advisory-only packages not in passports (from matcher index)
    # We can use the original function for this part if needed, or simply let the old function run for them.
    # To keep it completely identical, we should probably run the old function on the remainder, or just
    # do a quick sync run for them.
    
    # We can just call build_unified_mcp_security_catalog and only extract the missing ones.
    # Actually, building advisory-only packages is very fast since they have no tools to score.
    # We can construct them here or use a helper.
    # For now, let's replicate the advisory-only logic.
    
    matcher = VulnerabilityMatcher.from_directory(in_dir) if in_dir.is_dir() else VulnerabilityMatcher.from_snapshot(in_dir)
    
    for norm_name, advs in matcher._package_index.items():
        if any(
            VulnerabilityMatcher._normalize_package_name(p) == norm_name
            for p in passports
        ):
            continue

        first_adv = advs[0]
        pkg_name = norm_name
        eco = "generic"
        for aff in first_adv.get("affected", []):
            p = aff.get("package", {})
            if VulnerabilityMatcher._normalize_package_name(p.get("name", "")) == norm_name:
                pkg_name = p.get("name", norm_name)
                eco = p.get("ecosystem", "generic")
                break

        discrete_versions = set()
        for adv_dict in advs:
            for aff in adv_dict.get("affected", []):
                for v in aff.get("versions", []):
                    discrete_versions.add(str(v))
                for r in aff.get("ranges", []):
                    for ev in r.get("events", []):
                        if "fixed" in ev:
                            discrete_versions.add(str(ev["fixed"]))
                        if "introduced" in ev and str(ev["introduced"]) != "0":
                            discrete_versions.add(str(ev["introduced"]))

        v_list = sorted(list(discrete_versions), key=_parse_sort_version)
        if not v_list:
            v_list = ["1.0.0"]

        syn_version_records: list[VersionSecurityRecord] = []
        for ver_str in v_list:
            is_vuln = False
            matching_advs: list[OsvVulnerability] = []
            for adv_dict in advs:
                for aff in adv_dict.get("affected", []):
                    if VulnerabilityMatcher._normalize_package_name(aff.get("package", {}).get("name", "")) != norm_name:
                        continue
                    ranges = aff.get("ranges", [])
                    versions = aff.get("versions", [])
                    if matcher._is_version_in_ranges(ver_str, ranges, versions):
                        try:
                            matching_advs.append(OsvVulnerability.from_dict(adv_dict))
                        except Exception:
                            matching_advs.append(adv_dict)

            if matching_advs:
                is_vuln = True

            syn_version_records.append(
                VersionSecurityRecord(
                    version=ver_str,
                    is_vulnerable=is_vuln,
                    advisories=matching_advs,
                    tools=[],
                )
            )

        for v_rec in syn_version_records:
            if v_rec.is_vulnerable:
                rec_ver = compute_remediation_target(v_rec.version, syn_version_records)
                v_rec.recommended_update_version = rec_ver
                if rec_ver:
                    v_rec.upgrade_command = generate_upgrade_command(
                        eco,
                        pkg_name,
                        rec_ver,
                    )
                else:
                    v_rec.no_fix_available = True

        latest_version = syn_version_records[-1].version
        rec_safe = None
        for r in reversed(syn_version_records):
            if not r.is_vulnerable:
                rec_safe = r.version
                break

        record = UnifiedMcpSecurityRecord(
            package_name=pkg_name,
            ecosystem=eco,
            purl=f"pkg:{eco.lower()}/{pkg_name}",
            display_name=pkg_name,
            description=first_adv.get("summary", ""),
            latest_version=latest_version,
            recommended_safe_version=rec_safe,
            is_vulnerable=True,
            security_summary=f"Package `{pkg_name}` has {len(advs)} security advisories.",
            versions=syn_version_records,
        )
        catalog_dicts[pkg_name] = record.to_dict()

    catalog = {
        k: v for k, v in catalog_dicts.items()
        if k not in ("unknown", "", "none") and v.get("package_name") not in ("unknown", "", "none")
    }
    
    t2 = time.time()

    # 3. Partition Catalog into Shards and Build Index
    shards: dict[str, dict[str, Any]] = {
        f"{i:02x}": {} for i in range(num_shards)
    }
    catalog_index: list[dict[str, Any]] = []

    risk_tier_counts: dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    vuln_servers_count = 0
    safe_servers_count = 0

    for rec_key, record in catalog.items():
        is_vuln = record.get("is_vulnerable", False)
        if is_vuln:
            vuln_servers_count += 1
        else:
            safe_servers_count += 1

        tier = record.get("static_risk_tier", "LOW")
        tier = tier.upper() if tier else "LOW"
        risk_tier_counts[tier] = risk_tier_counts.get(tier, 0) + 1

        # Shard calculation (SHA256 hex mod num_shards)
        ecosystem = record.get("ecosystem", "")
        pkg_name = record.get("package_name", "")
        norm_key = f"{ecosystem}:{pkg_name}".lower()
        shard_num = int(hashlib.sha256(norm_key.encode("utf-8")).hexdigest()[:8], 16) % num_shards
        shard_id = f"{shard_num:02x}"
        shard_file = f"shard_{shard_id}.json"

        rec_dict = record
        # Optimize version advisories for browser payload efficiency
        for v in rec_dict.get("versions", []):
            new_advs = []
            for adv in v.get("advisories", []):
                if isinstance(adv, dict):
                    if "database_specific" in adv:
                        db_spec = adv.get("database_specific", {})
                    else:
                        db_spec = adv
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

        shards[shard_id][pkg_name] = rec_dict

        versions = record.get("versions", [])
        tools = versions[0].get("tools", []) if versions else []
        tools_count = len(tools)
        tools_sample = [t.get("name") for t in tools[:5]]

        vuln_versions_count = sum(1 for v in versions if v.get("is_vulnerable"))

        catalog_index.append({
            "id": f"{ecosystem}:{pkg_name}",
            "package_name": pkg_name,
            "ecosystem": ecosystem,
            "purl": record.get("purl"),
            "display_name": record.get("display_name") or pkg_name,
            "description": record.get("description", ""),
            "author": record.get("author", ""),
            "license": record.get("license", ""),
            "repository_url": record.get("repository_url", ""),
            "homepage_url": record.get("homepage_url", ""),
            "latest_version": record.get("latest_version"),
            "recommended_safe_version": record.get("recommended_safe_version"),
            "is_vulnerable": is_vuln,
            "vulnerable_versions_count": vuln_versions_count,
            "total_versions_count": len(versions),
            "security_summary": record.get("security_summary"),
            "static_risk_score": record.get("static_risk_score"),
            "static_risk_tier": record.get("static_risk_tier"),
            "tools_count": tools_count,
            "tools_sample": tools_sample,
            "shard_id": shard_id,
            "shard_file": shard_file,
        })

    # Sort shards alphabetically by package_name to maintain Sort Order Parity
    for s_id in shards:
        shards[s_id] = {k: shards[s_id][k] for k in sorted(shards[s_id].keys(), key=lambda x: x.lower())}

    # Sort index deterministically: vulnerable first, then alphabetical by package_name
    catalog_index.sort(key=lambda x: (not x["is_vulnerable"], x["package_name"].lower()))

    index_file = out_dir / "mcp_catalog_index.json"
    index_file.write_text(
        json.dumps(catalog_index, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
    )

    shard_paths: list[Path] = []
    for s_id, s_data in shards.items():
        s_file = shards_dir / f"shard_{s_id}.json"
        s_file.write_text(
            json.dumps(s_data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
        )
        shard_paths.append(s_file)

    t3 = time.time()

    # 4. Calculate Analytics
    tools_stats: dict[str, Any] = {}
    owasp_stats: dict[str, Any] = {}
    ecosystems: dict[str, int] = {}

    fs_read_write = 0
    shell_exec = 0
    network_egress = 0
    mutating_tools = 0
    read_only_tools = 0

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

    import collections
    env_vars = collections.Counter()
    tool_counts = collections.defaultdict(set)
    transports_dist = collections.Counter()
    
    for s_id, s_data in shards.items():
        for pkg, pkg_data in s_data.items():
            has_fs = False
            has_shell = False
            has_network = False
            has_mutating = False
            has_tools = False
            
            versions = pkg_data.get("versions", [])
            if not versions:
                continue
            v = versions[0]
            
            req_envs = v.get("required_env_vars", [])
            for env in req_envs:
                env_vars[env] += 1
                
            tools = v.get("tools", [])
            if tools:
                has_tools = True
            for t in tools:
                name = t.get("name")
                chash = t.get("canonical_hash")
                if name and chash:
                    tool_counts[name].add(chash)
                
                tname = (t.get("name") or "").lower()
                if any(x in tname for x in ["read", "write", "file", "fs", "path", "dir"]): has_fs = True
                if any(x in tname for x in ["exec", "bash", "cmd", "shell", "run", "script"]): has_shell = True
                if any(x in tname for x in ["http", "request", "fetch", "url", "network", "api", "curl"]): has_network = True
                if any(x in tname for x in ["create", "update", "delete", "write", "insert", "put", "post", "remove", "add", "set"]): has_mutating = True
            
            if has_fs: fs_read_write += 1
            if has_shell: shell_exec += 1
            if has_network: network_egress += 1
            
            if has_tools:
                if has_mutating: mutating_tools += 1
                else: read_only_tools += 1

    patched_remediable_count = 0
    zero_day_unpatched_count = 0
    for s in catalog_index:
        if s.get("is_vulnerable"):
            if s.get("recommended_safe_version"):
                patched_remediable_count += 1
            else:
                zero_day_unpatched_count += 1
                
    if passports_path:
        p = Path(passports_path)
        if p.exists():
            try:
                if p.suffix == ".gz":
                    with gzip.open(p, "rt", encoding="utf-8") as f:
                        data = json.load(f)
                else:
                    data = json.loads(p.read_text(encoding="utf-8"))
                passports_data = data.get("passports", data) if isinstance(data, dict) else data
                if isinstance(passports_data, dict):
                    for k, v in passports_data.items():
                        transports_dist[v.get("transport", "unknown")] += 1
            except Exception:
                pass
    else:
        try:
            ps = _load_passports(None)
            for k, v in ps.items():
                transports_dist[v.get("transport", "unknown")] += 1
        except Exception:
            pass

    shadow_list = []
    for tname, hashes in tool_counts.items():
        if len(hashes) > 1:
            shadow_list.append({"tool": tname, "entropy": len(hashes)})
    shadow_list.sort(key=lambda x: x["entropy"], reverse=True)

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
        "patched_remediable_count": patched_remediable_count,
        "zero_day_unpatched_count": zero_day_unpatched_count,
        "capabilities": {
            "fs_read_write": fs_read_write,
            "shell_exec": shell_exec,
            "network_egress": network_egress,
            "mutating": mutating_tools,
            "read_only": read_only_tools,
        },
        "top_secrets": [{"name": k, "count": v} for k, v in env_vars.most_common(10)],
        "transports": dict(transports_dist),
        "tool_shadowing": shadow_list[:10],
        "risk_tier_counts": risk_tier_counts,
        "top_tools": top_tools,
        "owasp_breakdown": owasp_breakdown,
        "ecosystems": ecosystems,
    }

    analytics_file = out_dir / "analytics.json"
    analytics_file.write_text(
        json.dumps(analytics_data, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8"
    )
    
    t4 = time.time()
    
    if benchmark:
        print(f"Benchmark Results:")
        print(f"  OSV Consolidate: {t1-t0:.3f}s")
        print(f"  Catalog Eval:    {t2-t1:.3f}s")
        print(f"  Sharding/Index:  {t3-t2:.3f}s")
        print(f"  Analytics:       {t4-t3:.3f}s")
        print(f"  Total Time:      {t4-t0:.3f}s")

    return {
        "vulnerabilities": vuln_file,
        "mcp_catalog_index": index_file,
        "analytics": analytics_file,
        "shards": shard_paths,
    }


def build_static_site_data(
    data_dir: str | Path = "data/vulnerabilities",
    output_dir: str | Path = "docs/data",
    passports_path: str | Path | None = None,
    num_shards: int = 32,
    workers: int = 1,
    use_cache: bool = False,
    benchmark: bool = False,
) -> dict[str, Any]:
    """
    Compiles static data assets for the web explorer.
    Delegates to build_site_parallel.
    """
    return build_site_parallel(
        passports_path=passports_path,
        vuln_path=data_dir,
        output_dir=output_dir,
        workers=workers,
        use_cache=use_cache,
        num_shards=num_shards,
        benchmark=benchmark,
    )


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
    parser = argparse.ArgumentParser(description="Multi-Core Parallel Site Builder")
    parser.add_argument("--data-dir", default="data/vulnerabilities", help="Vulnerabilities directory")
    parser.add_argument("--output-dir", default="docs/data", help="Output directory")
    parser.add_argument("--passports", default=None, help="Passports file path")
    parser.add_argument("--workers", type=int, default=os.cpu_count() or 4, help="Worker concurrency")
    parser.add_argument("--no-cache", action="store_true", help="Force complete re-evaluation without cache")
    parser.add_argument("--benchmark", action="store_true", help="Print detailed timing breakdown")
    args = parser.parse_args()
    
    build_static_site_data(
        data_dir=args.data_dir,
        output_dir=args.output_dir,
        passports_path=args.passports,
        workers=args.workers,
        use_cache=not args.no_cache,
        benchmark=args.benchmark,
    )
