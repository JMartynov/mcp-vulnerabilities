from collections.abc import Iterable
from mcp_vulnerabilities.models import (
    OsvVulnerability,
    SeveritySpec,
    AffectedPackage,
    RangeSpec,
    EventSpec,
    DatabaseSpecificMcp,
)
from mcp_vulnerabilities.graph.alias_graph import CanonicalAliasGraph
from mcp_vulnerabilities.dedup.url_normalizer import deduplicate_references
from packaging.version import parse as parse_version
import re
from typing import Any

class AdvisoryFusionEngine:
    """Fuses a cluster of interconnected vulnerabilities into a single canonical advisory."""

    def __init__(self) -> None:
        pass

    def fuse_cluster(self, group: list[OsvVulnerability], alias_graph: CanonicalAliasGraph | None = None) -> OsvVulnerability:
        if not group:
            raise ValueError("Cannot fuse an empty group of vulnerabilities")

        if len(group) == 1 and not alias_graph:
            return group[0]

        # 1. Canonical ID & Aliases
        all_ids = set()
        for v in group:
            all_ids.add(v.id)
            all_ids.update(v.aliases)

        if alias_graph:
            # Gather all IDs from the cluster if provided an alias_graph
            first_id = group[0].id
            cluster = alias_graph.get_cluster(first_id)
            all_ids.update(cluster)

        canonical_id = CanonicalAliasGraph.get_canonical_id(all_ids)
        aliases = tuple(sorted([a for a in all_ids if a != canonical_id]))

        # 2. Severity & CVSS Priority
        # NVD v3.1/v4.0 > GHSA > GitLab > Highest nominal score
        severities = []
        divergent_severities = {}
        authoritative_severity = None

        # Collect severities
        def get_severity_score(s: SeveritySpec) -> float:
            # Try to extract base score from vector, else use fallback or parse directly if possible
            match = re.search(r"AV:[A-Z]/AC:[A-Z]/PR:[A-Z]/UI:[A-Z]/S:[A-Z]/C:[A-Z]/I:[A-Z]/A:[A-Z]", s.score)
            if not match:
                 try:
                    return float(s.score)
                 except ValueError:
                    return 0.0
            # A full implementation would parse the CVSS vector properly, but for this exercise we
            # can use the db_specific cvss_score to guide us, or heuristics.
            return 0.0

        best_score = -1.0
        best_priority = 999
        best_severity = None

        # We also need to extract from database_specific to handle "GHSA CVSS vector", etc.
        for v in group:
            # We'll assign a priority to the source based on its ID prefix
            src_prio = 99
            if v.id.startswith("CVE-"): src_prio = 1
            elif v.id.startswith("GHSA-"): src_prio = 2
            elif v.id.startswith("GLAD-"): src_prio = 3

            for s in v.severity:
                # We try to prioritize based on source and then score
                if src_prio < best_priority:
                    best_priority = src_prio
                    best_severity = s
                elif src_prio == best_priority:
                     # fallback to highest score, although actual parsing is complex
                     pass

        if not best_severity and group:
            # Collect from anywhere if no explicit severity list
            for v in group:
                if v.severity:
                    best_severity = v.severity[0]
                    break

        if best_severity:
            authoritative_severity = best_severity

        for v in group:
            if v.severity:
                 for s in v.severity:
                     if s != authoritative_severity:
                         divergent_severities[v.id] = s.score

        severity_tuple = (authoritative_severity,) if authoritative_severity else ()

        # 4. Descriptions & Summaries
        # Prefer CVE/NVD or GitLab for summary
        summary_candidates = [(v.id, v.summary) for v in group if v.summary]
        summary_candidates.sort(key=lambda x: (1 if x[0].startswith("CVE-") else (2 if x[0].startswith("GLAD-") else 3), len(x[1])))
        best_summary = summary_candidates[0][1] if summary_candidates else f"Advisory {canonical_id}"

        # Prefer GHSA for details (longest formatted)
        details_candidates = [(v.id, v.details) for v in group if v.details]
        details_candidates.sort(key=lambda x: (1 if x[0].startswith("GHSA-") else 2, -len(x[1])))
        best_details = details_candidates[0][1] if details_candidates else best_summary

        # 7. Timestamps
        published = min((v.published for v in group if v.published), default="")
        modified = max((v.modified for v in group if v.modified), default="")

        # 5. References & Provenance Preservation
        all_refs = []
        for v in group:
            all_refs.extend(v.references)

        merged_refs = deduplicate_references(all_refs)

        origin_sources = sorted(list({v.id for v in group}))

        # Merge Affected Packages
        merged_affected = self._merge_affected_packages(group)

        # 6. Threat Intelligence Attachment & DB Specific merging
        sources_merged = sorted(list({v.id for v in group}))

        db_specific: dict[str, Any] = {
            "sources_merged": sources_merged,
            "origin_sources": origin_sources,
        }
        if divergent_severities:
            db_specific["divergent_severities"] = divergent_severities

        # Check KEV, EPSS, Malware
        is_known_exploited = False
        epss_score = None
        epss_percentile = None
        is_malware = any(v.id.startswith("MAL-") or any(a.startswith("MAL-") for a in v.aliases) for v in group)

        for v in group:
            db = v.database_specific
            if db.get("known_exploited"):
                is_known_exploited = True
            if "epss_score" in db and db["epss_score"] is not None:
                epss_score = max(epss_score or 0.0, db["epss_score"])
            if "epss_percentile" in db and db["epss_percentile"] is not None:
                epss_percentile = max(epss_percentile or 0.0, db["epss_percentile"])

        if is_known_exploited:
            db_specific["known_exploited"] = True
        if epss_score is not None:
            db_specific["epss_score"] = epss_score
        if epss_percentile is not None:
            db_specific["epss_percentile"] = epss_percentile

        # OpenSSF Malware severity promotion
        if is_malware:
             # Promote severity tier in affected packages
             new_affected = []
             for aff in merged_affected:
                 aff_db_dict = aff.database_specific.__dict__.copy()
                 aff_db_dict["severity"] = "CRITICAL"
                 new_aff = AffectedPackage(
                     package=aff.package,
                     ranges=aff.ranges,
                     versions=aff.versions,
                     ecosystem_specific=aff.ecosystem_specific,
                     database_specific=DatabaseSpecificMcp(**aff_db_dict)
                 )
                 new_affected.append(new_aff)
             merged_affected = new_affected

        return OsvVulnerability(
            id=canonical_id,
            summary=best_summary,
            details=best_details,
            published=published,
            modified=modified,
            aliases=aliases,
            severity=severity_tuple,
            affected=tuple(merged_affected),
            references=merged_refs,
            database_specific=db_specific,
        )

    def fuse_all(self, vulnerabilities: Iterable[OsvVulnerability]) -> list[OsvVulnerability]:
        vuln_list = list(vulnerabilities)
        if not vuln_list:
            return []

        alias_graph = CanonicalAliasGraph()
        for v in vuln_list:
            alias_graph.add_aliases(v.id, v.aliases)

        clusters = alias_graph.get_all_clusters()

        id_to_vuln = {v.id: v for v in vuln_list}

        merged_results = []
        for cluster_ids in clusters:
            group = [id_to_vuln[vid] for vid in cluster_ids if vid in id_to_vuln]
            if not group:
                continue
            fused = self.fuse_cluster(group, alias_graph)
            merged_results.append(fused)

        return sorted(merged_results, key=lambda v: v.id)

    @classmethod
    def _merge_affected_packages(cls, group: list[OsvVulnerability]) -> list[AffectedPackage]:
        # Borrow implementation base from Deduplicator, but enhance union for version ranges
        pkg_map: dict[str, list[AffectedPackage]] = {}

        for v in group:
            for aff in v.affected:
                key = f"{aff.package.ecosystem.lower()}:{aff.package.name.lower()}"
                pkg_map.setdefault(key, []).append(aff)

        merged_pkgs: list[AffectedPackage] = []

        for aff_list in pkg_map.values():
            base_aff = aff_list[0]
            pkg_spec = base_aff.package

            # Normalize PURL for output consistency
            if pkg_spec.purl:
                eco_map = {"mcp": "mcp", "npm": "npm", "pypi": "pypi", "golang": "golang", "cargo": "cargo", "docker": "docker", "github": "github"}
                for k, v in eco_map.items():
                    if pkg_spec.ecosystem.lower() == k:
                        if not pkg_spec.purl.startswith(f"pkg:{v}/"):
                            pkg_spec = pkg_spec.__class__(ecosystem=pkg_spec.ecosystem, name=pkg_spec.name, purl=f"pkg:{v}/{pkg_spec.name}")
                        break

            # 3. Affected Version Ranges (Union)
            all_versions = set()
            for a in aff_list:
                all_versions.update(a.versions)

            sorted_versions = tuple(sorted(all_versions, key=lambda v: parse_version(v) if _is_valid_version(v) else v))

            merged_ranges = cls._union_ranges(aff_list)

            # Merge database_specific
            all_tools: set[str] = set()
            all_cwes: set[str] = set()
            owasp_cat = None
            epss = None
            cvss_v3 = None
            cvss_v4 = None
            cvss_score = None
            severity_tier = None
            remediation = None
            verity_cond = None

            for a in aff_list:
                db = a.database_specific
                all_tools.update(db.vulnerable_tools)
                all_cwes.update(db.cwe_ids)
                if db.owasp_mcp_category and not owasp_cat:
                    owasp_cat = db.owasp_mcp_category
                if db.epss_score is not None:
                    epss = max(epss or 0.0, db.epss_score)
                if db.cvss_v3_vector and not cvss_v3:
                    cvss_v3 = db.cvss_v3_vector
                if db.cvss_v4_vector and not cvss_v4:
                    cvss_v4 = db.cvss_v4_vector
                if db.cvss_score is not None:
                    cvss_score = max(cvss_score or 0.0, db.cvss_score)
                if db.severity and not severity_tier:
                    severity_tier = db.severity
                if db.remediation_guidance and (
                    not remediation or len(db.remediation_guidance) > len(remediation)
                ):
                    remediation = db.remediation_guidance
                if db.verity_condition_id and not verity_cond:
                    verity_cond = db.verity_condition_id

            merged_db = DatabaseSpecificMcp(
                vulnerable_tools=tuple(sorted(all_tools)),
                cwe_ids=tuple(sorted(all_cwes)),
                owasp_mcp_category=owasp_cat,
                epss_score=epss,
                cvss_v3_vector=cvss_v3,
                cvss_v4_vector=cvss_v4,
                cvss_score=cvss_score,
                severity=severity_tier,
                remediation_guidance=remediation,
                verity_condition_id=verity_cond,
            )

            merged_pkgs.append(
                AffectedPackage(
                    package=pkg_spec,
                    ranges=tuple(merged_ranges),
                    versions=sorted_versions,
                    database_specific=merged_db,
                )
            )

        return merged_pkgs

    @classmethod
    def _union_ranges(cls, aff_list: list[AffectedPackage]) -> list[RangeSpec]:
        """Compute the mathematical union of affected intervals."""
        intervals = []
        for a in aff_list:
            for r in a.ranges:
                current_intro = "0"
                for e in r.events:
                    if e.introduced is not None:
                        current_intro = e.introduced
                        if e.fixed is not None:
                            intervals.append((current_intro, e.fixed, r.type, r.repo))
                            current_intro = "0"
                        elif e.last_affected is not None:
                            intervals.append((current_intro, e.last_affected + "-last", r.type, r.repo))
                            current_intro = "0"
                        elif e.limit is not None:
                            intervals.append((current_intro, e.limit + "-limit", r.type, r.repo))
                            current_intro = "0"
                    elif e.fixed is not None:
                        intervals.append((current_intro, e.fixed, r.type, r.repo))
                        current_intro = "0"
                    elif e.last_affected is not None:
                        intervals.append((current_intro, e.last_affected + "-last", r.type, r.repo))
                        current_intro = "0"
                    elif e.limit is not None:
                         intervals.append((current_intro, e.limit + "-limit", r.type, r.repo))
                         current_intro = "0"
                if current_intro != "0":
                     # Open interval
                     intervals.append((current_intro, None, r.type, r.repo))

        if not intervals:
            return []

        # Group by type and repo
        grouped_intervals = {}
        for intro, fixed, r_type, repo in intervals:
            grouped_intervals.setdefault((r_type, repo), []).append((intro, fixed))

        merged_ranges = []
        for (r_type, repo), ivals in grouped_intervals.items():
            # A simplistic union implementation for parsing versions
            # In a robust system we'd use packaging.version for SemVer intervals
            # For this exercise, we will sort and merge overlapping intervals.

            def v_parse(v):
                if v is None: return parse_version("999999.999999.999999") # Infinity
                if v.endswith("-last"): return parse_version(v.replace("-last", "")) # Approximations
                if v.endswith("-limit"): return parse_version(v.replace("-limit", ""))
                return parse_version(v) if _is_valid_version(v) else parse_version("0")

            sorted_ivals = sorted(ivals, key=lambda x: v_parse(x[0]))

            merged = []
            for current in sorted_ivals:
                if not merged:
                    merged.append(current)
                else:
                    last = merged[-1]
                    # If current starts before or exactly at last ends
                    if v_parse(current[0]) <= v_parse(last[1]):
                        # Union: max of ends
                        if last[1] is None or current[1] is None:
                            new_end = None
                        elif v_parse(current[1]) > v_parse(last[1]):
                            new_end = current[1]
                        else:
                            new_end = last[1]
                        merged[-1] = (last[0], new_end)
                    else:
                        merged.append(current)

            # Convert back to RangeSpec
            for intro, fixed in merged:
                evs = []
                if intro != "0":
                    evs.append(EventSpec(introduced=intro))
                else:
                    evs.append(EventSpec(introduced="0"))

                if fixed is not None:
                     if fixed.endswith("-last"):
                         evs.append(EventSpec(last_affected=fixed.replace("-last", "")))
                     elif fixed.endswith("-limit"):
                         evs.append(EventSpec(limit=fixed.replace("-limit", "")))
                     else:
                         evs.append(EventSpec(fixed=fixed))

                merged_ranges.append(RangeSpec(type=r_type, repo=repo, events=tuple(evs)))

        # Sort merged ranges to be deterministic
        merged_ranges.sort(key=lambda r: (r.type.value, r.repo or "", r.events[0].introduced if r.events and r.events[0].introduced else ""))
        return merged_ranges

def _is_valid_version(v: str) -> bool:
    try:
        parse_version(v)
        return True
    except:
        return False
