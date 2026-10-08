"""Deduplication and advisory merging engine for multi-source MCP vulnerabilities."""

from __future__ import annotations

from collections.abc import Iterable

from mcp_vulnerabilities.models import (
    AffectedPackage,
    DatabaseSpecificMcp,
    EventSpec,
    OsvVulnerability,
    RangeSpec,
    RangeType,
    ReferenceSpec,
    SeveritySpec,
)


class OsvDeduplicator:
    """Deduplicates and merges vulnerability entries across heterogeneous upstream sources."""

    @classmethod
    def deduplicate_and_merge(
        cls, vulnerabilities: Iterable[OsvVulnerability]
    ) -> list[OsvVulnerability]:
        """Group and merge overlapping vulnerability records."""
        groups: list[list[OsvVulnerability]] = []

        for vuln in vulnerabilities:
            matched_group = None
            vuln_keys = cls._get_lookup_keys(vuln)

            for group in groups:
                group_keys = set()
                for member in group:
                    group_keys.update(cls._get_lookup_keys(member))
                if vuln_keys.intersection(group_keys):
                    matched_group = group
                    break

            if matched_group is not None:
                matched_group.append(vuln)
            else:
                groups.append([vuln])

        merged_results: list[OsvVulnerability] = []
        for group in groups:
            merged_results.append(cls._merge_group(group))

        return sorted(merged_results, key=lambda v: v.id)

    @classmethod
    def _get_lookup_keys(cls, vuln: OsvVulnerability) -> set[str]:
        keys = {vuln.id.upper()}
        for a in vuln.aliases:
            keys.add(a.upper())
        return keys

    @classmethod
    def _merge_group(cls, group: list[OsvVulnerability]) -> OsvVulnerability:
        if len(group) == 1:
            return group[0]

        # Primary ID selection: Prefer MCP-*, then CVE-*, then GHSA-*, then first
        def _id_priority(vid: str) -> int:
            if vid.startswith("MCP-"):
                return 0
            if vid.startswith("CVE-"):
                return 1
            if vid.startswith("GHSA-"):
                return 2
            if vid.startswith("VERITY-"):
                return 3
            return 4

        sorted_by_id = sorted(group, key=lambda v: _id_priority(v.id))
        primary_id = sorted_by_id[0].id

        # Collect all aliases
        all_aliases: set[str] = set()
        for v in group:
            if v.id != primary_id:
                all_aliases.add(v.id)
            for a in v.aliases:
                if a != primary_id:
                    all_aliases.add(a)

        # Summary & Details: Pick longest / most informative
        best_summary = max(
            (v.summary for v in group if v.summary), key=len, default=f"Advisory {primary_id}"
        )
        best_details = max((v.details for v in group if v.details), key=len, default=best_summary)

        # Timestamps: earliest published, latest modified
        published = min(v.published for v in group if v.published)
        modified = max(v.modified for v in group if v.modified)

        # Merge Severities
        severities: list[SeveritySpec] = []
        seen_sev: set[str] = set()
        for v in group:
            for s in v.severity:
                if s.score not in seen_sev:
                    seen_sev.add(s.score)
                    severities.append(s)

        # Merge References
        references: list[ReferenceSpec] = []
        seen_refs: set[str] = set()
        for v in group:
            for r in v.references:
                if r.url not in seen_refs:
                    seen_refs.add(r.url)
                    references.append(r)

        # Merge Affected Packages
        merged_affected = cls._merge_affected_packages(group)

        return OsvVulnerability(
            id=primary_id,
            summary=best_summary,
            details=best_details,
            published=published,
            modified=modified,
            aliases=tuple(sorted(all_aliases)),
            severity=tuple(severities),
            affected=tuple(merged_affected),
            references=tuple(references),
            database_specific={"sources_merged": [v.id for v in group]},
        )

    @classmethod
    def _merge_affected_packages(cls, group: list[OsvVulnerability]) -> list[AffectedPackage]:
        pkg_map: dict[str, list[AffectedPackage]] = {}

        for v in group:
            for aff in v.affected:
                key = f"{aff.package.ecosystem.lower()}:{aff.package.name.lower()}"
                pkg_map.setdefault(key, []).append(aff)

        merged_pkgs: list[AffectedPackage] = []

        for _key, aff_list in pkg_map.items():
            base_aff = aff_list[0]
            pkg_spec = base_aff.package

            # Merge ranges
            # Group events into valid OSV 1.6 pairs or distinct RangeSpec entries
            range_groups: dict[tuple[RangeType, str | None], set[tuple[str | None, str | None, str | None, str | None]]] = {}

            for a in aff_list:
                for r in a.ranges:
                    group_key = (r.type, r.repo)
                    if group_key not in range_groups:
                        range_groups[group_key] = set()

                    current_intro: str | None = None
                    for e in r.events:
                        if e.introduced is not None:
                            if current_intro is not None:
                                # Unclosed range before another intro? Emit as open.
                                range_groups[group_key].add((current_intro, None, None, None))
                            current_intro = e.introduced
                            
                            # Handle case where introduced and fixed are in the same EventSpec
                            if e.fixed is not None:
                                range_groups[group_key].add((current_intro, e.fixed, None, None))
                                current_intro = None
                            elif e.last_affected is not None:
                                range_groups[group_key].add((current_intro, None, e.last_affected, None))
                                current_intro = None
                            elif e.limit is not None:
                                range_groups[group_key].add((current_intro, None, None, e.limit))
                                current_intro = None
                        elif e.fixed is not None:
                            range_groups[group_key].add((current_intro or "0", e.fixed, None, None))
                            current_intro = None
                        elif e.last_affected is not None:
                            range_groups[group_key].add((current_intro or "0", None, e.last_affected, None))
                            current_intro = None
                        elif e.limit is not None:
                            range_groups[group_key].add((current_intro or "0", None, None, e.limit))
                            current_intro = None

                    # Open range ending
                    if current_intro is not None:
                        range_groups[group_key].add((current_intro, None, None, None))

            merged_ranges: list[RangeSpec] = []
            
            for (r_type, r_repo), pairs in range_groups.items():
                # For each valid pair, create a distinct RangeSpec to ensure OSV 1.6 sequence validity
                # sorting by string values for deterministic output
                for intro, fixed, last_aff, limit in sorted(pairs, key=lambda x: (x[0] or "", x[1] or "", x[2] or "", x[3] or "")):
                    evs = []
                    if intro is not None and intro != "0":
                        evs.append(EventSpec(introduced=intro))
                    elif intro == "0":
                        evs.append(EventSpec(introduced="0"))
                    
                    if fixed is not None:
                        evs.append(EventSpec(fixed=fixed))
                    elif last_aff is not None:
                        evs.append(EventSpec(last_affected=last_aff))
                    elif limit is not None:
                        evs.append(EventSpec(limit=limit))
                        
                    merged_ranges.append(
                        RangeSpec(
                            type=r_type,
                            repo=r_repo,
                            events=tuple(evs)
                        )
                    )

            # Sort merged ranges to be deterministic
            merged_ranges.sort(key=lambda r: (r.type.value, r.repo or "", r.events[0].introduced if r.events and r.events[0].introduced else ""))

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
                    database_specific=merged_db,
                )
            )

        return merged_pkgs
