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
            events_set: set[tuple[str | None, str | None, str | None]] = set()
            for a in aff_list:
                for r in a.ranges:
                    for e in r.events:
                        events_set.add((e.introduced, e.fixed, e.last_affected))

            merged_events = [
                EventSpec(introduced=i, fixed=f, last_affected=la) for (i, f, la) in events_set
            ]
            merged_events.sort(key=lambda ev: (ev.introduced or "", ev.fixed or ""))

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
                    ranges=(
                        RangeSpec(
                            type=base_aff.ranges[0].type if base_aff.ranges else RangeType.SEMVER,
                            events=tuple(merged_events),
                        ),
                    ),
                    database_specific=merged_db,
                )
            )

        return merged_pkgs
