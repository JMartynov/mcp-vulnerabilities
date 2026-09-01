"""Converter and normalizer for native Google OSV.dev JSON advisory streams."""

from __future__ import annotations

import re
from typing import Any

from mcp_vulnerabilities.models import (
    AffectedPackage,
    DatabaseSpecificMcp,
    EventSpec,
    OsvVulnerability,
    PackageSpec,
    RangeSpec,
    RangeType,
    ReferenceSpec,
    ReferenceType,
    SeveritySpec,
    SeverityType,
    build_purl,
)


class OsvDevConverter:
    """Normalizes native Google OSV.dev records and enriches them with MCP-specific extensions."""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OsvVulnerability:
        """Convert/normalize OSV.dev dictionary to OsvVulnerability with MCP extensions."""
        primary_id = str(data.get("id") or "OSV-UNKNOWN")
        summary = str(data.get("summary") or f"Security advisory for {primary_id}")
        details = str(data.get("details") or summary)
        published = str(data.get("published") or "2026-01-01T00:00:00Z")
        modified = str(data.get("modified") or published)
        aliases = tuple(data.get("aliases", ()))
        related = tuple(data.get("related", ()))

        # Severities
        severities: list[SeveritySpec] = []
        cvss_v3 = None
        cvss_v4 = None
        for s in data.get("severity", []):
            s_type_str = s.get("type", "CVSS_V3")
            score_str = str(s.get("score", ""))
            s_type = (
                SeverityType.CVSS_V4
                if ("V4" in s_type_str or "CVSS:4" in score_str)
                else SeverityType.CVSS_V3
            )
            severities.append(SeveritySpec(type=s_type, score=score_str))
            if s_type == SeverityType.CVSS_V4:
                cvss_v4 = score_str
            else:
                cvss_v3 = score_str

        # References
        references: list[ReferenceSpec] = []
        seen_urls: set[str] = set()
        for ref in data.get("references", []):
            url = ref.get("url") if isinstance(ref, dict) else str(ref)
            r_type_str = ref.get("type", "WEB") if isinstance(ref, dict) else "WEB"
            if url and url not in seen_urls:
                seen_urls.add(url)
                try:
                    ref_type = ReferenceType(r_type_str.upper())
                except ValueError:
                    ref_type = ReferenceType.WEB
                references.append(ReferenceSpec(url=url, type=ref_type))

        # Affected packages
        affected_list: list[AffectedPackage] = []
        vulnerable_tools = cls._infer_vulnerable_tools(details)

        for aff in data.get("affected", []):
            pkg_data = aff.get("package", {})
            name = str(pkg_data.get("name", "unknown"))
            ecosystem = str(pkg_data.get("ecosystem", "PyPI"))
            purl = pkg_data.get("purl") or build_purl(ecosystem, name)

            ranges_list: list[RangeSpec] = []
            for r in aff.get("ranges", []):
                events_list: list[EventSpec] = []
                for ev in r.get("events", []):
                    events_list.append(
                        EventSpec(
                            introduced=ev.get("introduced"),
                            fixed=ev.get("fixed"),
                            last_affected=ev.get("last_affected"),
                            limit=ev.get("limit"),
                        )
                    )
                r_type_str = r.get("type", "SEMVER")
                try:
                    r_type = RangeType(r_type_str)
                except ValueError:
                    r_type = RangeType.ECOSYSTEM

                ranges_list.append(
                    RangeSpec(
                        type=r_type,
                        events=tuple(events_list),
                        repo=r.get("repo"),
                        database_specific=r.get("database_specific", {}),
                    )
                )

            # Ingest/enrich database_specific
            db_mcp_raw = aff.get("database_specific", {})
            cwe_ids = list(db_mcp_raw.get("cwe_ids", []))
            # Scan details for CWEs if missing
            if not cwe_ids:
                cwe_ids = re.findall(r"CWE-\d+", details, re.IGNORECASE)

            db_mcp = DatabaseSpecificMcp(
                vulnerable_tools=tuple(vulnerable_tools),
                cwe_ids=tuple(cwe_ids),
                cvss_v3_vector=cvss_v3,
                cvss_v4_vector=cvss_v4,
                severity=db_mcp_raw.get("severity"),
                remediation_guidance=cls._extract_mitigation(details),
            )

            affected_list.append(
                AffectedPackage(
                    package=PackageSpec(name=name, ecosystem=ecosystem, purl=purl),
                    ranges=tuple(ranges_list),
                    versions=tuple(aff.get("versions", ())),
                    ecosystem_specific=aff.get("ecosystem_specific", {}),
                    database_specific=db_mcp,
                )
            )

        return OsvVulnerability(
            id=primary_id,
            summary=summary,
            details=details,
            published=published,
            modified=modified,
            aliases=aliases,
            related=related,
            severity=tuple(severities),
            affected=tuple(affected_list),
            references=tuple(references),
            database_specific=data.get("database_specific", {"source": "OSV.dev"}),
        )

    @classmethod
    def _extract_mitigation(cls, details: str) -> str | None:
        match = re.search(
            r"###\s*Mitigation\s*\n(.*?)(?=\n###|\Z)", details, re.DOTALL | re.IGNORECASE
        )
        if match:
            return match.group(1).strip()
        return None

    @classmethod
    def _infer_vulnerable_tools(cls, text: str) -> list[str]:
        tools: set[str] = set()
        keywords = (
            "query",
            "get",
            "search",
            "read",
            "write",
            "exec",
            "init",
            "add",
            "diff",
            "checkout",
            "install",
            "fetch",
            "delete",
            "update",
            "cypher",
        )
        for match in re.finditer(r"`([a-z][a-z0-9_]{2,30})`", text):
            candidate = match.group(1)
            if any(term in candidate for term in keywords):
                tools.add(candidate)
        return sorted(tools)
