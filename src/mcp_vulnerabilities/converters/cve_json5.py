"""Converter for official CVE JSON 5.x (cvelistV5) records."""

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


class CveJson5Converter:
    """Converts CVE JSON 5.x records into canonical OSV v1.6.0 objects with zero data loss."""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OsvVulnerability:
        """Convert a CVE JSON 5.x record dictionary to OsvVulnerability."""
        cve_meta = data.get("cveMetadata", {})
        cve_id = str(cve_meta.get("cveId") or "CVE-UNKNOWN")
        published = cls._normalize_rfc3339(cve_meta.get("datePublished"))
        modified = cls._normalize_rfc3339(cve_meta.get("dateUpdated") or published)

        containers = data.get("containers", {})
        cna = containers.get("cna", {})

        # English description and HTML breakdown
        descriptions = cna.get("descriptions", [])
        summary = ""
        details_parts: list[str] = []
        for desc in descriptions:
            val = desc.get("value", "")
            if desc.get("lang") == "en" and not summary:
                summary = val
            details_parts.append(val)
            for sm in desc.get("supportingMedia", []):
                if sm.get("value"):
                    details_parts.append(sm["value"])

        if not summary and descriptions:
            summary = descriptions[0].get("value", "")
        if not summary:
            summary = f"CVE Advisory for {cve_id}"

        details = "\n\n".join(details_parts) if details_parts else summary

        # Extract CWEs from problemTypes
        cwe_ids: list[str] = []
        for pt in cna.get("problemTypes", []):
            for desc in pt.get("descriptions", []):
                cwe_raw = desc.get("cweId", "")
                if cwe_raw and cwe_raw.startswith("CWE-") and cwe_raw not in cwe_ids:
                    cwe_ids.append(cwe_raw)
                val_text = desc.get("description", "")
                m = re.search(r"CWE-\d+", val_text)
                if m and m.group(0) not in cwe_ids:
                    cwe_ids.append(m.group(0))

        # Metrics (CVSS v2, v3.0, v3.1, v4.0)
        severities: list[SeveritySpec] = []
        cvss_v3_vector = None
        cvss_v4_vector = None
        cvss_score = None
        severity_tier = None

        for metric in cna.get("metrics", []):
            if "cvssV3_1" in metric:
                v3 = metric["cvssV3_1"]
                cvss_v3_vector = v3.get("vectorString")
                raw_score = v3.get("baseScore")
                cvss_score = float(raw_score) if raw_score is not None else None
                severity_tier = v3.get("baseSeverity")
                if cvss_v3_vector:
                    severities.append(SeveritySpec(type=SeverityType.CVSS_V3, score=cvss_v3_vector))
            elif "cvssV4_0" in metric:
                v4 = metric["cvssV4_0"]
                cvss_v4_vector = v4.get("vectorString")
                raw_score = v4.get("baseScore")
                cvss_score = float(raw_score) if raw_score is not None else None
                severity_tier = v4.get("baseSeverity")
                if cvss_v4_vector:
                    severities.append(SeveritySpec(type=SeverityType.CVSS_V4, score=cvss_v4_vector))
            elif "cvssV3_0" in metric and not cvss_v3_vector:
                v3 = metric["cvssV3_0"]
                cvss_v3_vector = v3.get("vectorString")
                raw_score = v3.get("baseScore")
                cvss_score = float(raw_score) if raw_score is not None else None
                severity_tier = v3.get("baseSeverity")
                if cvss_v3_vector:
                    severities.append(SeveritySpec(type=SeverityType.CVSS_V3, score=cvss_v3_vector))

        # References
        references: list[ReferenceSpec] = []
        seen_urls: set[str] = set()
        for ref in cna.get("references", []):
            url = ref.get("url") if isinstance(ref, dict) else str(ref)
            if url and url not in seen_urls:
                seen_urls.add(url)
                r_type = (
                    ReferenceType.ADVISORY
                    if ("advisories" in url or "nvd" in url or "cve.org" in url)
                    else ReferenceType.WEB
                )
                references.append(ReferenceSpec(url=url, type=r_type))

        # Credits
        credits_list = [c.get("value") for c in cna.get("credits", []) if c.get("value")]

        # Affected Packages
        affected_list: list[AffectedPackage] = []
        for aff in cna.get("affected", []):
            pkg_name = (
                aff.get("packageName") or aff.get("product") or cls._infer_package_name(summary)
            )
            collection = aff.get("collectionURL", "")
            repo = aff.get("repo", "")

            ecosystem = "MCP"
            if "npmjs" in collection:
                ecosystem = "npm"
            elif "pypi" in collection or "python" in collection:
                ecosystem = "PyPI"
            elif "go.dev" in collection or "golang" in collection:
                ecosystem = "Go"
            elif "github.com" in repo:
                ecosystem = "npm" if "@" in pkg_name else "PyPI"

            purl = build_purl(ecosystem, pkg_name)

            range_events: list[EventSpec] = []
            for v in aff.get("versions", []):
                if v.get("status") == "affected":
                    intro = v.get("version")
                    fix = v.get("lessThan")
                    last_aff = v.get("lessThanOrEqual")
                    if intro:
                        range_events.append(EventSpec(introduced=intro))
                    if fix:
                        range_events.append(EventSpec(fixed=fix))
                    elif last_aff:
                        range_events.append(EventSpec(last_affected=last_aff))

            if not range_events:
                range_events.append(EventSpec(introduced="0"))

            db_mcp = DatabaseSpecificMcp(
                cwe_ids=tuple(cwe_ids),
                cvss_v3_vector=cvss_v3_vector,
                cvss_v4_vector=cvss_v4_vector,
                cvss_score=cvss_score,
                severity=severity_tier,
                vulnerable_tools=cls._extract_vulnerable_tools(details),
            )

            affected_list.append(
                AffectedPackage(
                    package=PackageSpec(name=pkg_name, ecosystem=ecosystem, purl=purl),
                    ranges=(RangeSpec(type=RangeType.SEMVER, events=tuple(range_events)),),
                    database_specific=db_mcp,
                )
            )

        if not affected_list:
            pkg_name = cls._infer_package_name(summary)
            db_mcp = DatabaseSpecificMcp(
                cwe_ids=tuple(cwe_ids),
                cvss_v3_vector=cvss_v3_vector,
                cvss_v4_vector=cvss_v4_vector,
                cvss_score=cvss_score,
                severity=severity_tier,
                vulnerable_tools=cls._extract_vulnerable_tools(details),
            )
            affected_list.append(
                AffectedPackage(
                    package=PackageSpec(name=pkg_name, ecosystem="MCP", purl=f"pkg:mcp/{pkg_name}"),
                    ranges=(RangeSpec(type=RangeType.SEMVER, events=(EventSpec(introduced="0"),)),),
                    database_specific=db_mcp,
                )
            )

        # Retain full CNA payload to guarantee zero data loss
        db_specific: dict[str, Any] = {
            "source": "cvelistV5",
            "assigner": cve_meta.get("assignerShortName"),
            "assignerOrgId": cve_meta.get("assignerOrgId"),
            "state": cve_meta.get("state"),
            "credits": credits_list,
            "raw_cve_json5": cna,
        }

        return OsvVulnerability(
            id=cve_id,
            summary=summary[:120] if len(summary) > 120 else summary,
            details=details,
            published=published,
            modified=modified,
            severity=tuple(severities),
            affected=tuple(affected_list),
            references=tuple(references),
            database_specific=db_specific,
        )

    @classmethod
    def _normalize_rfc3339(cls, ts: Any) -> str:
        if not ts:
            return "2026-01-01T00:00:00Z"
        s = str(ts).strip()
        if not s.endswith("Z") and not re.search(r"[+-]\d{2}:\d{2}$", s):
            return f"{s}Z"
        return s

    @classmethod
    def _infer_package_name(cls, text: str) -> str:
        words = text.split()
        for w in words:
            cleaned = w.strip("`.,:;'\"()[]{}")
            if (
                cleaned.startswith("mcp-")
                or cleaned.startswith("@modelcontextprotocol/")
                or cleaned == "fastmcp"
            ):
                return cleaned
        return words[0].strip("`.,:;'\"") if words else "unknown-mcp"

    @classmethod
    def _extract_vulnerable_tools(cls, text: str) -> tuple[str, ...]:
        tools: list[str] = []
        tool_patterns = (
            r"\b(cypher_query|read_cypher|write_cypher|git_init|git_add|git_diff|git_checkout|connect|authorization_endpoint|run_command|fetch_url)\b",
        )
        for pat in tool_patterns:
            matches = re.findall(pat, text, re.IGNORECASE)
            for m in matches:
                norm = m.lower()
                if norm not in tools:
                    tools.append(norm)
        return tuple(tools)
