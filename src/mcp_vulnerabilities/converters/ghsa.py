"""Converter for GitHub Security Advisories (GHSA) JSON and API payloads."""

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


class GhsaConverter:
    """Converts GitHub Advisory Database objects into canonical OSV v1.6.0 documents."""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OsvVulnerability:
        """Convert GHSA REST/GraphQL dictionary to OsvVulnerability."""
        ghsa_id = str(data.get("ghsa_id") or data.get("id") or "")
        cve_id = str(data.get("cve_id") or "") if data.get("cve_id") else None

        primary_id = ghsa_id if ghsa_id else (cve_id or "GHSA-UNKNOWN")
        aliases: list[str] = []
        if cve_id and cve_id != primary_id:
            aliases.append(cve_id)
        for ident in data.get("identifiers", []):
            val = ident.get("value")
            if val and val != primary_id and val not in aliases:
                aliases.append(val)

        summary = str(data.get("summary") or f"GHSA Advisory {primary_id}")
        details = str(data.get("description") or data.get("details") or summary)
        published = str(data.get("published_at") or data.get("published") or "2026-01-01T00:00:00Z")
        modified = str(data.get("updated_at") or data.get("modified") or published)

        # CWE extraction
        cwe_ids: list[str] = []
        for cwe_item in data.get("cwes", []):
            if isinstance(cwe_item, dict) and "cwe_id" in cwe_item:
                cwe_ids.append(str(cwe_item["cwe_id"]).upper())
            elif isinstance(cwe_item, str):
                cwe_ids.append(cwe_item.upper())
        for cwe_item in data.get("cwe_ids", []):
            if isinstance(cwe_item, str):
                cwe_ids.append(cwe_item.upper())
            elif isinstance(cwe_item, dict) and "cwe_id" in cwe_item:
                cwe_ids.append(str(cwe_item["cwe_id"]).upper())

        # Severity
        severity_str = str(data.get("severity") or "").upper()
        severities: list[SeveritySpec] = []
        cvss_vector = None
        cvss_score = None

        cvss_severities = data.get("cvss_severities", {})
        if cvss_severities and "cvss_v3" in cvss_severities and cvss_severities["cvss_v3"]:
            v3_obj = cvss_severities["cvss_v3"]
            cvss_vector = v3_obj.get("vector_string")
            cvss_score = float(v3_obj["score"]) if v3_obj.get("score") is not None else None
            if cvss_vector:
                severities.append(SeveritySpec(type=SeverityType.CVSS_V3, score=cvss_vector))

        cvss_data = data.get("cvss", {})
        if not cvss_vector and cvss_data:
            cvss_vector = cvss_data.get("vector_string")
            cvss_score = float(cvss_data["score"]) if cvss_data.get("score") is not None else None
            if cvss_vector:
                s_type = SeverityType.CVSS_V4 if "CVSS:4" in cvss_vector else SeverityType.CVSS_V3
                severities.append(SeveritySpec(type=s_type, score=cvss_vector))

        # References
        references: list[ReferenceSpec] = []
        seen_urls: set[str] = set()
        for ref in data.get("references", []):
            url = ref if isinstance(ref, str) else ref.get("url")
            if url and url not in seen_urls:
                seen_urls.add(url)
                r_type = (
                    ReferenceType.ADVISORY
                    if ("advisories" in url or "nvd" in url)
                    else ReferenceType.WEB
                )
                references.append(ReferenceSpec(url=url, type=r_type))

        # Affected packages
        affected_list: list[AffectedPackage] = []
        vulns = data.get("vulnerabilities", [])
        if not vulns and "package" in data:
            vulns = [data]

        for v in vulns:
            pkg_info = v.get("package", {})
            name = str(pkg_info.get("name", "unknown"))
            raw_eco = str(pkg_info.get("ecosystem", "npm"))
            ecosystem = (
                "PyPI"
                if raw_eco.lower() in ("pypi", "pip")
                else ("npm" if raw_eco.lower() == "npm" else raw_eco)
            )
            purl = build_purl(ecosystem, name)

            range_events = cls._parse_ghsa_range(
                v.get("vulnerable_version_range"),
                v.get("first_patched_version"),
            )

            vulnerable_tools = cls._infer_vulnerable_tools(details)
            valid_sevs = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

            db_mcp = DatabaseSpecificMcp(
                vulnerable_tools=tuple(vulnerable_tools),
                cwe_ids=tuple(cwe_ids),
                cvss_v3_vector=cvss_vector if (cvss_vector and "CVSS:3" in cvss_vector) else None,
                cvss_v4_vector=cvss_vector if (cvss_vector and "CVSS:4" in cvss_vector) else None,
                cvss_score=cvss_score,
                severity=severity_str if severity_str in valid_sevs else None,
            )

            range_type = (
                RangeType.SEMVER if ecosystem.lower() in ("npm", "pypi") else RangeType.ECOSYSTEM
            )
            affected_list.append(
                AffectedPackage(
                    package=PackageSpec(name=name, ecosystem=ecosystem, purl=purl),
                    ranges=(
                        RangeSpec(
                            type=range_type,
                            events=tuple(range_events),
                        ),
                    ),
                    database_specific=db_mcp,
                )
            )

        return OsvVulnerability(
            id=primary_id,
            summary=summary,
            details=details,
            published=published,
            modified=modified,
            aliases=tuple(aliases),
            severity=tuple(severities),
            affected=tuple(affected_list),
            references=tuple(references),
            database_specific={"source": "GHSA"},
        )

    @classmethod
    def _parse_ghsa_range(cls, range_str: str | None, first_patched: str | None) -> list[EventSpec]:
        """Parse GHSA vulnerable_version_range e.g. '>= 0.0.5, < 0.1.16' into EventSpec list."""
        events: list[EventSpec] = []
        if not range_str:
            if first_patched:
                return [EventSpec(introduced="0"), EventSpec(fixed=first_patched)]
            return [EventSpec(introduced="0")]

        clean = range_str.strip()
        intro_match = re.search(r">=\s*(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9_.-]+)?)", clean)
        fixed_match = re.search(r"<\s*(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9_.-]+)?)", clean)
        last_aff_match = re.search(r"<=\s*(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9_.-]+)?)", clean)

        introduced = (
            intro_match.group(1)
            if intro_match
            else ("0" if ("<" in clean or "<=" in clean) else None)
        )
        fixed = fixed_match.group(1) if fixed_match else first_patched
        last_affected = last_aff_match.group(1) if last_aff_match else None

        if introduced:
            events.append(EventSpec(introduced=introduced))
        if last_affected:
            events.append(EventSpec(last_affected=last_affected))
        if fixed:
            events.append(EventSpec(fixed=fixed))

        if not events:
            events.append(EventSpec(introduced="0"))

        return events

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
