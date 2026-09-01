"""Converter for NIST NVD CVE 2.0 API records."""

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


class NvdConverter:
    """Converts NVD CVE 2.0 JSON records into canonical OSV v1.6.0 objects with zero data loss."""

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OsvVulnerability:
        """Convert NVD CVE 2.0 dictionary to OsvVulnerability."""
        cve_item = data
        if "vulnerabilities" in data and isinstance(data["vulnerabilities"], list):
            if len(data["vulnerabilities"]) > 0:
                cve_item = data["vulnerabilities"][0].get("cve", data["vulnerabilities"][0])
        elif "cve" in data and isinstance(data["cve"], dict):
            cve_item = data["cve"]

        cve_id = str(cve_item.get("id") or "CVE-UNKNOWN")

        # Multi-language descriptions
        descriptions = cve_item.get("descriptions", [])
        summary = ""
        details_parts: list[str] = []
        for desc in descriptions:
            val = desc.get("value", "")
            if desc.get("lang") == "en" and not summary:
                summary = val
            details_parts.append(val)

        if not summary and descriptions:
            summary = descriptions[0].get("value", "")
        if not summary:
            summary = f"NVD Advisory for {cve_id}"

        details = "\n\n".join(details_parts) if details_parts else summary
        published = cls._normalize_rfc3339(cve_item.get("published"))
        modified = cls._normalize_rfc3339(cve_item.get("lastModified") or published)

        # CWE Weaknesses
        cwe_ids: list[str] = []
        weakness_details: list[dict[str, Any]] = []
        for weakness in cve_item.get("weaknesses", []):
            w_source = weakness.get("source")
            w_type = weakness.get("type")
            for w_desc in weakness.get("description", []):
                val = w_desc.get("value", "")
                if val.startswith("CWE-") and val not in cwe_ids:
                    cwe_ids.append(val)
                weakness_details.append(
                    {"source": w_source, "type": w_type, "value": val, "lang": w_desc.get("lang")}
                )

        # CVSS Metrics (v2.0, v3.0, v3.1, v4.0, SSVC)
        metrics = cve_item.get("metrics", {})
        severities: list[SeveritySpec] = []
        cvss_v3_vector = None
        cvss_v4_vector = None
        cvss_score = None
        severity_tier = None
        raw_metrics_summary: dict[str, Any] = {}

        if metrics.get("cvssMetricV31"):
            v3_entry = metrics["cvssMetricV31"][0]
            v3_data = v3_entry.get("cvssData", {})
            cvss_v3_vector = v3_data.get("vectorString")
            score_raw = v3_data.get("baseScore")
            cvss_score = float(score_raw) if score_raw is not None else None
            severity_tier = v3_data.get("baseSeverity")
            if cvss_v3_vector:
                severities.append(SeveritySpec(type=SeverityType.CVSS_V3, score=cvss_v3_vector))
            raw_metrics_summary["cvssV31"] = v3_entry
        elif metrics.get("cvssMetricV40"):
            v4_entry = metrics["cvssMetricV40"][0]
            v4_data = v4_entry.get("cvssData", {})
            cvss_v4_vector = v4_data.get("vectorString")
            score_raw = v4_data.get("baseScore")
            cvss_score = float(score_raw) if score_raw is not None else None
            severity_tier = v4_data.get("baseSeverity")
            if cvss_v4_vector:
                severities.append(SeveritySpec(type=SeverityType.CVSS_V4, score=cvss_v4_vector))
            raw_metrics_summary["cvssV40"] = v4_entry
        elif metrics.get("cvssMetricV30"):
            v3_entry = metrics["cvssMetricV30"][0]
            v3_data = v3_entry.get("cvssData", {})
            cvss_v3_vector = v3_data.get("vectorString")
            score_raw = v3_data.get("baseScore")
            cvss_score = float(score_raw) if score_raw is not None else None
            severity_tier = v3_data.get("baseSeverity")
            if cvss_v3_vector:
                severities.append(SeveritySpec(type=SeverityType.CVSS_V3, score=cvss_v3_vector))
            raw_metrics_summary["cvssV30"] = v3_entry

        if metrics.get("cvssMetricV2"):
            raw_metrics_summary["cvssV2"] = metrics["cvssMetricV2"][0]
        if metrics.get("ssvcV203"):
            raw_metrics_summary["ssvcV203"] = metrics["ssvcV203"]

        # References with source and tags
        references: list[ReferenceSpec] = []
        seen_urls: set[str] = set()
        for ref in cve_item.get("references", []):
            url = ref.get("url") if isinstance(ref, dict) else str(ref)
            if url and url not in seen_urls:
                seen_urls.add(url)
                r_type = (
                    ReferenceType.ADVISORY
                    if ("advisories" in url or "nvd" in url or "github.com/advisories" in url)
                    else ReferenceType.WEB
                )
                references.append(ReferenceSpec(url=url, type=r_type))

        # CPE Configurations
        cpe_configs: list[dict[str, Any]] = []
        for config in cve_item.get("configurations", []):
            for node in config.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe_configs.append(match)

        # Affected packages from affected array or CPE inference
        affected_list: list[AffectedPackage] = []
        for aff in cve_item.get("affected", []):
            for aff_data in aff.get("affectedData", []):
                pkg_name = aff_data.get("packageName", "unknown")
                collection = aff_data.get("collectionURL", "")
                ecosystem = (
                    "npm" if "npmjs" in collection else ("PyPI" if "pypi" in collection else "MCP")
                )
                purl = build_purl(ecosystem, pkg_name)

                range_events: list[EventSpec] = []
                for v in aff_data.get("versions", []):
                    intro = v.get("version")
                    last_aff = v.get("lessThanOrEqual")
                    fix = v.get("lessThan")
                    range_events.append(
                        EventSpec(introduced=intro, last_affected=last_aff, fixed=fix)
                    )

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
            inferred_pkg = cls._infer_package_name(summary)
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
                    package=PackageSpec(
                        name=inferred_pkg, ecosystem="MCP", purl=f"pkg:mcp/{inferred_pkg}"
                    ),
                    ranges=(RangeSpec(type=RangeType.SEMVER, events=(EventSpec(introduced="0"),)),),
                    database_specific=db_mcp,
                )
            )

        # Full raw NVD preservation to guarantee zero data loss
        db_specific: dict[str, Any] = {
            "source": "NVD",
            "sourceIdentifier": cve_item.get("sourceIdentifier"),
            "vulnStatus": cve_item.get("vulnStatus"),
            "cveTags": cve_item.get("cveTags", []),
            "weaknesses": weakness_details,
            "cpe_configurations": cpe_configs,
            "raw_metrics": raw_metrics_summary,
            "raw_nvd": cve_item,
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
    def _infer_package_name(cls, summary: str) -> str:
        words = summary.split()
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
