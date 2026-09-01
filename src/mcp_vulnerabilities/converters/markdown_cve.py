"""Converter for curated Markdown CVE advisory documents (e.g. mcp-cve-project)."""

from __future__ import annotations

import re
from pathlib import Path

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


class MarkdownAdvisoryConverter:
    """Parses structured Markdown CVE documents into canonical OSV v1.6.0 objects."""

    TABLE_ROW_REGEX = re.compile(r"^\|\s*([^|]+?)\s*\|\s*(.*?)\s*\|$", re.MULTILINE)
    LINK_REGEX = re.compile(r"\[([^\]]+)\]\(([^)]+)\)")
    CWE_REGEX = re.compile(r"CWE-\d+", re.IGNORECASE)
    CVSS_VECTOR_REGEX = re.compile(r"(CVSS:(?:3\.1|4\.0|3\.0)/[A-Z0-9:/._-]+)", re.IGNORECASE)

    @classmethod
    def from_file(cls, file_path: str | Path) -> OsvVulnerability:
        """Parse a Markdown CVE file from the filesystem."""
        path = Path(file_path)
        content = path.read_text(encoding="utf-8")
        return cls.from_markdown(content, fallback_id=path.stem)

    @classmethod
    def from_markdown(cls, text: str, fallback_id: str = "MCP-UNKNOWN") -> OsvVulnerability:
        """Parse raw Markdown content into an OsvVulnerability."""
        # 1. Parse table metadata
        fields: dict[str, str] = {}
        for match in cls.TABLE_ROW_REGEX.finditer(text):
            k = match.group(1).strip()
            v = match.group(2).strip()
            if k and not k.startswith("---") and k.lower() != "field":
                fields[k.lower()] = v

        # 2. Extract Identifiers
        cve_raw = fields.get("cve / nvd") or fields.get("cve") or ""
        cve_match = re.search(r"CVE-\d{4}-\d+", cve_raw, re.IGNORECASE)
        cve_id = cve_match.group(0).upper() if cve_match else None

        ghsa_raw = fields.get("ghsa id") or fields.get("ghsa") or ""
        ghsa_match = re.search(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", ghsa_raw, re.IGNORECASE)
        ghsa_id = ghsa_match.group(0) if ghsa_match else None

        primary_id = cve_id or ghsa_id or fallback_id

        aliases: list[str] = []
        if cve_id and cve_id != primary_id:
            aliases.append(cve_id)
        if ghsa_id and ghsa_id != primary_id:
            aliases.append(ghsa_id)
        if cve_id and ghsa_id and primary_id not in (cve_id, ghsa_id):
            aliases.extend([cve_id, ghsa_id])

        # 3. Extract Package & Ecosystem
        ecosystem_raw = fields.get("ecosystem") or "MCP"
        ecosystem = (
            "PyPI"
            if "pypi" in ecosystem_raw.lower()
            else ("npm" if "npm" in ecosystem_raw.lower() else "MCP")
        )

        affected_prod_raw = (
            fields.get("affected product (index)")
            or fields.get("affected product")
            or fields.get("component")
            or ""
        )
        # Search for package name inside parens `(mcp-neo4j-cypher)` or take raw
        pkg_match = re.search(r"\(([`@a-zA-Z0-9_/-]+)\)", affected_prod_raw) or re.search(
            r"`([@a-zA-Z0-9_/-]+)`", affected_prod_raw
        )
        if pkg_match:
            pkg_name = pkg_match.group(1).replace("`", "").strip()
        else:
            pkg_name = (
                affected_prod_raw.split()[0].replace("`", "").strip()
                if affected_prod_raw
                else "unknown-mcp"
            )

        purl = build_purl(ecosystem, pkg_name)

        # 4. Extract Affected & Fixed Versions
        aff_versions_raw = fields.get("affected versions") or ""
        fixed_versions_raw = fields.get("fixed versions") or ""

        range_events = cls._parse_version_range_events(aff_versions_raw, fixed_versions_raw)

        # 5. Extract CWE, OWASP, EPSS, and CVSS
        cwe_raw = fields.get("cwe") or ""
        cwe_ids = tuple(re.findall(r"CWE-\d+", cwe_raw, re.IGNORECASE))

        owasp_raw = fields.get("owasp mcp top 10 (2025)") or fields.get("owasp mcp top 10") or ""
        owasp_clean = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", owasp_raw).strip()

        epss_raw = fields.get("epss score") or ""
        epss_match = re.search(r"(\d+\.\d+)", epss_raw)
        epss_score = float(epss_match.group(1)) if epss_match else None

        cvss_raw = fields.get("cvss score") or ""
        cvss_score = None
        cvss_vector = None
        severity_tier = None

        if "critical" in cvss_raw.lower():
            severity_tier = "CRITICAL"
        elif "high" in cvss_raw.lower():
            severity_tier = "HIGH"
        elif "medium" in cvss_raw.lower():
            severity_tier = "MEDIUM"
        elif "low" in cvss_raw.lower():
            severity_tier = "LOW"

        score_match = re.search(r"(\d+\.\d+)", cvss_raw)
        if score_match:
            cvss_score = float(score_match.group(1))

        vec_match = cls.CVSS_VECTOR_REGEX.search(cvss_raw)
        if vec_match:
            cvss_vector = vec_match.group(1)

        # 6. Extract Narrative Details, Summary, and Remediation
        summary = cls._extract_summary(text, primary_id, affected_prod_raw)
        section_end_pattern = (
            r"(?:##\s*Fix\s*/\s*Remediation|##\s*Detection|##\s*Patch|##\s*Reference)"
        )
        details = cls._extract_section(text, r"##\s*CVE Breakdown", section_end_pattern)
        remediation_end_pattern = r"(?:##\s*Detection|##\s*Patch|##\s*Reference)"
        remediation = cls._extract_section(
            text, r"##\s*Fix\s*/\s*Remediation", remediation_end_pattern
        )

        # Extract references
        references = cls._extract_references(text, fields)

        # Extract vulnerable tools if present in breakdown
        vulnerable_tools = cls._infer_vulnerable_tools(details)

        db_mcp = DatabaseSpecificMcp(
            vulnerable_tools=tuple(vulnerable_tools),
            cwe_ids=cwe_ids,
            owasp_mcp_category=owasp_clean if owasp_clean else None,
            epss_score=epss_score,
            cvss_v3_vector=cvss_vector if (cvss_vector and "CVSS:3" in cvss_vector) else None,
            cvss_v4_vector=cvss_vector if (cvss_vector and "CVSS:4" in cvss_vector) else None,
            cvss_score=cvss_score,
            severity=severity_tier,
            remediation_guidance=remediation.strip() if remediation else None,
        )

        range_type = (
            RangeType.SEMVER if ecosystem.lower() in ("npm", "pypi") else RangeType.ECOSYSTEM
        )
        affected_pkg = AffectedPackage(
            package=PackageSpec(name=pkg_name, ecosystem=ecosystem, purl=purl),
            ranges=(
                RangeSpec(
                    type=range_type,
                    events=tuple(range_events),
                ),
            ),
            database_specific=db_mcp,
        )

        severities: list[SeveritySpec] = []
        if cvss_vector:
            s_type = SeverityType.CVSS_V4 if "CVSS:4" in cvss_vector else SeverityType.CVSS_V3
            severities.append(SeveritySpec(type=s_type, score=cvss_vector))

        pub_date = fields.get("published / disclosed") or fields.get("date (index)") or "2026-01-01"
        if len(pub_date) == 10 and pub_date[4] == "-" and pub_date[7] == "-":
            published_iso = f"{pub_date}T00:00:00Z"
        else:
            published_iso = "2026-01-01T00:00:00Z"

        return OsvVulnerability(
            id=primary_id,
            summary=summary,
            details=details if details else summary,
            published=published_iso,
            modified=published_iso,
            aliases=tuple(aliases),
            severity=tuple(severities),
            affected=(affected_pkg,),
            references=tuple(references),
        )

    @classmethod
    def _parse_version_range_events(cls, affected_raw: str, fixed_raw: str) -> list[EventSpec]:
        """Convert version text like '>= 0.2.2, <= 0.3.1' and 'v0.4.0' into EventSpec list."""
        events: list[EventSpec] = []
        clean_aff = affected_raw.replace("**", "").replace("`", "").strip()
        clean_fix = fixed_raw.replace("**", "").replace("`", "").strip()

        introduced = None
        last_affected = None
        fixed = None

        # Fixed version extraction: [mcp-neo4j-cypher-v0.4.0](...) or v0.4.0 or 0.4.0
        fix_match = re.search(r"v?(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9_.-]+)?)", clean_fix)
        if fix_match:
            fixed = fix_match.group(1)

        # Range matching (e.g. >= 0.2.2, <= 0.3.1 or < 0.2.0)
        intro_match = re.search(r">=\s*v?(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9_.-]+)?)", clean_aff)
        if intro_match:
            introduced = intro_match.group(1)
        elif "<" in clean_aff or "<=" in clean_aff:
            introduced = "0"

        last_aff_match = re.search(r"<=\s*v?(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9_.-]+)?)", clean_aff)
        if last_aff_match:
            last_affected = last_aff_match.group(1)

        less_match = re.search(r"<\s*v?(\d+\.\d+(?:\.\d+)?(?:[a-zA-Z0-9_.-]+)?)", clean_aff)
        if less_match and not fixed:
            fixed = less_match.group(1)

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
    def _extract_summary(cls, text: str, primary_id: str, product: str) -> str:
        """Extract or generate a clean summary from the top header or breakdown."""
        # Top heading: # CVE-2025-10193 | Neo4j MCP Cypher server (DNS rebinding) | High |
        header_match = re.search(r"^#\s*([^|\n]+)\s*\|\s*([^|\n]+)", text, re.MULTILINE)
        if header_match:
            desc = header_match.group(2).strip()
            return f"{primary_id}: {desc}"
        return f"{primary_id} vulnerability in {product or 'MCP server'}"

    @classmethod
    def _extract_section(cls, text: str, start_pattern: str, end_pattern: str) -> str:
        """Extract markdown content between headers."""
        start_match = re.search(start_pattern, text, re.IGNORECASE)
        if not start_match:
            return ""
        start_pos = start_match.end()
        end_match = re.search(end_pattern, text[start_pos:], re.IGNORECASE)
        chunk = text[start_pos : start_pos + end_match.start()] if end_match else text[start_pos:]
        return chunk.strip()

    @classmethod
    def _extract_references(cls, text: str, fields: dict[str, str]) -> list[ReferenceSpec]:
        """Extract reference URLs from markdown text and fields."""
        refs: list[ReferenceSpec] = []
        seen_urls: set[str] = set()

        def _add_ref(url: str, ref_type: ReferenceType) -> None:
            clean = url.strip().rstrip(")")
            if clean and clean.startswith("http") and clean not in seen_urls:
                seen_urls.add(clean)
                refs.append(ReferenceSpec(url=clean, type=ref_type))

        for raw_val in fields.values():
            for link in cls.LINK_REGEX.finditer(raw_val):
                target_url = link.group(2)
                r_type = (
                    ReferenceType.ADVISORY
                    if ("advisories" in target_url or "nvd" in target_url)
                    else ReferenceType.WEB
                )
                _add_ref(target_url, r_type)

        # Links in reference section
        ref_section = cls._extract_section(text, r"##\s*Reference\s*links", r"(?:##|\Z)")
        for line in ref_section.splitlines():
            url_match = re.search(r"(https?://[^\s)]+)", line)
            if url_match:
                _add_ref(url_match.group(1), ReferenceType.WEB)

        return refs

    @classmethod
    def _infer_vulnerable_tools(cls, text: str) -> list[str]:
        """Infer tool names mentioned in vulnerability descriptions."""
        tools: set[str] = set()
        lower = text.lower()
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
        # Look for code snippets mentioning tool names (e.g. `get_customer`, `cypher_query`)
        for match in re.finditer(r"`([a-z][a-z0-9_]{2,30})`", text):
            candidate = match.group(1)
            if any(term in candidate for term in keywords):
                tools.add(candidate)

        # Context-aware fallback for domain-specific servers
        if not tools:
            if "cypher query" in lower or "cypher" in lower:
                tools.add("cypher_query")
            elif "git_init" in lower:
                tools.add("git_init")

        return sorted(tools)
