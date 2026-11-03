import re
from pathlib import Path
from typing import Any

import yaml

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
)


class GitLabAdvisoryConverter:
    """Converter for GitLab Advisory Database YAML records to OSV."""

    @classmethod
    def from_yaml(cls, yaml_content: str | bytes) -> OsvVulnerability:
        data = yaml.safe_load(yaml_content)
        return cls.from_dict(data)

    @classmethod
    def from_file(cls, path: str | Path) -> OsvVulnerability:
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_yaml(f.read())

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OsvVulnerability:
        identifier = data.get("identifier", "")
        identifiers = data.get("identifiers", [])
        aliases = tuple(id for id in identifiers if id != identifier)

        # Map package slug
        package_slug = data.get("package_slug", "")
        ecosystem_str, _, package_name = package_slug.partition("/")
        
        ecosystem_map = {
            "npm": "npm",
            "pypi": "PyPI",
            "go": "Go",
        }
        purl_eco_map = {
            "npm": "npm",
            "pypi": "pypi",
            "go": "golang",
        }
        
        eco = ecosystem_map.get(ecosystem_str.lower(), ecosystem_str)
        purl_eco = purl_eco_map.get(ecosystem_str.lower(), ecosystem_str.lower())
        purl = f"pkg:{purl_eco}/{package_name}"

        # Dates
        pubdate = data.get("pubdate") or data.get("date", "")
        if pubdate:
            if not pubdate.endswith("Z") and "T" not in pubdate:
                pubdate = f"{pubdate}T00:00:00Z"
            elif not pubdate.endswith("Z") and not ("+" in pubdate or "-" in pubdate[11:]):
                 pubdate = f"{pubdate}Z"

        date = data.get("date") or pubdate
        if date:
            if not date.endswith("Z") and "T" not in date:
                date = f"{date}T00:00:00Z"
            elif not date.endswith("Z") and not ("+" in date or "-" in date[11:]):
                date = f"{date}Z"

        # Ranges
        ranges = []
        affected_range = data.get("affected_range")
        if affected_range:
            # Handle disjunctions
            disjunctions = [r.strip() for r in affected_range.split("||")]
            for dj in disjunctions:
                events = []
                # Simple parsing of "<=1.2.3", "<1.2.3", ">=1.0.0"
                parts = dj.split()
                
                introduced = "0"
                fixed = None
                last_affected = None
                
                for part in parts:
                    if part.startswith(">="):
                        introduced = part[2:]
                    elif part.startswith(">"):
                        pass 
                    elif part.startswith("<="):
                        last_affected = part[2:]
                    elif part.startswith("<"):
                        fixed = part[1:]
                
                if fixed is None and last_affected is None and data.get("fixed_versions"):
                    fixed = data.get("fixed_versions")[0]
                    
                if introduced:
                    events.append(EventSpec(introduced=introduced))
                if fixed:
                    events.append(EventSpec(fixed=fixed))
                if last_affected:
                    events.append(EventSpec(last_affected=last_affected))
                    
                if events:
                    ranges.append(RangeSpec(type=RangeType.SEMVER, events=tuple(events)))

        if not ranges and data.get("fixed_versions"):
            events = [EventSpec(introduced="0"), EventSpec(fixed=str(data["fixed_versions"][0]))]
            ranges.append(RangeSpec(type=RangeType.SEMVER, events=tuple(events)))


        severity = []
        db_specific_mcp = None
        db_specific = {}
        
        cvss_v3 = data.get("cvss_v3")
        if cvss_v3:
            severity.append(SeveritySpec(type=SeverityType.CVSS_V3, score=cvss_v3))

        solution = data.get("solution")
        if solution:
            db_specific["remediation"] = solution
            db_specific_mcp = DatabaseSpecificMcp(cvss_v3_vector=cvss_v3, remediation_guidance=solution)
        elif cvss_v3:
            db_specific_mcp = DatabaseSpecificMcp(cvss_v3_vector=cvss_v3)
        else:
            db_specific_mcp = DatabaseSpecificMcp()

        affected = (
            AffectedPackage(
                package=PackageSpec(
                    name=package_name,
                    ecosystem=eco,
                    purl=purl
                ),
                ranges=tuple(ranges),
                database_specific=db_specific_mcp
            ),
        )

        urls = data.get("urls", [])
        references = []
        for u in urls:
            references.append(ReferenceSpec(url=u, type=ReferenceType.WEB))
            
        uuid = data.get("uuid")
        if uuid:
            db_specific["gitlab_uuid"] = uuid

        osv_vuln = OsvVulnerability(
            id=identifier,
            summary=data.get("title", ""),
            details=data.get("description", ""),
            published=pubdate,
            modified=date,
            aliases=aliases,
            affected=affected,
            severity=tuple(severity),
            references=tuple(references),
            database_specific=db_specific,
        )
            
        return osv_vuln


GitLabConverter = GitLabAdvisoryConverter
