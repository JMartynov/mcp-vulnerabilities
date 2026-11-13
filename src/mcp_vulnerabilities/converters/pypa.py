import yaml
from pathlib import Path
from typing import Any
from mcp_vulnerabilities.models import (
    OsvVulnerability,
    AffectedPackage,
    PackageSpec,
    ReferenceSpec,
    ReferenceType,
    RangeSpec,
    RangeType,
    EventSpec,
)
from packaging.version import Version
from packaging.specifiers import SpecifierSet

class PyPaAdvisoryConverter:
    @classmethod
    def _bump_patch(cls, v_str: str) -> str:
        v = Version(v_str)
        rel = list(v.release)
        if len(rel) < 3:
            rel += [0] * (3 - len(rel))
        rel[-1] += 1
        epoch = f"{v.epoch}!" if v.epoch else ""
        return f"{epoch}{'.'.join(map(str, rel))}"

    @classmethod
    def decompose_pep440_ranges(cls, spec_str: str) -> tuple[RangeSpec, ...]:
        if not spec_str:
            return ()
            
        spec = SpecifierSet(spec_str)
        
        lower_bound = None
        upper_bound = None
        exclusions = []
        
        for s in spec:
            if s.operator in (">=", ">"):
                lower_bound = s
            elif s.operator in ("<=", "<"):
                upper_bound = s
            elif s.operator == "!=":
                exclusions.append(s)
            elif s.operator == "~=":
                # ~=1.4.2 -> >=1.4.2, ==1.4.* -> introduced: 1.4.2, fixed: 1.5.0
                v = Version(s.version)
                rel = list(v.release)
                if len(rel) == 1:
                    rel = [rel[0], 0]
                idx = max(0, len(rel) - 2)
                rel[idx] += 1
                for i in range(idx + 1, len(rel)):
                    rel[i] = 0
                upper_v = ".".join(map(str, rel))
                
                return (RangeSpec(
                    type=RangeType.ECOSYSTEM,
                    events=(
                        EventSpec(introduced=s.version),
                        EventSpec(fixed=upper_v)
                    )
                ),)
                
        events_list: list[EventSpec] = []
        
        current_introduced = "0"
        if lower_bound:
            current_introduced = lower_bound.version
            if lower_bound.operator == ">":
                current_introduced = cls._bump_patch(current_introduced)
                
        # sort exclusions
        exclusions = sorted([Version(s.version) for s in exclusions])
        
        for ex_v in exclusions:
            # segment: introduced -> excluded version
            events_list.append(EventSpec(introduced=current_introduced))
            events_list.append(EventSpec(fixed=str(ex_v)))
            current_introduced = cls._bump_patch(str(ex_v))
            
        if upper_bound:
            events_list.append(EventSpec(introduced=current_introduced))
            if upper_bound.operator == "<":
                events_list.append(EventSpec(fixed=upper_bound.version))
            else: # <=
                events_list.append(EventSpec(last_affected=upper_bound.version))
        else:
            if current_introduced != "0" or not exclusions:
                events_list.append(EventSpec(introduced=current_introduced))
            
        if not events_list:
            return ()
            
        return (RangeSpec(
            type=RangeType.ECOSYSTEM,
            events=tuple(events_list)
        ),)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OsvVulnerability:
        affected_list = []
        for aff in data.get("affected", []):
            pkg_data = aff.get("package", {})
            pkg_name = pkg_data.get("name", "")
            ecosystem = pkg_data.get("ecosystem", "PyPI")
            
            ranges_list = []
            
            # If ranges already provided, convert them
            for r in aff.get("ranges", []):
                events = []
                for ev in r.get("events", []):
                    events.append(EventSpec(
                        introduced=ev.get("introduced"),
                        fixed=ev.get("fixed"),
                        last_affected=ev.get("last_affected"),
                        limit=ev.get("limit")
                    ))
                ranges_list.append(RangeSpec(
                    type=RangeType(r.get("type", "ECOSYSTEM")),
                    events=tuple(events),
                    repo=r.get("repo"),
                    database_specific=r.get("database_specific", {})
                ))
                
            # If specifiers string is present and ranges are missing, or it's a raw PEP 440 constraint
            spec_str = aff.get("database_specific", {}).get("pep440_specifier")
            if spec_str and not ranges_list:
                pep_ranges = cls.decompose_pep440_ranges(spec_str)
                if pep_ranges:
                    ranges_list.extend(pep_ranges)
            
            affected_list.append(AffectedPackage(
                package=PackageSpec(
                    name=pkg_name,
                    ecosystem=ecosystem,
                    purl=pkg_data.get("purl", f"pkg:pypi/{pkg_name}")
                ),
                ranges=tuple(ranges_list),
                versions=tuple(aff.get("versions", ()))
            ))
            
        references_list = []
        for ref in data.get("references", []):
            references_list.append(ReferenceSpec(
                url=ref.get("url", ""),
                type=ReferenceType(ref.get("type", "WEB"))
            ))

        return OsvVulnerability(
            id=data["id"],
            summary=data.get("summary", ""),
            details=data.get("details", ""),
            aliases=tuple(data.get("aliases", ())),
            published=data.get("published", ""),
            modified=data.get("modified", ""),
            affected=tuple(affected_list),
            references=tuple(references_list)
        )

    @classmethod
    def from_yaml(cls, yaml_content: str) -> OsvVulnerability:
        return cls.from_dict(yaml.safe_load(yaml_content))

    @classmethod
    def from_file(cls, path: str | Path) -> OsvVulnerability:
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_yaml(f.read())

PyPaConverter = PyPaAdvisoryConverter
