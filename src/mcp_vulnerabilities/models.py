"""OSV (Open Source Vulnerability) v1.6.0 schema models with MCP security extensions."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from urllib.parse import quote, unquote


class RangeType(StrEnum):
    SEMVER = "SEMVER"
    ECOSYSTEM = "ECOSYSTEM"
    GIT = "GIT"


class SeverityType(StrEnum):
    CVSS_V2 = "CVSS_V2"
    CVSS_V3 = "CVSS_V3"
    CVSS_V4 = "CVSS_V4"


class ReferenceType(StrEnum):
    ADVISORY = "ADVISORY"
    ARTICLE = "ARTICLE"
    DETECTION = "DETECTION"
    DISCUSSION = "DISCUSSION"
    REPORT = "REPORT"
    FIX = "FIX"
    INTRODUCED = "INTRODUCED"
    PACKAGE = "PACKAGE"
    EVIDENCE = "EVIDENCE"
    WEB = "WEB"


@dataclass(frozen=True)
class PackageSpec:
    """Identifies the affected package and ecosystem."""

    name: str
    ecosystem: str
    purl: str | None = None

    def canonical_purl(self) -> str:
        """Return or compute the standard PURL string."""
        if self.purl:
            return self.purl
        eco = self.ecosystem.lower()
        if eco in ("pypi", "pip"):
            encoded = self.name.lower().replace("_", "-")
            return f"pkg:pypi/{encoded}"
        elif eco == "npm":
            encoded = (
                quote(self.name, safe="/") if ("@" in self.name or "/" in self.name) else self.name
            )
            return f"pkg:npm/{encoded}"
        elif eco == "docker":
            return f"pkg:docker/{self.name}"
        elif eco == "go" or eco == "golang":
            return f"pkg:golang/{self.name}"
        return f"pkg:mcp/{self.name}"


@dataclass(frozen=True)
class EventSpec:
    """Specific version milestone within a vulnerability range."""

    introduced: str | None = None
    fixed: str | None = None
    last_affected: str | None = None
    limit: str | None = None


@dataclass(frozen=True)
class RangeSpec:
    """Affected version range specification."""

    type: RangeType = RangeType.SEMVER
    events: tuple[EventSpec, ...] = field(default_factory=tuple)
    repo: str | None = None
    database_specific: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class SeveritySpec:
    """Numerical or categorical vulnerability severity score."""

    type: SeverityType
    score: str


@dataclass(frozen=True)
class ReferenceSpec:
    """External link or reference document."""

    url: str
    type: ReferenceType = ReferenceType.WEB


@dataclass(frozen=True)
class CreditSpec:
    """Individual or organization credited with vulnerability discovery/mitigation."""

    name: str
    contact: tuple[str, ...] = field(default_factory=tuple)
    type: str | None = None


@dataclass(frozen=True)
class DatabaseSpecificMcp:
    """MCP ecosystem-specific security extensions."""

    vulnerable_tools: tuple[str, ...] = field(default_factory=tuple)
    cwe_ids: tuple[str, ...] = field(default_factory=tuple)
    owasp_mcp_category: str | None = None
    epss_score: float | None = None
    cvss_v3_vector: str | None = None
    cvss_v4_vector: str | None = None
    cvss_score: float | None = None
    severity: str | None = None
    remediation_guidance: str | None = None
    verity_condition_id: str | None = None


@dataclass(frozen=True)
class AffectedPackage:
    """Details on an affected package, versions, and ecosystem-specific parameters."""

    package: PackageSpec
    ranges: tuple[RangeSpec, ...] = field(default_factory=tuple)
    versions: tuple[str, ...] = field(default_factory=tuple)
    ecosystem_specific: dict[str, Any] = field(default_factory=dict)
    database_specific: DatabaseSpecificMcp = field(default_factory=DatabaseSpecificMcp)


@dataclass(frozen=True)
class OsvVulnerability:
    """Full Open Source Vulnerability (OSV v1.6.0) specification document."""

    id: str
    summary: str
    details: str
    schema_version: str = "1.6.0"
    modified: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z")
    )
    published: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat().replace("+00:00", "Z")
    )
    withdrawn: str | None = None
    aliases: tuple[str, ...] = field(default_factory=tuple)
    related: tuple[str, ...] = field(default_factory=tuple)
    severity: tuple[SeveritySpec, ...] = field(default_factory=tuple)
    affected: tuple[AffectedPackage, ...] = field(default_factory=tuple)
    references: tuple[ReferenceSpec, ...] = field(default_factory=tuple)
    credits: tuple[CreditSpec, ...] = field(default_factory=tuple)
    database_specific: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.id:
            raise ValueError("OsvVulnerability 'id' is required.")
        if not self.summary:
            raise ValueError("OsvVulnerability 'summary' is required.")
        if not self.details:
            raise ValueError("OsvVulnerability 'details' is required.")

    def to_dict(self) -> dict[str, Any]:
        """Convert model to standard JSON dictionary with None and empty collections cleaned."""

        def _clean(val: Any) -> Any:
            if isinstance(val, dict):
                return {
                    k: _clean(v)
                    for k, v in val.items()
                    if v is not None and v != () and v != [] and v != {}
                }
            elif isinstance(val, (list, tuple)):
                return [_clean(v) for v in val]
            elif isinstance(val, StrEnum):
                return str(val.value)
            return val

        raw = asdict(self)
        cleaned = _clean(raw)
        return cleaned

    def to_json(self, indent: int = 2) -> str:
        """Serialize to deterministic, canonical indented JSON string."""
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> OsvVulnerability:
        """Parse raw dictionary into OsvVulnerability model."""
        affected_list: list[AffectedPackage] = []
        for aff in data.get("affected", []):
            pkg_data = aff.get("package", {})
            pkg = PackageSpec(
                name=str(pkg_data.get("name", "")),
                ecosystem=str(pkg_data.get("ecosystem", "")),
                purl=pkg_data.get("purl"),
            )

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
                ranges_list.append(
                    RangeSpec(
                        type=RangeType(r.get("type", "SEMVER")),
                        events=tuple(events_list),
                        repo=r.get("repo"),
                        database_specific=r.get("database_specific", {}),
                    )
                )

            db_mcp_raw = aff.get("database_specific", {})
            epss_val = (
                float(db_mcp_raw["epss_score"])
                if db_mcp_raw.get("epss_score") is not None
                else None
            )
            cvss_val = (
                float(db_mcp_raw["cvss_score"])
                if db_mcp_raw.get("cvss_score") is not None
                else None
            )
            db_mcp = DatabaseSpecificMcp(
                vulnerable_tools=tuple(db_mcp_raw.get("vulnerable_tools", ())),
                cwe_ids=tuple(db_mcp_raw.get("cwe_ids", ())),
                owasp_mcp_category=db_mcp_raw.get("owasp_mcp_category"),
                epss_score=epss_val,
                cvss_v3_vector=db_mcp_raw.get("cvss_v3_vector"),
                cvss_v4_vector=db_mcp_raw.get("cvss_v4_vector"),
                cvss_score=cvss_val,
                severity=db_mcp_raw.get("severity"),
                remediation_guidance=db_mcp_raw.get("remediation_guidance"),
                verity_condition_id=db_mcp_raw.get("verity_condition_id"),
            )

            affected_list.append(
                AffectedPackage(
                    package=pkg,
                    ranges=tuple(ranges_list),
                    versions=tuple(aff.get("versions", ())),
                    ecosystem_specific=aff.get("ecosystem_specific", {}),
                    database_specific=db_mcp,
                )
            )

        severities_list: list[SeveritySpec] = []
        for s in data.get("severity", []):
            severities_list.append(
                SeveritySpec(
                    type=SeverityType(s.get("type", "CVSS_V3")),
                    score=str(s.get("score", "")),
                )
            )

        references_list: list[ReferenceSpec] = []
        for ref in data.get("references", []):
            references_list.append(
                ReferenceSpec(
                    url=str(ref.get("url", "")),
                    type=ReferenceType(ref.get("type", "WEB")),
                )
            )

        credits_list: list[CreditSpec] = []
        for cr in data.get("credits", []):
            credits_list.append(
                CreditSpec(
                    name=str(cr.get("name", "")),
                    contact=tuple(cr.get("contact", ())),
                    type=cr.get("type"),
                )
            )

        return cls(
            id=str(data["id"]),
            summary=str(data.get("summary", "")),
            details=str(data.get("details", "")),
            schema_version=str(data.get("schema_version", "1.6.0")),
            modified=str(data.get("modified", "")),
            published=str(data.get("published", "")),
            withdrawn=data.get("withdrawn"),
            aliases=tuple(data.get("aliases", ())),
            related=tuple(data.get("related", ())),
            severity=tuple(severities_list),
            affected=tuple(affected_list),
            references=tuple(references_list),
            credits=tuple(credits_list),
            database_specific=data.get("database_specific", {}),
        )


def parse_purl(purl: str) -> tuple[str, str, str | None]:
    """Parse a Package URL string into (ecosystem, package_name, version)."""
    if not purl.startswith("pkg:"):
        raise ValueError(f"Invalid PURL format: '{purl}'")
    rest = purl[4:]
    if "/" not in rest:
        raise ValueError(f"Invalid PURL format, missing slash: '{purl}'")
    ecosystem, pkg_part = rest.split("/", 1)

    version = None
    if "@" in pkg_part:
        pkg_name, version = pkg_part.rsplit("@", 1)
    else:
        pkg_name = pkg_part

    decoded_name = unquote(pkg_name)
    return ecosystem, decoded_name, version


def build_purl(ecosystem: str, package_name: str, version: str | None = None) -> str:
    """Build a canonical Package URL string from components."""
    eco = ecosystem.lower()
    if eco in ("pypi", "pip"):
        eco = "pypi"
        encoded = package_name.lower().replace("_", "-")
    elif eco == "npm":
        encoded = (
            quote(package_name, safe="/")
            if ("@" in package_name or "/" in package_name)
            else package_name
        )
    elif eco in ("go", "golang"):
        eco = "golang"
        encoded = quote(package_name, safe="/") if "/" in package_name else package_name
    else:
        encoded = quote(package_name, safe="/") if "/" in package_name else package_name

    base = f"pkg:{eco}/{encoded}"
    if version:
        return f"{base}@{version}"
    return base
