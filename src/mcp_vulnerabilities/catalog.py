"""Version-aware MCP catalog state, cache tracking, and unified security catalog engine."""

from __future__ import annotations

import gzip
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from mcp_vulnerabilities.analyzers.capability_classifier import (
    analyze_tool_security,
    classify_server_security_profile,
    generate_server_security_summary,
    generate_tool_security_comment,
)
from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher
from mcp_vulnerabilities.fingerprints.correlator import VulnerabilityCorrelator
from mcp_vulnerabilities.fingerprints.models import (
    ParameterMetadata,
    PromptSignature,
    ResourceSignature,
    ServerPackageSpec,
)
from mcp_vulnerabilities.models import OsvVulnerability

logger = logging.getLogger("mcp_vulnerabilities.catalog")


def normalize_version(ver_str: str | None) -> str:
    """Normalize version string, stripping leading 'v' and handling semver."""
    if not ver_str:
        return ""
    clean = ver_str.strip().lstrip("vV")
    try:
        return str(Version(clean))
    except InvalidVersion:
        return clean


def compute_remediation_target(
    current_version: str,
    versions: list[VersionSecurityRecord],
) -> str | None:
    """
    Computes the recommended update version for a given current_version.
    Returns the lowest safe version that is >= current_version.
    If no such version exists, returns None (meaning no fix is available).
    """
    def parse_ver(v_str: str) -> Version:
        clean = v_str.lstrip("v=").strip()
        try:
            return Version(clean)
        except InvalidVersion:
            return Version("0.0.0")

    try:
        curr_v = parse_ver(current_version)
    except Exception:
        return None

    # Filter to safe versions that are >= current_version
    safe_candidates = [
        r for r in versions
        if not r.is_vulnerable and parse_ver(r.version) >= curr_v
    ]

    if not safe_candidates:
        return None

    # Return the lowest among the safe candidates
    safe_candidates.sort(key=lambda r: parse_ver(r.version))
    return safe_candidates[0].version


def generate_upgrade_command(
    ecosystem: str,
    package_name: str,
    target_version: str | None,
) -> str | None:
    """
    Generates an ecosystem-specific upgrade command.
    """
    if not target_version:
        return None

    eco = ecosystem.lower()
    if eco in ("npm", "javascript"):
        return f"npm install {package_name}@^{target_version}"
    elif eco in ("pypi", "python", "pip"):
        return f"pip install --upgrade {package_name}>={target_version}"
    elif eco in ("docker", "containers"):
        return f"docker pull {package_name}:{target_version}"
    elif eco in ("cargo", "crates.io", "rust"):
        return f"cargo update -p {package_name} --precise {target_version}"
    elif eco in ("go", "golang"):
        return f"go get {package_name}@{target_version}"
    elif eco in ("maven", "java", "kotlin"):
        return "mvn versions:use-latest-versions"
    return None


def _parse_sort_version(ver_str: str) -> Version:
    """Safely parse version for sorting."""
    clean = normalize_version(ver_str)
    try:
        return Version(clean)
    except InvalidVersion:
        return Version("0.0.0")


@dataclass
class ServerRecord:
    """State record for a single audited MCP server package."""

    name: str
    ecosystem: str
    last_version_seen: str = ""
    last_checked_utc: str = ""
    known_vulnerabilities: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class McpCatalogState:
    """Persistent catalog state tracking audited MCP packages and versions to prevent duplicate queries."""

    def __init__(self, state_file: str | Path = "data/mcp_catalog_state.json", ttl_days: int = 30) -> None:
        self.state_file = Path(state_file)
        self.ttl_days = ttl_days
        self.records: dict[str, ServerRecord] = {}
        self.load()

    @staticmethod
    def package_key(ecosystem: str, name: str) -> str:
        """Deterministic canonical package key."""
        return f"{ecosystem.strip().lower()}:{name.strip().lower()}"

    def load(self) -> None:
        """Load state from disk if exists."""
        if not self.state_file.exists():
            return
        try:
            raw = json.loads(self.state_file.read_text(encoding="utf-8"))
            for k, v in raw.get("servers", {}).items():
                self.records[k] = ServerRecord(
                    name=v["name"],
                    ecosystem=v["ecosystem"],
                    last_version_seen=v.get("last_version_seen", ""),
                    last_checked_utc=v.get("last_checked_utc", ""),
                    known_vulnerabilities=v.get("known_vulnerabilities", []),
                    metadata=v.get("metadata", {}),
                )
        except Exception as exc:
            logger.warning("Failed to load catalog state from %s: %s", self.state_file, exc)

    def save(self) -> None:
        """Atomically persist state to disk via temporary file."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": "1.0.0",
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "total_servers": len(self.records),
            "servers": {k: asdict(v) for k, v in sorted(self.records.items())},
        }
        tmp_file = self.state_file.with_suffix(".tmp")
        tmp_file.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp_file, self.state_file)

    def should_query(self, ecosystem: str, name: str, current_version: str | None = None) -> bool:
        """Check whether a package requires re-querying based on version change or TTL."""
        key = self.package_key(ecosystem, name)
        record = self.records.get(key)
        if not record:
            return True  # Never audited before

        # If current_version is provided, compare normalized versions
        if current_version:
            norm_curr = normalize_version(current_version)
            norm_last = normalize_version(record.last_version_seen)
            if norm_curr != norm_last or not record.last_version_seen:
                return True

        # Check TTL staleness (if last checked > ttl_days ago)
        if record.last_checked_utc:
            try:
                checked_dt = datetime.fromisoformat(record.last_checked_utc.replace("Z", "+00:00"))
                age_days = (datetime.now(UTC) - checked_dt).total_seconds() / 86400.0
                if age_days > self.ttl_days:
                    return True
            except Exception:
                return True

        return False

    def mark_stale(self, ecosystem: str, name: str) -> None:
        """Force a package to be re-queried on next pass (e.g. when an external advisory names it)."""
        key = self.package_key(ecosystem, name)
        if key in self.records:
            self.records[key].last_version_seen = ""
            self.records[key].last_checked_utc = ""

    def update_record(
        self,
        ecosystem: str,
        name: str,
        version: str = "",
        vulnerabilities: list[str] | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Update or insert a server record after successful audit."""
        key = self.package_key(ecosystem, name)
        existing_vulns = self.records[key].known_vulnerabilities if key in self.records else []
        new_vulns = sorted(set(existing_vulns + (vulnerabilities or [])))

        existing_meta = self.records[key].metadata if key in self.records else {}
        if metadata:
            existing_meta.update(metadata)

        if version:
            norm_ver = normalize_version(version)
        else:
            norm_ver = normalize_version(self.records[key].last_version_seen) if key in self.records else ""

        self.records[key] = ServerRecord(
            name=name,
            ecosystem=ecosystem,
            last_version_seen=norm_ver,
            last_checked_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            known_vulnerabilities=new_vulns,
            metadata=existing_meta,
        )


@dataclass(frozen=True)
class ToolSecurityAssessment:
    """Per-tool security and capability risk evaluation."""

    name: str
    canonical_hash: str
    description: str = ""
    risk_score: float = 0.0
    risk_tier: str = "LOW"
    security_comment: str = ""
    parameters: tuple[ParameterMetadata, ...] = ()
    annotations: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "canonical_hash": self.canonical_hash,
            "description": self.description,
            "risk_score": self.risk_score,
            "risk_tier": self.risk_tier,
            "security_comment": self.security_comment,
            "parameters": [
                p.to_dict() if hasattr(p, "to_dict") else p for p in self.parameters
            ],
            "annotations": self.annotations,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolSecurityAssessment:
        raw_params = data.get("parameters", ())
        params = tuple(
            ParameterMetadata.from_dict(p) if isinstance(p, dict) else p
            for p in raw_params
        )
        return cls(
            name=data["name"],
            canonical_hash=data.get("canonical_hash", ""),
            description=data.get("description", ""),
            risk_score=float(data.get("risk_score", 0.0)),
            risk_tier=data.get("risk_tier", "LOW"),
            security_comment=data.get("security_comment", ""),
            parameters=params,
            annotations=dict(data.get("annotations", {})),
        )


@dataclass
class VersionSecurityRecord:
    """Security assessment strictly isolated to a specific version release."""

    version: str
    is_vulnerable: bool
    advisories: list[OsvVulnerability] = field(default_factory=list)
    toolset_canonical_hash: str = ""
    tools: list[ToolSecurityAssessment] = field(default_factory=list)
    prompts: list[PromptSignature] = field(default_factory=list)
    resources: list[ResourceSignature] = field(default_factory=list)
    release_date: str | None = None
    required_env_vars: tuple[str, ...] = ()
    recommended_update_version: str | None = None
    upgrade_command: str | None = None
    no_fix_available: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "is_vulnerable": self.is_vulnerable,
            "advisories": [
                adv.to_dict() if hasattr(adv, "to_dict") else adv
                for adv in self.advisories
            ],
            "toolset_canonical_hash": self.toolset_canonical_hash,
            "tools": [t.to_dict() for t in self.tools],
            "prompts": [
                p.to_dict() if hasattr(p, "to_dict") else p for p in self.prompts
            ],
            "resources": [
                r.to_dict() if hasattr(r, "to_dict") else r for r in self.resources
            ],
            "release_date": self.release_date,
            "required_env_vars": list(self.required_env_vars),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VersionSecurityRecord:
        raw_advs = data.get("advisories", [])
        advisories = [
            OsvVulnerability.from_dict(a) if isinstance(a, dict) else a
            for a in raw_advs
        ]
        raw_tools = data.get("tools", [])
        tools = [
            ToolSecurityAssessment.from_dict(t) if isinstance(t, dict) else t
            for t in raw_tools
        ]
        raw_prompts = data.get("prompts", [])
        prompts = [
            PromptSignature.from_dict(p) if isinstance(p, dict) else p
            for p in raw_prompts
        ]
        raw_resources = data.get("resources", [])
        resources = [
            ResourceSignature.from_dict(r) if isinstance(r, dict) else r
            for r in raw_resources
        ]
        return cls(
            version=data["version"],
            is_vulnerable=bool(data.get("is_vulnerable", False)),
            advisories=advisories,
            toolset_canonical_hash=data.get("toolset_canonical_hash", ""),
            tools=tools,
            prompts=prompts,
            resources=resources,
            release_date=data.get("release_date"),
            required_env_vars=tuple(data.get("required_env_vars", ())),
            recommended_update_version=data.get("recommended_update_version"),
            upgrade_command=data.get("upgrade_command"),
            no_fix_available=bool(data.get("no_fix_available", False)),
        )


@dataclass
class UnifiedMcpSecurityRecord:
    """Unified security and fingerprint profile for an MCP server across all releases."""

    package_name: str
    ecosystem: str
    purl: str
    display_name: str | None = None
    description: str | None = None
    author: str | None = None
    repository_url: str | None = None
    homepage_url: str | None = None
    license: str | None = None
    latest_version: str = ""
    recommended_safe_version: str | None = None
    is_vulnerable: bool = False
    security_summary: str = ""
    static_risk_score: float = 0.0
    static_risk_tier: str = "LOW"
    versions: list[VersionSecurityRecord] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "ecosystem": self.ecosystem,
            "purl": self.purl,
            "display_name": self.display_name,
            "description": self.description,
            "author": self.author,
            "repository_url": self.repository_url,
            "homepage_url": self.homepage_url,
            "license": self.license,
            "latest_version": self.latest_version,
            "recommended_safe_version": self.recommended_safe_version,
            "is_vulnerable": self.is_vulnerable,
            "security_summary": self.security_summary,
            "static_risk_score": self.static_risk_score,
            "static_risk_tier": self.static_risk_tier,
            "versions": [v.to_dict() for v in self.versions],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UnifiedMcpSecurityRecord:
        raw_versions = data.get("versions", [])
        versions = [
            VersionSecurityRecord.from_dict(v) if isinstance(v, dict) else v
            for v in raw_versions
        ]
        return cls(
            package_name=data["package_name"],
            ecosystem=data.get("ecosystem", "generic"),
            purl=data.get(
                "purl",
                f"pkg:{data.get('ecosystem', 'generic').lower()}/{data['package_name']}",
            ),
            display_name=data.get("display_name"),
            description=data.get("description"),
            author=data.get("author"),
            repository_url=data.get("repository_url"),
            homepage_url=data.get("homepage_url"),
            license=data.get("license"),
            latest_version=data.get("latest_version", ""),
            recommended_safe_version=data.get("recommended_safe_version"),
            is_vulnerable=bool(data.get("is_vulnerable", False)),
            security_summary=data.get("security_summary", ""),
            static_risk_score=float(data.get("static_risk_score", 0.0)),
            static_risk_tier=data.get("static_risk_tier", "LOW"),
            versions=versions,
        )


def _load_passports(passports_path: str | Path | None) -> dict[str, ServerPackageSpec]:
    """Helper to load ServerPackageSpecs from gz, json, or directory."""
    passports: dict[str, ServerPackageSpec] = {}

    target: Path | None = None
    if passports_path:
        target = Path(passports_path)
    else:
        for candidate in (
            Path("passports.json.gz"),
            Path("data/passports.json.gz"),
            Path("data/fingerprints"),
        ):
            if candidate.exists():
                target = candidate
                break

    if not target or not target.exists():
        return passports

    if target.is_dir():
        for j_file in target.rglob("*.json"):
            if j_file.name in ("sync_state.json", "index.json", ".passport_index.pickle"):
                continue
            try:
                data = json.loads(j_file.read_text(encoding="utf-8"))
                spec = ServerPackageSpec.from_dict(data)
                passports[spec.package_name] = spec
            except Exception as exc:
                logger.debug("Failed to read passport %s: %exc", j_file, exc)
    else:
        open_func = gzip.open if target.name.endswith(".gz") else open
        try:
            with open_func(target, "rt", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    if "passports" in data and isinstance(data["passports"], (dict, list)):
                        data = data["passports"]
                    if isinstance(data, dict):
                        for k, v in data.items():
                            if isinstance(v, dict):
                                spec = ServerPackageSpec.from_dict(v)
                                passports[spec.package_name] = spec
                    elif isinstance(data, list):
                        for v in data:
                            if isinstance(v, dict):
                                spec = ServerPackageSpec.from_dict(v)
                                passports[spec.package_name] = spec
                elif isinstance(data, list):
                    for v in data:
                        if isinstance(v, dict):
                            spec = ServerPackageSpec.from_dict(v)
                            passports[spec.package_name] = spec
        except Exception as exc:
            logger.warning("Failed to load passports from %s: %s", target, exc)

    return passports


def build_unified_mcp_security_catalog(
    passports_path: str | Path | None = None,
    vulnerabilities_dir: str | Path | None = None,
) -> dict[str, UnifiedMcpSecurityRecord]:
    """
    Build a unified MCP security catalog cross-correlating server packages and version
    fingerprints against vulnerability advisories.

    Strictly isolates vulnerabilities to the versions they affect, marks non-affected
    releases safe (`is_vulnerable=False`), computes `recommended_safe_version`, and
    attaches capability risk assessments to tools.
    """
    # 1. Load Vulnerability Matcher
    matcher: VulnerabilityMatcher
    v_path: Path | None = None
    if vulnerabilities_dir:
        v_path = Path(vulnerabilities_dir)
    else:
        for candidate in (
            Path("vulnerabilities.json.gz"),
            Path("data/vulnerabilities.snapshot.json.gz"),
            Path("data/vulnerabilities"),
        ):
            if candidate.exists():
                v_path = candidate
                break

    if v_path and v_path.exists():
        if v_path.is_dir():
            matcher = VulnerabilityMatcher.from_directory(v_path)
        else:
            matcher = VulnerabilityMatcher.from_snapshot(v_path)
    else:
        matcher = VulnerabilityMatcher([])

    # 2. Load Passports
    passports = _load_passports(passports_path)

    unified_catalog: dict[str, UnifiedMcpSecurityRecord] = {}

    # 3. Process known passport packages
    for pkg_name, spec in passports.items():
        norm_name = VulnerabilityMatcher._normalize_package_name(spec.package_name)
        candidate_advs = matcher._package_index.get(norm_name, [])

        version_records: list[VersionSecurityRecord] = []
        all_tools_for_scoring: list[dict[str, Any]] = []

        for vf in spec.versions:
            ver_str = vf.version
            is_vuln = False
            matching_advs: list[OsvVulnerability] = []

            for adv_dict in candidate_advs:
                for affected in adv_dict.get("affected", []):
                    pkg_meta = affected.get("package", {})
                    if (
                        VulnerabilityMatcher._normalize_package_name(pkg_meta.get("name", ""))
                        != norm_name
                    ):
                        continue

                    eco = pkg_meta.get("ecosystem", "").lower()
                    if eco and spec.ecosystem:
                        spec_eco = spec.ecosystem.lower()
                        if eco != spec_eco:
                            if eco == "pypi" and spec_eco in ("pypi", "pip") or eco == "golang" and spec_eco in ("go", "golang"):
                                pass
                            else:
                                continue

                    ranges = affected.get("ranges", [])
                    versions = affected.get("versions", [])
                    if matcher._is_version_in_ranges(ver_str, ranges, versions):
                        is_vuln = True
                        try:
                            matching_advs.append(OsvVulnerability.from_dict(adv_dict))
                        except Exception:
                            pass

            # Build tool security assessments
            tool_assessments: list[ToolSecurityAssessment] = []
            for tool in vf.tool_signatures:
                tool_dict = tool.to_dict()
                all_tools_for_scoring.append(tool_dict)
                analysis = analyze_tool_security(tool_dict)
                comment = generate_tool_security_comment(
                    tool=tool_dict,
                    analysis=analysis,
                    affecting_advisories=[a.id for a in matching_advs],
                )
                assessment = ToolSecurityAssessment(
                    name=tool.name,
                    canonical_hash=tool.canonical_hash,
                    description=tool.description,
                    risk_score=float(analysis.get("risk_score", 0.0)),
                    risk_tier=analysis.get("risk_tier", "LOW"),
                    security_comment=comment,
                    parameters=tool.parameters,
                    annotations=tool.annotations,
                )
                tool_assessments.append(assessment)

            v_record = VersionSecurityRecord(
                version=ver_str,
                is_vulnerable=is_vuln,
                advisories=matching_advs,
                toolset_canonical_hash=vf.toolset_canonical_hash,
                tools=tool_assessments,
                prompts=list(vf.prompt_signatures),
                resources=list(vf.resource_signatures),
                release_date=vf.release_date,
                required_env_vars=vf.required_env_vars,
            )
            version_records.append(v_record)

        # Sort versions chronologically/semantically
        version_records.sort(key=lambda r: _parse_sort_version(r.version))

        # Add per-version remediation targets
        for v_rec in version_records:
            if v_rec.is_vulnerable:
                rec_ver = compute_remediation_target(v_rec.version, version_records)
                v_rec.recommended_update_version = rec_ver
                if rec_ver:
                    v_rec.upgrade_command = generate_upgrade_command(
                        spec.ecosystem,
                        spec.package_name,
                        rec_ver,
                    )
                else:
                    v_rec.no_fix_available = True

        # Determine latest_version and recommended_safe_version
        latest_version = version_records[-1].version if version_records else ""
        recommended_safe_version: str | None = None
        for r in reversed(version_records):
            if not r.is_vulnerable:
                recommended_safe_version = r.version
                break

        overall_vuln = any(r.is_vulnerable for r in version_records)

        # Profile scoring
        profile = classify_server_security_profile(all_tools_for_scoring)
        vuln_count = sum(1 for r in version_records if r.is_vulnerable)
        safe_count = len(version_records) - vuln_count
        sec_summary = generate_server_security_summary(
            package_name=spec.package_name,
            profile=profile,
            vuln_versions_count=vuln_count,
            safe_versions_count=safe_count,
        )

        record = UnifiedMcpSecurityRecord(
            package_name=spec.package_name,
            ecosystem=spec.ecosystem,
            purl=spec.purl,
            display_name=spec.display_name or spec.package_name,
            description=spec.description,
            author=spec.author,
            repository_url=spec.repository_url,
            homepage_url=spec.homepage_url,
            license=spec.license,
            latest_version=latest_version,
            recommended_safe_version=recommended_safe_version,
            is_vulnerable=overall_vuln,
            security_summary=sec_summary,
            static_risk_score=float(profile.get("overall_risk_score", 0.0)),
            static_risk_tier=profile.get("risk_tier", "LOW"),
            versions=version_records,
        )
        unified_catalog[spec.package_name] = record

    # 4. Synthesize records for advisory-only packages not in passports
    for norm_name, advs in matcher._package_index.items():
        if any(
            VulnerabilityMatcher._normalize_package_name(p) == norm_name
            for p in passports
        ):
            continue

        first_adv = advs[0]
        pkg_name = norm_name
        eco = "generic"
        for aff in first_adv.get("affected", []):
            p = aff.get("package", {})
            if VulnerabilityMatcher._normalize_package_name(p.get("name", "")) == norm_name:
                pkg_name = p.get("name", norm_name)
                eco = p.get("ecosystem", "generic")
                break

        # Collect discrete versions mentioned across advisories
        discrete_versions = set()
        for adv_dict in advs:
            for aff in adv_dict.get("affected", []):
                for v in aff.get("versions", []):
                    discrete_versions.add(str(v))
                for r in aff.get("ranges", []):
                    for ev in r.get("events", []):
                        if "fixed" in ev:
                            discrete_versions.add(str(ev["fixed"]))
                        if "introduced" in ev and ev["introduced"] != "0":
                            discrete_versions.add(str(ev["introduced"]))

        v_list = sorted(list(discrete_versions), key=_parse_sort_version)
        if not v_list:
            v_list = ["1.0.0"]

        syn_version_records: list[VersionSecurityRecord] = []
        for ver_str in v_list:
            matching_advs = []
            for adv_dict in advs:
                for aff in adv_dict.get("affected", []):
                    ranges = aff.get("ranges", [])
                    versions = aff.get("versions", [])
                    if matcher._is_version_in_ranges(ver_str, ranges, versions):
                        try:
                            matching_advs.append(OsvVulnerability.from_dict(adv_dict))
                        except Exception:
                            matching_advs.append(adv_dict)

            is_vuln = len(matching_advs) > 0
            syn_version_records.append(
                VersionSecurityRecord(
                    version=ver_str,
                    is_vulnerable=is_vuln,
                    advisories=matching_advs,
                )
            )

        for v_rec in syn_version_records:
            if v_rec.is_vulnerable:
                rec_ver = compute_remediation_target(v_rec.version, syn_version_records)
                v_rec.recommended_update_version = rec_ver
                if rec_ver:
                    v_rec.upgrade_command = generate_upgrade_command(
                        eco,
                        pkg_name,
                        rec_ver,
                    )
                else:
                    v_rec.no_fix_available = True

        latest_version = syn_version_records[-1].version
        rec_safe = None
        for r in reversed(syn_version_records):
            if not r.is_vulnerable:
                rec_safe = r.version
                break

        record = UnifiedMcpSecurityRecord(
            package_name=pkg_name,
            ecosystem=eco,
            purl=f"pkg:{eco.lower()}/{pkg_name}",
            display_name=pkg_name,
            description=first_adv.get("summary", ""),
            latest_version=latest_version,
            recommended_safe_version=rec_safe,
            is_vulnerable=True,
            security_summary=f"Package `{pkg_name}` has {len(advs)} security advisories.",
            versions=syn_version_records,
        )
        unified_catalog[pkg_name] = record

    return unified_catalog


__all__ = [
    "McpCatalogState",
    "ServerRecord",
    "ToolSecurityAssessment",
    "UnifiedMcpSecurityRecord",
    "VersionSecurityRecord",
    "VulnerabilityCorrelator",
    "build_unified_mcp_security_catalog",
    "normalize_version",
]
