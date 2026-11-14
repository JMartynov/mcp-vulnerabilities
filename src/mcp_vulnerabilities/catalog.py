"""Version-aware MCP catalog state, cache tracking, and unified security catalog engine."""

from __future__ import annotations

import gzip
import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from packaging.version import InvalidVersion, Version

from mcp_vulnerabilities.state import atomic_save_json
from mcp_vulnerabilities.analyzers.capability_classifier import (
    analyze_tool_security,
    classify_server_security_profile,
    generate_server_security_summary,
    generate_tool_security_comment,
)
from mcp_vulnerabilities.analyzers.models import DualAxisSecurityAssessment
from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher, is_version_in_ranges
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
class TombstoneRecord:
    name: str
    ecosystem: str
    reason: str  # "deprecated", "yanked", "archived", "deleted_404"
    tombstoned_at_utc: str
    details: str = ""

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
        self.tombstones: dict[str, TombstoneRecord] = {}
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
            for k, v in raw.get("tombstones", {}).items():
                self.tombstones[k] = TombstoneRecord(
                    name=v["name"],
                    ecosystem=v["ecosystem"],
                    reason=v["reason"],
                    tombstoned_at_utc=v["tombstoned_at_utc"],
                    details=v.get("details", ""),
                )
        except Exception as exc:
            logger.warning("Failed to load catalog state from %s: %s", self.state_file, exc)

            # Attempt to recover from standard backup (.bak)
            bak_file = self.state_file.with_name(self.state_file.name + ".bak")
            if bak_file.is_file():
                try:
                    logger.info("Attempting to recover catalog state from %s", bak_file)
                    raw = json.loads(bak_file.read_text(encoding="utf-8"))
                    for k, v in raw.get("servers", {}).items():
                        self.records[k] = ServerRecord(
                            name=v["name"],
                            ecosystem=v["ecosystem"],
                            last_version_seen=v.get("last_version_seen", ""),
                            last_checked_utc=v.get("last_checked_utc", ""),
                            known_vulnerabilities=v.get("known_vulnerabilities", []),
                            metadata=v.get("metadata", {}),
                        )
                    for k, v in raw.get("tombstones", {}).items():
                        self.tombstones[k] = TombstoneRecord(
                            name=v["name"],
                            ecosystem=v["ecosystem"],
                            reason=v["reason"],
                            tombstoned_at_utc=v["tombstoned_at_utc"],
                            details=v.get("details", ""),
                        )
                    logger.info("Successfully recovered catalog state from backup.")
                    return
                except Exception as backup_err:
                    logger.warning("Failed to recover catalog state from backup %s: %s", bak_file, backup_err)

            # Standard backup failed or missing, rename original corrupted file so we don't lose it entirely
            import shutil
            corrupt_file = self.state_file.with_name(self.state_file.name + ".corrupt.bak")
            try:
                shutil.move(self.state_file, corrupt_file)
            except Exception:
                pass

    def save(self) -> None:
        """Atomically persist state to disk via temporary file."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": "1.0.0",
            "updated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "total_servers": len(self.records),
            "servers": {k: asdict(v) for k, v in sorted(self.records.items())},
            "tombstones": {k: asdict(v) for k, v in sorted(self.tombstones.items())},
        }
        try:
            atomic_save_json(self.state_file, payload)
        except Exception as e:
            logger.error(f"Error saving catalog state: {e}")

    def is_expired(self, key: str, ttl_days: int = 30) -> bool:
        """Check if a package's TTL has expired."""
        record = self.records.get(key)
        if not record:
            return True
        if not record.last_checked_utc:
            return True
        try:
            checked_dt = datetime.fromisoformat(record.last_checked_utc.replace("Z", "+00:00"))
            age_days = (datetime.now(UTC) - checked_dt).total_seconds() / 86400.0
            return age_days > ttl_days
        except Exception:
            return True

    def should_query(self, ecosystem: str, name: str, current_version: str | None = None, ttl_days: int = 30) -> bool:
        """Check whether a package requires re-querying based on version change or TTL."""
        key = self.package_key(ecosystem, name)

        if hasattr(self, "tombstones") and key in self.tombstones:
            return False

        record = self.records.get(key)
        if not record:
            return True  # Never audited before

        # If current_version is provided, compare normalized versions
        if current_version:
            norm_curr = normalize_version(current_version)
            norm_last = normalize_version(record.last_version_seen)
            if norm_curr != norm_last or not record.last_version_seen:
                return True

        # Check TTL staleness
        return self.is_expired(key, ttl_days)

    def record_deprecation(self, ecosystem: str, name: str, reason: str, details: str = "") -> None:
        """Records a tombstone and removes the package from active records."""
        key = self.package_key(ecosystem, name)
        if key in self.records:
            del self.records[key]
        self.tombstones[key] = TombstoneRecord(
            name=name,
            ecosystem=ecosystem,
            reason=reason,
            tombstoned_at_utc=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            details=details,
        )

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
    connections: list[dict[str, Any]] = field(default_factory=list)
    recommended_update_version: str | None = None
    upgrade_command: str | None = None
    no_fix_available: bool = False
    dual_axis_security: DualAxisSecurityAssessment | None = None

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
            "connections": self.connections,
            "dual_axis_security": self.dual_axis_security.to_dict() if self.dual_axis_security else None,
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

        dual_axis_security = None
        if "dual_axis_security" in data and data["dual_axis_security"] is not None:
            dual_axis_security = DualAxisSecurityAssessment.from_dict(data["dual_axis_security"])

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
            connections=data.get("connections", []),
            recommended_update_version=data.get("recommended_update_version"),
            upgrade_command=data.get("upgrade_command"),
            no_fix_available=bool(data.get("no_fix_available", False)),
            dual_axis_security=dual_axis_security,
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
    is_unpublished: bool = False
    is_malicious: bool = False
    quarantine_tier: str | None = None
    malicious_advisory_id: str | None = None
    composite_risk_score: float | None = None
    repo_http_status: int = 200
    archival_reason: str | None = None
    transport: str | None = None
    prompts_count: int = 0
    resources_count: int = 0
    toolset_canonical_hash: str | None = None
    required_env_vars: tuple[str, ...] = field(default_factory=tuple)
    versions: list[VersionSecurityRecord] = field(default_factory=list)
    dual_axis_security: DualAxisSecurityAssessment | None = None

    @property
    def mcp_trust_score(self) -> float:
        """Legacy fallback property for backward compatibility."""
        return self.static_risk_score

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
            "is_unpublished": self.is_unpublished,
            "repo_http_status": self.repo_http_status,
            "archival_reason": self.archival_reason,
            "is_malicious": self.is_malicious,
            "quarantine_tier": self.quarantine_tier,
            "malicious_advisory_id": self.malicious_advisory_id,
            "composite_risk_score": self.composite_risk_score,
            "transport": self.transport,
            "prompts_count": self.prompts_count,
            "resources_count": self.resources_count,
            "toolset_canonical_hash": self.toolset_canonical_hash,
            "required_env_vars": list(self.required_env_vars),
            "versions": [v.to_dict() for v in self.versions],
            "dual_axis_security": self.dual_axis_security.to_dict() if self.dual_axis_security else None,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> UnifiedMcpSecurityRecord:
        raw_versions = data.get("versions", [])
        versions = [
            VersionSecurityRecord.from_dict(v) if isinstance(v, dict) else v
            for v in raw_versions
        ]

        dual_axis_security = None
        if "dual_axis_security" in data and data["dual_axis_security"] is not None:
            dual_axis_security = DualAxisSecurityAssessment.from_dict(data["dual_axis_security"])

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
            is_unpublished=bool(data.get("is_unpublished", False)),
            repo_http_status=int(data.get("repo_http_status", 200)),
            archival_reason=data.get("archival_reason"),
            transport=data.get("transport"),
            prompts_count=int(data.get("prompts_count", 0)),
            resources_count=int(data.get("resources_count", 0)),
            toolset_canonical_hash=data.get("toolset_canonical_hash"),
            required_env_vars=tuple(data.get("required_env_vars", ())),
            versions=versions,
            dual_axis_security=dual_axis_security,
        )


def load_passport_data(
    passports_path: str | Path | None = None,
    as_specs: bool = True,
) -> dict[str, Any]:
    """
    Consolidate passport file discovery and loading logic (directory vs json vs passports.json.gz).

    Args:
        passports_path: Path to a directory containing passport json files, or a .json/.json.gz file.
                        If None or if the path does not exist, checks candidate paths:
                        'passports.json.gz', 'data/passports.json.gz', 'data/fingerprints'.
        as_specs: If True, returns dict[str, ServerPackageSpec]. If False, returns dict[str, dict] (raw passport data).

    Returns:
        Mapping from package name to ServerPackageSpec (if as_specs=True) or raw dictionary (if as_specs=False).
    """
    passports: dict[str, Any] = {}

    target: Path | None = None
    if passports_path:
        p = Path(passports_path)
        if p.exists():
            target = p

    if not target:
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
                if as_specs:
                    spec = ServerPackageSpec.from_dict(data)
                    passports[spec.package_name] = spec
                else:
                    pkg = data.get("package_name")
                    if pkg:
                        passports[pkg] = data
            except Exception as exc:
                logger.debug("Failed to read passport %s: %s", j_file, exc)
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
                                if as_specs:
                                    spec = ServerPackageSpec.from_dict(v)
                                    passports[spec.package_name] = spec
                                else:
                                    pkg = str(v.get("package_name") or k)
                                    passports[pkg] = v
                    elif isinstance(data, list):
                        for v in data:
                            if isinstance(v, dict):
                                if as_specs:
                                    spec = ServerPackageSpec.from_dict(v)
                                    passports[spec.package_name] = spec
                                else:
                                    pkg = v.get("package_name")
                                    if pkg:
                                        passports[pkg] = v
                elif isinstance(data, list):
                    for v in data:
                        if isinstance(v, dict):
                            if as_specs:
                                spec = ServerPackageSpec.from_dict(v)
                                passports[spec.package_name] = spec
                            else:
                                pkg = v.get("package_name")
                                if pkg:
                                    passports[pkg] = v
        except Exception as exc:
            logger.warning("Failed to load passports from %s: %s", target, exc)

    return passports


def _load_passports(passports_path: str | Path | None = None) -> dict[str, ServerPackageSpec]:
    """Helper to load ServerPackageSpecs from gz, json, or directory."""
    return load_passport_data(passports_path=passports_path, as_specs=True)


def evaluate_passport_security(
    spec: ServerPackageSpec | dict[str, Any],
    matcher: VulnerabilityMatcher | None = None,
    candidate_advs: list[dict[str, Any]] | None = None,
    raw_spec: dict[str, Any] | ServerPackageSpec | None = None,
    malicious_sync: Any = None,
) -> UnifiedMcpSecurityRecord:
    """Evaluate security profile and version-specific vulnerabilities for an MCP server passport.

    Correlates passport version fingerprints against OSV vulnerability advisories,
    performs static tool capability and risk assessments, sorts releases, computes
    per-version remediation targets (upgrade commands or no-fix flags), and builds
    a comprehensive UnifiedMcpSecurityRecord.

    Args:
        spec: ServerPackageSpec instance or raw passport dictionary.
        matcher: Optional VulnerabilityMatcher for version range matching and advisory lookups.
        candidate_advs: Optional pre-filtered list of advisory dictionaries for the package.
        raw_spec: Optional raw dictionary or spec for extra metadata (unpublished, archival, etc.).
        malicious_sync: Optional threat intel sync service for OpenSSF malicious package lookup.

    Returns:
        UnifiedMcpSecurityRecord populated with version assessments, risk profile, and metadata.
    """
    if isinstance(spec, dict):
        spec_obj = ServerPackageSpec.from_dict(spec)
        if raw_spec is None:
            raw_spec = spec
    else:
        spec_obj = spec
        if raw_spec is None:
            raw_spec = spec

    norm_name = VulnerabilityMatcher._normalize_package_name(spec_obj.package_name)
    if candidate_advs is None:
        if matcher is not None:
            candidate_advs = matcher._package_index.get(norm_name, [])
        else:
            candidate_advs = []

    version_records: list[VersionSecurityRecord] = []
    all_tools_for_scoring: list[dict[str, Any]] = []

    for vf in spec_obj.versions:
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
                if eco and spec_obj.ecosystem:
                    spec_eco = spec_obj.ecosystem.lower()
                    if eco != spec_eco:
                        if eco == "pypi" and spec_eco in ("pypi", "pip") or eco == "golang" and spec_eco in ("go", "golang"):
                            pass
                        else:
                            continue

                ranges = affected.get("ranges", [])
                versions = affected.get("versions", [])
                in_range = False
                if matcher is not None:
                    in_range = matcher._is_version_in_ranges(ver_str, ranges, versions)
                else:
                    in_range = is_version_in_ranges(ver_str, ranges=ranges, versions=versions)

                if in_range:
                    is_vuln = True
                    try:
                        matching_advs.append(OsvVulnerability.from_dict(adv_dict))
                    except Exception:
                        pass

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
            connections=getattr(vf, "connections", []),
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
                    spec_obj.ecosystem,
                    spec_obj.package_name,
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
        package_name=spec_obj.package_name,
        profile=profile,
        vuln_versions_count=vuln_count,
        safe_versions_count=safe_count,
    )

    is_unpublished = (
        raw_spec.get("is_unpublished", False)
        if isinstance(raw_spec, dict)
        else getattr(raw_spec, "is_unpublished", False)
    )
    repo_http_status = (
        raw_spec.get("repo_http_status", 200)
        if isinstance(raw_spec, dict)
        else getattr(raw_spec, "repo_http_status", 200)
    )
    archival_reason = (
        raw_spec.get("archival_reason")
        if isinstance(raw_spec, dict)
        else getattr(raw_spec, "archival_reason", None)
    )
    transport = (
        raw_spec.get("transport", getattr(spec_obj, "transport", "stdio"))
        if isinstance(raw_spec, dict)
        else getattr(raw_spec, "transport", getattr(spec_obj, "transport", "stdio"))
    )

    latest_v_record = None
    if version_records:
        for r in reversed(version_records):
            if r.tools or r.required_env_vars:
                latest_v_record = r
                break
        if not latest_v_record:
            latest_v_record = version_records[-1]

    prompts_count = len(latest_v_record.prompts) if latest_v_record else 0
    resources_count = len(latest_v_record.resources) if latest_v_record else 0
    toolset_canonical_hash = (
        latest_v_record.toolset_canonical_hash if latest_v_record else None
    )
    required_env_vars = (
        latest_v_record.required_env_vars if latest_v_record else ()
    )

    # OpenSSF Malicious Check
    malicious_record = (
        malicious_sync.get_malicious_record(spec_obj.ecosystem, spec_obj.package_name)
        if malicious_sync
        else None
    )

    is_malicious = False
    quarantine_tier = None
    malicious_advisory_id = None
    comp_risk_score = None

    if malicious_record:
        is_malicious = True
        quarantine_tier = "MALICIOUS"
        malicious_advisory_id = malicious_record.id
        comp_risk_score = 10.0
        sec_summary = f"MALICIOUS PACKAGE DETECTED: {malicious_record.id} - {malicious_record.summary}"
        overall_vuln = True

    # Dual Axis Security if present in raw_spec
    dual_axis_sec = None
    da_raw = (
        raw_spec.get("dual_axis_security")
        if isinstance(raw_spec, dict)
        else getattr(raw_spec, "dual_axis_security", None)
    )
    if isinstance(da_raw, dict):
        try:
            dual_axis_sec = DualAxisSecurityAssessment.from_dict(da_raw)
        except Exception:
            pass
    elif isinstance(da_raw, DualAxisSecurityAssessment):
        dual_axis_sec = da_raw

    record = UnifiedMcpSecurityRecord(
        package_name=spec_obj.package_name,
        ecosystem=spec_obj.ecosystem,
        purl=spec_obj.purl,
        display_name=spec_obj.display_name or spec_obj.package_name,
        description=spec_obj.description,
        author=spec_obj.author,
        repository_url=spec_obj.repository_url,
        homepage_url=spec_obj.homepage_url,
        license=spec_obj.license,
        latest_version=latest_version,
        recommended_safe_version=recommended_safe_version,
        is_vulnerable=overall_vuln,
        security_summary=sec_summary,
        static_risk_score=float(profile.get("overall_risk_score", 0.0)),
        static_risk_tier=profile.get("risk_tier", "LOW"),
        is_unpublished=is_unpublished,
        repo_http_status=repo_http_status,
        archival_reason=archival_reason,
        transport=transport,
        prompts_count=prompts_count,
        resources_count=resources_count,
        toolset_canonical_hash=toolset_canonical_hash,
        required_env_vars=required_env_vars,
        versions=version_records,
        is_malicious=is_malicious,
        quarantine_tier=quarantine_tier,
        malicious_advisory_id=malicious_advisory_id,
        composite_risk_score=comp_risk_score,
        dual_axis_security=dual_axis_sec,
    )
    return record


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
        record = evaluate_passport_security(
            spec=spec,
            matcher=matcher,
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
                            matching_advs.append(adv_dict)  # type: ignore[arg-type]

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
    "evaluate_passport_security",
    "load_passport_data",
    "normalize_version",
    "prune_catalog",
]


def prune_catalog(catalog_data: dict, catalog_state: 'McpCatalogState') -> dict:
    """Removes tombstoned and archived servers from the catalog dictionary."""
    if not catalog_data or "servers" not in catalog_data:
        return catalog_data

    servers = catalog_data["servers"]
    pruned_servers = {}

    for key, server in servers.items():
        eco = server.get("ecosystem")
        name = server.get("name")
        if not eco or not name:
            pruned_servers[key] = server
            continue

        canonical_key = catalog_state.package_key(eco, name)

        # Check tombstones
        if canonical_key in catalog_state.tombstones:
            tombstone = catalog_state.tombstones[canonical_key]
            # Log pruning for info
            logger.info("Pruning %s from catalog: %s", key, tombstone.reason)
            continue

        pruned_servers[key] = server

    pruned_data = catalog_data.copy()
    pruned_data["servers"] = pruned_servers
    pruned_data["total_servers"] = len(pruned_servers)
    return pruned_data

