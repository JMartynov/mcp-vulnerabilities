"""Data models for MCP Structural Fingerprints, Passports, and Version Correlated Timelines."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Literal, Optional, Tuple

from mcp_fingerprints.models import (
    ParameterMetadata,
    ResourceSignature,
    ToolContractSignature,
    PromptSignature,
    VersionFingerprint,
    ServerPackageSpec,
    TransportType,
)
from mcp_vulnerabilities.models import OsvVulnerability


@dataclass
class FingerprintMatchResult:
    package_name: str
    ecosystem: str
    version: str
    repository_url: Optional[str] = None
    confidence_score: float = 0.0
    match_type: str = "toolset_exact"
    matched_tools_count: int = 0
    total_tools_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "ecosystem": self.ecosystem,
            "version": self.version,
            "repository_url": self.repository_url,
            "confidence_score": self.confidence_score,
            "match_type": self.match_type,
            "matched_tools_count": self.matched_tools_count,
            "total_tools_count": self.total_tools_count,
        }


@dataclass
class VersionVulnerabilityState:
    version: str
    is_vulnerable: bool
    matching_advisories: List[OsvVulnerability] = field(default_factory=list)
    toolset_canonical_hash: Optional[str] = None
    fingerprint: Optional[VersionFingerprint] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "is_vulnerable": self.is_vulnerable,
            "matching_advisories": [adv.to_dict() if hasattr(adv, "to_dict") else adv for adv in self.matching_advisories],
            "toolset_canonical_hash": self.toolset_canonical_hash,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> VersionVulnerabilityState:
        advisories_raw = data.get("matching_advisories", [])
        advisories = []
        for adv in advisories_raw:
            if isinstance(adv, dict):
                advisories.append(OsvVulnerability.from_dict(adv))
            else:
                advisories.append(adv)
        fp_data = data.get("fingerprint")
        fingerprint = VersionFingerprint.from_dict(fp_data) if fp_data else None
        return cls(
            version=str(data.get("version", "")),
            is_vulnerable=bool(data.get("is_vulnerable", False)),
            matching_advisories=advisories,
            toolset_canonical_hash=data.get("toolset_canonical_hash"),
            fingerprint=fingerprint,
        )


@dataclass
class CorrelatedTimeline:
    package_name: str
    timeline: List[VersionVulnerabilityState] = field(default_factory=list)
    package_spec: Optional[ServerPackageSpec] = None
    recommended_safe_version: Optional[str] = None
    no_fix_available: bool = False

    def get_remediation_for_version(self, current_version: str) -> Tuple[Optional[str], bool]:
        """
        Returns (recommended_safe_version, no_fix_available) for a specific current version,
        ensuring monotonic upgrade (safe_version > current_version).
        """
        from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher
        
        try:
            curr_v = VulnerabilityMatcher._parse_version(current_version)
        except Exception:
            return self.recommended_safe_version, self.no_fix_available

        # Find all safe versions strictly greater than current_version
        safe_candidates = []
        for state in self.timeline:
            if not state.is_vulnerable:
                try:
                    if VulnerabilityMatcher._parse_version(state.version) > curr_v:
                        safe_candidates.append(state)
                except Exception:
                    continue

        if not safe_candidates:
            # Check if it's currently vulnerable
            current_state = next((s for s in self.timeline if s.version == current_version), None)
            is_currently_vulnerable = current_state.is_vulnerable if current_state else True
            if is_currently_vulnerable:
                return None, True
            else:
                return None, False

        # Return the lowest safe version that is > current_version
        safe_candidates.sort(key=lambda s: VulnerabilityMatcher._parse_version(s.version))
        return safe_candidates[0].version, False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "package_name": self.package_name,
            "timeline": [item.to_dict() for item in self.timeline],
            "package_spec": self.package_spec.to_dict() if self.package_spec else None,
            "recommended_safe_version": self.recommended_safe_version,
            "no_fix_available": self.no_fix_available,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CorrelatedTimeline:
        timeline_raw = data.get("timeline", [])
        timeline = [VersionVulnerabilityState.from_dict(item) for item in timeline_raw if isinstance(item, dict)]
        spec_data = data.get("package_spec")
        package_spec = ServerPackageSpec.from_dict(spec_data) if spec_data else None
        return cls(
            package_name=str(data.get("package_name", "")),
            timeline=timeline,
            package_spec=package_spec,
            recommended_safe_version=data.get("recommended_safe_version"),
            no_fix_available=bool(data.get("no_fix_available", False)),
        )


__all__ = [
    "ParameterMetadata",
    "ResourceSignature",
    "ToolContractSignature",
    "PromptSignature",
    "VersionFingerprint",
    "ServerPackageSpec",
    "FingerprintMatchResult",
    "TransportType",
    "VersionVulnerabilityState",
    "CorrelatedTimeline",
]
