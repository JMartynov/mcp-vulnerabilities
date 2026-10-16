import json
import gzip
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from packaging.version import Version, InvalidVersion

from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher
from mcp_vulnerabilities.models import OsvVulnerability
from mcp_vulnerabilities.fingerprints.models import ServerPackageSpec, VersionFingerprint, VersionVulnerabilityState, CorrelatedTimeline

class VulnerabilityCorrelator:
    def __init__(self, matcher: VulnerabilityMatcher, passports: Dict[str, ServerPackageSpec]):
        self.matcher = matcher
        self.passports = passports

    @classmethod
    def from_paths(cls, vulnerabilities_path: Path, passports_path: Path) -> "VulnerabilityCorrelator":
        if vulnerabilities_path.is_dir():
            matcher = VulnerabilityMatcher.from_directory(vulnerabilities_path)
        else:
            matcher = VulnerabilityMatcher.from_snapshot(vulnerabilities_path)

        passports = {}
        if passports_path.exists():
            open_func = gzip.open if passports_path.name.endswith(".gz") else open
            with open_func(passports_path, "rt", encoding="utf-8") as f:
                data = json.load(f)
                for key, pkg_data in data.items():
                    passports[key] = ServerPackageSpec.from_dict(pkg_data)

        return cls(matcher=matcher, passports=passports)

    def correlate_package(self, package_name: str) -> Optional[CorrelatedTimeline]:
        """Correlates vulnerability advisories for all versions of a specific package."""
        package_spec = None
        # Try to find the package in passports
        for key, spec in self.passports.items():
            if spec.package_name == package_name or package_name in spec.to_dict().get("aliases", []):
                package_spec = spec
                break
        
        if not package_spec:
            return None

        timeline = []
        for v_fingerprint in package_spec.versions:
            version_str = v_fingerprint.version
            is_vulnerable = False
            matching_advisories = []

            # We need to find advisories for this package name and ecosystem
            # We can use the matcher's package index
            norm_name = VulnerabilityMatcher._normalize_package_name(package_spec.package_name)
            advisories = self.matcher._package_index.get(norm_name, [])

            for adv_dict in advisories:
                for affected in adv_dict.get("affected", []):
                    pkg = affected.get("package", {})
                    if VulnerabilityMatcher._normalize_package_name(pkg.get("name", "")) != norm_name:
                        continue
                    
                    eco = pkg.get("ecosystem", "").lower()
                    if eco and eco != package_spec.ecosystem.lower():
                        if eco == "pypi" and package_spec.ecosystem.lower() in ("pypi", "pip"):
                            pass
                        elif eco == "golang" and package_spec.ecosystem.lower() in ("go", "golang"):
                            pass
                        else:
                            continue

                    # Check if version is in ranges
                    ranges = affected.get("ranges", [])
                    versions = affected.get("versions", [])
                    if self.matcher._is_version_in_ranges(version_str, ranges, versions):
                        is_vulnerable = True
                        matching_advisories.append(OsvVulnerability.from_dict(adv_dict))
            
            timeline.append(VersionVulnerabilityState(
                version=version_str,
                is_vulnerable=is_vulnerable,
                advisories=matching_advisories
            ))
        
        # Sort timeline by version
        def sort_key(state: VersionVulnerabilityState):
            try:
                return VulnerabilityMatcher._parse_version(state.version)
            except Exception:
                return Version("0.0.0")

        timeline.sort(key=sort_key)

        return CorrelatedTimeline(
            package_name=package_spec.package_name,
            ecosystem=package_spec.ecosystem,
            timeline=timeline
        )

    def correlate_all(self) -> List[CorrelatedTimeline]:
        """Correlates vulnerabilities for all packages in the passports."""
        results = []
        for key, spec in self.passports.items():
            timeline = self.correlate_package(spec.package_name)
            if timeline:
                results.append(timeline)
        return results

