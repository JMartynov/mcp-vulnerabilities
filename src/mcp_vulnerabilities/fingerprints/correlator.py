import gzip
import json
from pathlib import Path

from packaging.version import Version

from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher
from mcp_vulnerabilities.fingerprints.models import (
    CorrelatedTimeline,
    ServerPackageSpec,
    VersionVulnerabilityState,
)
from mcp_vulnerabilities.models import OsvVulnerability


class VulnerabilityCorrelator:
    def __init__(self, matcher: VulnerabilityMatcher, passports: dict[str, ServerPackageSpec]):
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

    def correlate_package(self, package_name: str) -> CorrelatedTimeline | None:
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
                    if eco and package_spec.ecosystem:
                        spec_eco = package_spec.ecosystem.lower()
                        if eco != spec_eco:
                            if eco == "pypi" and spec_eco in ("pypi", "pip", "python") or eco in ("go", "golang") and spec_eco in ("go", "golang") or eco in ("cargo", "crates.io", "rust") and spec_eco in ("cargo", "crates.io", "rust") or eco in ("maven", "java") and spec_eco in ("maven", "java") or eco in ("docker", "containers") and spec_eco in ("docker", "containers") or eco in ("npm", "javascript") and spec_eco in ("npm", "javascript"):
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
                matching_advisories=matching_advisories
            ))
        
        # Sort timeline by version
        def sort_key(state: VersionVulnerabilityState):
            try:
                return VulnerabilityMatcher._parse_version(state.version)
            except Exception:
                return Version("0.0.0")

        timeline.sort(key=sort_key)

        recommended_safe_version: str | None = None
        no_fix_available = False

        if any(item.is_vulnerable for item in timeline):
            # Find safe versions that are greater than the latest vulnerable version?
            # Actually, to compute recommended_safe_version for the package overall,
            # we just find the highest safe version, or the lowest safe version that is > highest vulnerable version.
            # But wait, a specific current version might be checked. Let's just provide the latest safe version.
            # Or perhaps, find if there are ANY safe versions.
            safe_versions = [item for item in timeline if not item.is_vulnerable]
            if not safe_versions:
                no_fix_available = True
            else:
                # Get the highest safe version as the recommended one for the package overall
                recommended_safe_version = safe_versions[-1].version

        return CorrelatedTimeline(
            package_name=package_spec.package_name,
            timeline=timeline,
            package_spec=package_spec,
            recommended_safe_version=recommended_safe_version,
            no_fix_available=no_fix_available
        )
        
    def generate_remediation_command(self, ecosystem: str, package: str, safe_version: str) -> str | None:
        """Generates an ecosystem-specific remediation upgrade command."""
        from mcp_vulnerabilities.catalog import generate_upgrade_command
        return generate_upgrade_command(ecosystem, package, safe_version)

    def correlate_all(self) -> list[CorrelatedTimeline]:
        """Correlates vulnerabilities for all packages in the passports."""
        results = []
        for key, spec in self.passports.items():
            timeline = self.correlate_package(spec.package_name)
            if timeline:
                results.append(timeline)
        return results

