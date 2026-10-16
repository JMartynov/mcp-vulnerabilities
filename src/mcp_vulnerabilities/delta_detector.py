"""Automated sync delta detector for substantive security data updates."""

from __future__ import annotations

from typing import Dict, Sequence

from .models import OsvVulnerability


class DeltaDetector:
    """
    Evaluates new advisories, version changes, and severity updates.
    """

    @staticmethod
    def _hash_affected_ranges(vuln: OsvVulnerability) -> str:
        """Create a simple hash or canonical string of affected packages and ranges."""
        parts = []
        for affected in vuln.affected:
            pkg_id = f"{affected.package.ecosystem}:{affected.package.name}"
            ranges = []
            for r in affected.ranges:
                events = []
                for ev in r.events:
                    events.append(f"i:{ev.introduced},f:{ev.fixed},l:{ev.last_affected},lim:{ev.limit}")
                ranges.append(f"type:{r.type.value},events:[{','.join(events)}]")
            parts.append(f"{pkg_id}=[{';'.join(ranges)}]")
        return "|".join(parts)

    @staticmethod
    def _hash_severities(vuln: OsvVulnerability) -> str:
        """Create a canonical string of severities."""
        parts = []
        for s in vuln.severity:
            parts.append(f"{s.type.value}:{s.score}")
        return "|".join(parts)

    def evaluate_deltas(
        self,
        old_data: Sequence[OsvVulnerability],
        new_data: Sequence[OsvVulnerability],
    ) -> bool:
        """
        Returns True if substantive security data updates exist.
        Substantive updates include:
        1. New CVE/GHSA advisories.
        2. Newly vulnerable package versions (range changes).
        3. Updated risk assessments (severity updates).
        """
        old_map: Dict[str, OsvVulnerability] = {v.id: v for v in old_data}
        new_map: Dict[str, OsvVulnerability] = {v.id: v for v in new_data}

        # 1. New advisories
        new_ids = set(new_map.keys()) - set(old_map.keys())
        if new_ids:
            return True

        # 2 & 3. Changed range or severity for existing advisories
        for v_id, new_v in new_map.items():
            if v_id in old_map:
                old_v = old_map[v_id]

                # Check ranges
                if self._hash_affected_ranges(old_v) != self._hash_affected_ranges(new_v):
                    return True

                # Check severities
                if self._hash_severities(old_v) != self._hash_severities(new_v):
                    return True

        return False


__all__ = ["DeltaDetector"]
