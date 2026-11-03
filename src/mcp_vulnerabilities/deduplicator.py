from collections.abc import Iterable
from mcp_vulnerabilities.models import OsvVulnerability
from mcp_vulnerabilities.dedup.fusion import AdvisoryFusionEngine

class OsvDeduplicator:
    """Deduplicates and merges vulnerability entries across heterogeneous upstream sources."""

    @classmethod
    def deduplicate_and_merge(
        cls, vulnerabilities: Iterable[OsvVulnerability]
    ) -> list[OsvVulnerability]:
        """Group and merge overlapping vulnerability records using Disjoint-Set Union."""
        engine = AdvisoryFusionEngine()
        return engine.fuse_all(vulnerabilities)

