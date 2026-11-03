import pytest
import sys
from unittest.mock import MagicMock

if 'mcp_fingerprints' not in sys.modules:
    try:
        import mcp_fingerprints
    except ImportError:
        sys.modules['mcp_fingerprints'] = MagicMock()
        sys.modules['mcp_fingerprints.config_scanner'] = MagicMock()
        sys.modules['mcp_fingerprints.models'] = MagicMock()

import itertools
import json
from collections.abc import Iterable
from mcp_vulnerabilities.graph import CanonicalAliasGraph
from mcp_vulnerabilities.dedup import AdvisoryFusionEngine, normalize_url
from mcp_vulnerabilities.deduplicator import OsvDeduplicator
from mcp_vulnerabilities.models import (
    OsvVulnerability,
    SeveritySpec,
    SeverityType,
    ReferenceSpec,
    ReferenceType,
    AffectedPackage,
    PackageSpec,
    RangeSpec,
    RangeType,
    EventSpec,
    DatabaseSpecificMcp
)

def test_alias_graph_connected_components():
    """INVARIANT_150_1: Overlapping alias pairs collapse into a single cluster."""
    graph = CanonicalAliasGraph()
    graph.add_alias("CVE-A", "GHSA-B")
    graph.add_alias("GHSA-B", "PYSEC-C")
    graph.add_alias("PYSEC-C", "GLAD-D")

    cluster = graph.get_cluster("CVE-A")
    assert "CVE-A" in cluster
    assert "GHSA-B" in cluster
    assert "PYSEC-C" in cluster
    assert "GLAD-D" in cluster

    assert len(graph.get_all_clusters()) == 1

def test_canonical_id_selection_hierarchy():
    """INVARIANT_150_2: Deterministic Canonical ID Selection."""
    # CVE-* over GHSA-* over MAL-* over PYSEC-* over GLAD-*
    assert CanonicalAliasGraph.get_canonical_id(["GHSA-123", "CVE-2024-1000", "PYSEC-1"]) == "CVE-2024-1000"

    # Lowest year/sequence among multiple CVEs
    assert CanonicalAliasGraph.get_canonical_id(["CVE-2024-2000", "CVE-2024-1000"]) == "CVE-2024-1000"
    assert CanonicalAliasGraph.get_canonical_id(["CVE-2023-9999", "CVE-2024-1000"]) == "CVE-2023-9999"

    # Fallbacks
    assert CanonicalAliasGraph.get_canonical_id(["PYSEC-1", "GHSA-1"]) == "GHSA-1"
    assert CanonicalAliasGraph.get_canonical_id(["MAL-1", "GHSA-1"]) == "GHSA-1"
    assert CanonicalAliasGraph.get_canonical_id(["GLAD-1", "PYSEC-1"]) == "PYSEC-1"

def create_mock_vuln(vid, aliases=None, cvss=None, ranges=None, urls=None, intel=None, summary="sum", details="det"):
    severity = []
    if cvss:
        severity.append(SeveritySpec(type=SeverityType.CVSS_V3, score=cvss))

    affected = []
    if ranges:
        for r_in in ranges:
             events = []
             if len(r_in) == 2:
                 intro, fixed = r_in
                 events.append(EventSpec(introduced=intro))
                 events.append(EventSpec(fixed=fixed))
             else:
                 intro, = r_in
                 events.append(EventSpec(introduced=intro))

             affected.append(
                 AffectedPackage(
                     package=PackageSpec(name="testpkg", ecosystem="pypi", purl="pkg:pypi/testpkg"),
                     ranges=(RangeSpec(type=RangeType.SEMVER, events=tuple(events)),),
                     versions=(),
                     database_specific=DatabaseSpecificMcp()
                 )
             )
    else:
        affected.append(AffectedPackage(package=PackageSpec(name="testpkg", ecosystem="pypi", purl="pkg:pypi/testpkg")))

    refs = []
    if urls:
        for u in urls:
             refs.append(ReferenceSpec(url=u, type=ReferenceType.WEB))

    db_spec = {}
    if intel:
        db_spec.update(intel)

    return OsvVulnerability(
        id=vid,
        summary=summary,
        details=details,
        aliases=tuple(aliases or []),
        severity=tuple(severity),
        affected=tuple(affected),
        references=tuple(refs),
        database_specific=db_spec
    )

def test_severity_conflict_resolution():
    """INVARIANT_150_X: Conflicting CVSS scores prioritizes NVD."""
    # Actually checking priority by source ID in our mock fusion
    v_nvd = create_mock_vuln("CVE-2024-1000", cvss="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    v_ghsa = create_mock_vuln("GHSA-1234-abcd", cvss="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", aliases=["CVE-2024-1000"])

    engine = AdvisoryFusionEngine()
    fused = engine.fuse_all([v_nvd, v_ghsa])

    assert len(fused) == 1
    # Authoritative is from NVD
    assert fused[0].severity[0].score == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    # Divergent tracked
    assert "divergent_severities" in fused[0].database_specific
    assert "GHSA-1234-abcd" in fused[0].database_specific["divergent_severities"]

def test_version_range_union():
    """INVARIANT_150_3: Fuses overlapping ranges into union."""
    v1 = create_mock_vuln("CVE-1", ranges=[("1.0.0", "1.2.0")])
    v2 = create_mock_vuln("GHSA-1", aliases=["CVE-1"], ranges=[("1.1.0", "1.3.0")])

    fused = AdvisoryFusionEngine().fuse_all([v1, v2])[0]
    merged_range = fused.affected[0].ranges[0]

    assert len(merged_range.events) == 2
    assert merged_range.events[0].introduced == "1.0.0"
    assert merged_range.events[1].fixed == "1.3.0"

def test_reference_url_deduplication():
    """INVARIANT_150_X: Deduplicates URLs with tracking parameters and trailing slashes."""
    v1 = create_mock_vuln("CVE-1", urls=["https://example.com/advisory/?utm_source=foo"])
    v2 = create_mock_vuln("GHSA-1", aliases=["CVE-1"], urls=["HTTPS://EXAMPLE.COM/advisory"])

    fused = AdvisoryFusionEngine().fuse_all([v1, v2])[0]
    assert len(fused.references) == 1
    assert fused.references[0].url == "https://example.com/advisory"

def test_threat_intel_inheritance():
    """INVARIANT_150_4: Asserts KEV flag on CVE-A is inherited when querying by GHSA-B."""
    v1 = create_mock_vuln("CVE-1", intel={"known_exploited": True})
    v2 = create_mock_vuln("GHSA-1", aliases=["CVE-1"])

    fused = AdvisoryFusionEngine().fuse_all([v1, v2])[0]
    assert fused.database_specific.get("known_exploited") is True

def test_permutation_invariance():
    """INVARIANT_150_5: Feeds identical datasets in 5 randomized orderings and asserts identical output JSON hashes."""
    v1 = create_mock_vuln("CVE-2024-1000", cvss="8.8", ranges=[("1.0.0", "1.2.0")], urls=["https://a.com"], intel={"known_exploited": True})
    v2 = create_mock_vuln("GHSA-1", aliases=["CVE-2024-1000"], cvss="7.5", ranges=[("1.1.0", "1.3.0")], urls=["https://b.com"])
    v3 = create_mock_vuln("PYSEC-1", aliases=["GHSA-1"], ranges=[("1.2.0", "1.4.0")], urls=["https://c.com"], intel={"epss_score": 0.95})

    perms = list(itertools.permutations([v1, v2, v3]))[:5]

    outputs = []
    engine = AdvisoryFusionEngine()

    for perm in perms:
         res = engine.fuse_all(perm)
         # Using JSON dump with sorting to guarantee determinism
         out_json = json.dumps([r.to_dict() for r in res], sort_keys=True)
         outputs.append(out_json)

    # All outputs must be identical
    for i in range(1, len(outputs)):
        assert outputs[0] == outputs[i], f"Permutation mismatch at index {i}"
