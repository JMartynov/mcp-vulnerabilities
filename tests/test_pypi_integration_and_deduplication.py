"""Unit and acceptance tests for Task 50: PyPI Integration, Caching Loader & Deduplication."""

import gzip
import json
import pytest
from pathlib import Path


from mcp_vulnerabilities.fingerprints.models import (
    ServerPackageSpec,
    VersionFingerprint,
    ToolContractSignature,
    ParameterMetadata,
    FingerprintMatchResult,
    VersionVulnerabilityState,
    CorrelatedTimeline,
)
import mcp_fingerprints.models as mf_models
import mcp_vulnerabilities.fingerprints.canonicalizer as vuln_canon
import mcp_fingerprints.canonicalizer as mf_canon
from mcp_vulnerabilities.fingerprints.matcher import FingerprintMatcher


def test_model_identity_parity():
    """Verify that models are identical to canonical mcp_fingerprints classes."""
    assert ServerPackageSpec is mf_models.ServerPackageSpec
    assert VersionFingerprint is mf_models.VersionFingerprint
    assert ToolContractSignature is mf_models.ToolContractSignature
    assert ParameterMetadata is mf_models.ParameterMetadata


def test_canonicalizer_hash_parity():
    """Verify that canonicalizer utilities produce bit-for-bit identical hashes."""
    tools = [
        {
            "name": "search",
            "description": "Search index",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer"},
                },
                "required": ["query"],
            },
        }
    ]
    hash_vuln = vuln_canon.compute_toolset_canonical_hash(tools)
    hash_mf = mf_canon.compute_toolset_canonical_hash(tools)
    assert hash_vuln == hash_mf
    assert hash_vuln.startswith("sha256:")


def test_matcher_loads_passports():
    """Verify that FingerprintMatcher initializes and loads passports without errors."""
    matcher = FingerprintMatcher()
    assert len(matcher.packages) > 0 or len(matcher.by_toolset_hash) > 0


def test_version_vulnerability_extensions():
    """Verify that vulnerability-specific extensions remain fully functional."""
    state = VersionVulnerabilityState(
        version="1.0.0",
        is_vulnerable=True,
        matching_advisories=[],
    )
    d = state.to_dict()
    assert d["version"] == "1.0.0"
    assert d["is_vulnerable"] is True

    timeline = CorrelatedTimeline(
        package_name="test-pkg",
        timeline=[state],
    )
    td = timeline.to_dict()
    assert td["package_name"] == "test-pkg"
    assert len(td["timeline"]) == 1
