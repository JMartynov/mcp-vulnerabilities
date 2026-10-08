"""Unit tests for OSV validator, deduplicator, and pipeline execution."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from mcp_vulnerabilities.deduplicator import OsvDeduplicator
from mcp_vulnerabilities.models import (
    AffectedPackage,
    DatabaseSpecificMcp,
    EventSpec,
    OsvVulnerability,
    PackageSpec,
    RangeSpec,
    RangeType,
    ReferenceSpec,
)
from mcp_vulnerabilities.pipeline import McpVulnerabilityPipeline
from mcp_vulnerabilities.validator import OsvValidationError, OsvValidator

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "osv"


def test_validator_rejects_missing_fields() -> None:
    # Missing details
    vuln = OsvVulnerability(
        id="MCP-TEST-001",
        summary="Test summary",
        details="Test details",
        affected=(),  # no affected package
    )
    errors = OsvValidator.validate(vuln)
    assert any("affected" in e for e in errors)

    with pytest.raises(OsvValidationError):
        OsvValidator.assert_valid(vuln)


def test_validator_validates_clean_record() -> None:
    vuln = OsvVulnerability(
        id="MCP-2025-0001",
        summary="Valid summary",
        details="Valid details",
        published="2026-01-01T00:00:00Z",
        modified="2026-01-01T00:00:00Z",
        affected=(
            AffectedPackage(
                package=PackageSpec(name="mcp-test", ecosystem="PyPI", purl="pkg:pypi/mcp-test"),
                ranges=(
                    RangeSpec(
                        type=RangeType.SEMVER,
                        events=(EventSpec(introduced="0.1.0"), EventSpec(fixed="0.2.0")),
                    ),
                ),
                database_specific=DatabaseSpecificMcp(
                    cvss_score=7.5,
                    epss_score=0.05,
                ),
            ),
        ),
    )
    errors = OsvValidator.validate(vuln)
    assert errors == []
    OsvValidator.assert_valid(vuln)


def test_deduplicator_merges_overlapping_records() -> None:
    # Record 1: from NVD (has CVE ID and CVSS score)
    rec1 = OsvVulnerability(
        id="CVE-2025-6514",
        summary="mcp-remote RCE",
        details="NVD details",
        aliases=("GHSA-6xpm-ggf7-wc3p",),
        affected=(
            AffectedPackage(
                package=PackageSpec(name="mcp-remote", ecosystem="npm", purl="pkg:npm/mcp-remote"),
                ranges=(
                    RangeSpec(
                        type=RangeType.SEMVER,
                        events=(EventSpec(introduced="0.0.5"), EventSpec(fixed="0.1.16")),
                    ),
                ),
                database_specific=DatabaseSpecificMcp(cvss_score=9.6, cwe_ids=("CWE-78",)),
            ),
        ),
        references=(ReferenceSpec(url="https://nvd.nist.gov/vuln/detail/CVE-2025-6514"),),
    )

    # Record 2: from GHSA (has GHSA ID, remediation, vulnerable tools)
    rec2 = OsvVulnerability(
        id="GHSA-6xpm-ggf7-wc3p",
        summary="mcp-remote command injection in authorization_endpoint",
        details="GHSA details with longer writeup on authorization_endpoint",
        aliases=("CVE-2025-6514",),
        affected=(
            AffectedPackage(
                package=PackageSpec(name="mcp-remote", ecosystem="npm", purl="pkg:npm/mcp-remote"),
                ranges=(
                    RangeSpec(
                        type=RangeType.SEMVER,
                        events=(EventSpec(introduced="0.0.5"), EventSpec(fixed="0.1.16")),
                    ),
                ),
                database_specific=DatabaseSpecificMcp(
                    vulnerable_tools=("connect",),
                    severity="CRITICAL",
                    remediation_guidance="Upgrade to 0.1.16",
                ),
            ),
        ),
        references=(ReferenceSpec(url="https://github.com/advisories/GHSA-6xpm-ggf7-wc3p"),),
    )

    merged = OsvDeduplicator.deduplicate_and_merge([rec1, rec2])
    assert len(merged) == 1
    m = merged[0]

    assert m.id == "CVE-2025-6514"
    assert "GHSA-6xpm-ggf7-wc3p" in m.aliases
    assert len(m.affected) == 1
    aff = m.affected[0]
    assert aff.database_specific.cvss_score == pytest.approx(9.6)
    assert aff.database_specific.severity == "CRITICAL"
    assert "CWE-78" in aff.database_specific.cwe_ids
    assert "connect" in aff.database_specific.vulnerable_tools
    assert aff.database_specific.remediation_guidance == "Upgrade to 0.1.16"
    assert len(m.references) == 2


def test_pipeline_execution_with_fixtures_and_catalog() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        pipeline = McpVulnerabilityPipeline(output_dir=tmpdir)
        res = pipeline.run(
            include_markdown_dirs=[FIXTURES_DIR / "markdown"],
            include_ghsa_api=False,
            include_osv_api=False,
            include_verity_catalog=True,
            offline_fallback_fixtures=FIXTURES_DIR,
        )

        assert res.collected_count >= 6
        assert res.emitted_count >= 6
        assert len(res.errors) == 0

        out_path = Path(tmpdir)
        index_file = out_path / "index.json"
        assert index_file.is_file()

        index_data = json.loads(index_file.read_text(encoding="utf-8"))
        assert index_data["count"] == res.emitted_count
        assert len(index_data["vulnerabilities"]) == res.emitted_count

        # Check that CVE-2025-10193.json was written and is valid JSON
        cve_file = out_path / "CVE-2025-10193.json"
        assert cve_file.is_file()
        cve_data = json.loads(cve_file.read_text(encoding="utf-8"))
        assert cve_data["id"] == "CVE-2025-10193"
        assert cve_data["affected"][0]["package"]["name"] == "mcp-neo4j-cypher"


def test_pipeline_cvelistv5_checkpoint_resumption() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "vulns"
        state_file = Path(tmpdir) / "sync_state.json"
        cve5_dir = FIXTURES_DIR / "cve_json5"

        pipeline = McpVulnerabilityPipeline(output_dir=out_path, state_file=state_file)

        # Run 1: Initial full ingestion
        res1 = pipeline.run(
            include_cvelistv5_dirs=[cve5_dir],
            include_verity_catalog=False,
        )
        assert res1.collected_count == 2  # Neo4j & mcp-remote (irrelevant calculator filtered out)
        assert "CVE-2025-10193" in res1.emitted_ids
        assert "CVE-2025-6514" in res1.emitted_ids
        assert state_file.is_file()

        # Verify state file content
        state_data = json.loads(state_file.read_text(encoding="utf-8"))
        assert "cvelist_v5" in state_data["sources"]
        assert state_data["sources"]["cvelist_v5"]["records_synced"] == 2

        # Run 2: Incremental resumption (no new files added)
        res2 = pipeline.run(
            include_cvelistv5_dirs=[cve5_dir],
            include_verity_catalog=False,
        )
        # Checkpoint skipped all previously processed files, but historical records are pre-loaded
        assert res2.collected_count == 2

        # Run 3: Reset state
        res3 = pipeline.run(
            include_cvelistv5_dirs=[cve5_dir],
            include_verity_catalog=False,
            reset_checkpoints=True,
        )
        assert res3.collected_count == 2

import urllib.request
from unittest.mock import patch, MagicMock

@patch("urllib.request.urlopen")
def test_pipeline_ghsa_api_pagination(mock_urlopen: MagicMock) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "vulns"
        state_file = Path(tmpdir) / "sync_state.json"

        pipeline = McpVulnerabilityPipeline(output_dir=out_path, state_file=state_file)
        pipeline.state_manager.update_checkpoint("ghsa_api", last_updated_at="2024-01-01T00:00:00Z")

        # Mock two pages of GHSA API
        page1_data = [{"id": "GHSA-1", "updated_at": "2024-01-02T00:00:00Z", "summary": "Test 1", "vulnerabilities": [{"package": {"name": "mcp-remote"}}]}]
        page2_data = [{"id": "GHSA-2", "updated_at": "2024-01-03T00:00:00Z", "summary": "Test 2", "vulnerabilities": [{"package": {"name": "mcp-remote"}}]}]

        mock_resp1 = MagicMock()
        mock_resp1.read.return_value = json.dumps(page1_data).encode("utf-8")
        mock_resp1.headers = {"Link": '<https://api.github.com/advisories?since=2024-01-01T00:00:00Z&page=2>; rel="next"'}
        
        mock_resp2 = MagicMock()
        mock_resp2.read.return_value = json.dumps(page2_data).encode("utf-8")
        mock_resp2.headers = {}

        mock_urlopen.side_effect = [
            MagicMock(__enter__=lambda self: mock_resp1, __exit__=lambda *args: None),
            MagicMock(__enter__=lambda self: mock_resp2, __exit__=lambda *args: None),
        ]

        res = pipeline.run(include_ghsa_api=True, include_verity_catalog=False)
        assert res.collected_count == 2
        
        # Checkpoint is updated to newest date
        chk = pipeline.state_manager.get_checkpoint("ghsa_api")
        assert chk.last_updated_at == "2024-01-03T00:00:00Z"
        assert mock_urlopen.call_count == 2

@patch("urllib.request.urlopen")
def test_pipeline_cvelist_delta_traversal(mock_urlopen: MagicMock) -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "vulns"
        state_file = Path(tmpdir) / "sync_state.json"

        pipeline = McpVulnerabilityPipeline(output_dir=out_path, state_file=state_file)
        pipeline.state_manager.update_checkpoint("cvelist_delta", last_marker="sha-old")

        commits_data = [
            {"sha": "sha-new"},
            {"sha": "sha-mid"},
            {"sha": "sha-old"}, # Should stop here
            {"sha": "sha-older"},
        ]

        mock_commits = MagicMock()
        mock_commits.read.return_value = json.dumps(commits_data).encode("utf-8")
        mock_commits.headers = {}
        
        mock_detail_new = MagicMock()
        mock_detail_new.read.return_value = json.dumps({"files": []}).encode("utf-8")
        mock_detail_new.headers = {}
        
        mock_detail_mid = MagicMock()
        mock_detail_mid.read.return_value = json.dumps({"files": []}).encode("utf-8")
        mock_detail_mid.headers = {}

        mock_urlopen.side_effect = [
            MagicMock(__enter__=lambda self: mock_commits, __exit__=lambda *args: None),
            MagicMock(__enter__=lambda self: mock_detail_new, __exit__=lambda *args: None),
            MagicMock(__enter__=lambda self: mock_detail_mid, __exit__=lambda *args: None),
        ]

        res = pipeline.run(include_cvelist_delta=True, include_verity_catalog=False)
        
        chk = pipeline.state_manager.get_checkpoint("cvelist_delta")
        assert chk.last_marker == "sha-new"
        
        # 1 call for commits + 2 calls for details before hitting "sha-old"
        assert mock_urlopen.call_count == 3


def test_pipeline_incremental_sync_retains_history() -> None:
    with tempfile.TemporaryDirectory() as tmpdir:
        out_path = Path(tmpdir) / "vulns"
        state_file = Path(tmpdir) / "sync_state.json"

        pipeline = McpVulnerabilityPipeline(output_dir=out_path, state_file=state_file)

        # 1. Create a dummy initial vulnerability
        initial_vuln = OsvVulnerability(
            id="MCP-TEST-OLD",
            summary="Old Vuln",
            details="Details",
            published="2025-01-01T00:00:00Z",
            modified="2025-01-02T00:00:00Z",
            affected=(
                AffectedPackage(
                    package=PackageSpec(name="mcp-test", ecosystem="PyPI", purl="pkg:pypi/mcp-test"),
                    ranges=(
                        RangeSpec(
                            type=RangeType.SEMVER,
                            events=(EventSpec(introduced="0.1.0"), EventSpec(fixed="0.2.0")),
                        ),
                    ),
                    database_specific=DatabaseSpecificMcp(),
                ),
            ),
        )
        out_path.mkdir(parents=True, exist_ok=True)
        (out_path / "MCP-TEST-OLD.json").write_text(initial_vuln.to_json(), encoding="utf-8")
        
        index_data = {
            "version": "1.0.0",
            "count": 1,
            "vulnerabilities": [{"id": "MCP-TEST-OLD"}]
        }
        (out_path / "index.json").write_text(json.dumps(index_data), encoding="utf-8")

        # Create a new dummy cve json5 directory with 1 new item
        new_cve5_dir = Path(tmpdir) / "new_cves"
        new_cve5_dir.mkdir()
        
        new_cve_data = {
            "dataType": "CVE_RECORD",
            "dataVersion": "5.0",
            "cveMetadata": {
                "cveId": "CVE-2025-9999",
                "assignerOrgId": "abc",
                "state": "PUBLISHED"
            },
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "packageName": "mcp-test",
                            "product": "mcp-test",
                            "vendor": "Test",
                            "versions": [
                                {
                                    "status": "affected",
                                    "version": "1.0.0",
                                    "lessThan": "2.0.0",
                                    "versionType": "semver"
                                }
                            ]
                        }
                    ],
                    "descriptions": [{"lang": "en", "value": "A new test vulnerability"}],
                    "metrics": [
                        {
                            "cvssV3_1": {"baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
                        }
                    ]
                }
            }
        }
        (new_cve5_dir / "CVE-2025-9999.json").write_text(json.dumps(new_cve_data), encoding="utf-8")

        # 2. Run pipeline which should pick up the new item and retain the old one
        res = pipeline.run(
            include_cvelistv5_dirs=[new_cve5_dir],
            include_verity_catalog=False,
        )

        assert res.collected_count == 2
        assert "MCP-TEST-OLD" in res.emitted_ids
        assert "CVE-2025-9999" in res.emitted_ids
        
        index_file = out_path / "index.json"
        final_index = json.loads(index_file.read_text(encoding="utf-8"))
        assert final_index["count"] == 2
        
        vuln_ids = [v["id"] for v in final_index["vulnerabilities"]]
        assert "MCP-TEST-OLD" in vuln_ids
        assert "CVE-2025-9999" in vuln_ids

