"""Unit tests for Phase 2 extracted shared helpers:

1. infer_vulnerable_tools (converters.common)
2. extract_advisory_severity (cvss)
3. is_version_affected / is_version_in_ranges (cvss and pipeline) with discontinuous range evaluation
"""

from __future__ import annotations

import pytest
from packaging.version import Version

from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher
from mcp_vulnerabilities.converters.common import (
    _infer_vulnerable_tools,
    infer_vulnerable_tools,
)
from mcp_vulnerabilities.converters.ghsa import GhsaConverter
from mcp_vulnerabilities.converters.markdown_cve import MarkdownAdvisoryConverter
from mcp_vulnerabilities.converters.osv_dev import OsvDevConverter
from mcp_vulnerabilities.cvss import (
    _extract_severity_info,
    extract_advisory_severity,
    is_version_in_ranges,
    parse_version_lenient,
)
from mcp_vulnerabilities.cvss import (
    is_version_affected as cvss_is_version_affected,
)
from mcp_vulnerabilities.feed import AdvisoryFeedBuilder
from mcp_vulnerabilities.models import EventSpec, RangeSpec, RangeType
from mcp_vulnerabilities.pipeline import is_version_affected
from mcp_vulnerabilities.transitive import TransitiveDependencyAuditor


class TestConverterToolInference:
    """Test suite for infer_vulnerable_tools."""

    def test_empty_or_none_text(self) -> None:
        assert infer_vulnerable_tools("") == []
        assert _infer_vulnerable_tools("") == []

    def test_backtick_keyword_extraction(self) -> None:
        text = "Vulnerability in `query_database` and `get_user_info` allows RCE. Also calls `non_matching_tool`."
        tools = infer_vulnerable_tools(text)
        assert tools == ["get_user_info", "query_database"]

    def test_deduplication_and_sorting(self) -> None:
        text = "Repeated mentions of `exec_cmd`, `exec_cmd`, and `fetch_record`."
        tools = infer_vulnerable_tools(text)
        assert tools == ["exec_cmd", "fetch_record"]

    def test_context_aware_fallback_cypher(self) -> None:
        text = "This MCP server executes cypher queries without sanitization."
        tools = infer_vulnerable_tools(text)
        assert tools == ["cypher_query"]

    def test_context_aware_fallback_git_init(self) -> None:
        text = "Improper repository handling during git_init operation."
        tools = infer_vulnerable_tools(text)
        assert tools == ["git_init"]

    def test_converter_classmethods_delegate_properly(self) -> None:
        text = "Issue in `delete_resource` endpoint."
        assert GhsaConverter._infer_vulnerable_tools(text) == ["delete_resource"]
        assert OsvDevConverter._infer_vulnerable_tools(text) == ["delete_resource"]
        assert MarkdownAdvisoryConverter._infer_vulnerable_tools(text) == ["delete_resource"]


class TestSeverityExtraction:
    """Test suite for extract_advisory_severity."""

    def test_cvss_v3_vector_scoring(self) -> None:
        adv = {
            "severity": [
                {"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
            ]
        }
        sev, score = extract_advisory_severity(adv)
        assert sev == "CRITICAL"
        assert score == pytest.approx(9.8)

    def test_nominal_severity_fallback_for_extended_vector(self) -> None:
        adv = {
            "severity": [
                {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/C:H/I:H/A:H"}
            ]
        }
        sev, score = extract_advisory_severity(adv)
        assert sev == "CRITICAL"
        assert score is None

    def test_numeric_float_score(self) -> None:
        adv = {
            "severity": [
                {"type": "CVSS_V3", "score": "7.5"}
            ]
        }
        sev, score = extract_advisory_severity(adv)
        assert sev == "HIGH"
        assert score == pytest.approx(7.5)

    def test_database_specific_severity_override(self) -> None:
        adv = {
            "database_specific": {"severity": "MODERATE"},
            "severity": [{"score": "7.5"}]
        }
        sev, score = extract_advisory_severity(adv)
        assert sev == "MODERATE"
        assert score == pytest.approx(7.5)

    def test_affected_package_override(self) -> None:
        adv = {
            "severity": []
        }
        affected = {
            "database_specific": {
                "severity": "LOW",
                "cvss_score": 3.1
            }
        }
        sev, score = extract_advisory_severity(adv, affected=affected)
        assert sev == "LOW"
        assert score == pytest.approx(3.1)

    def test_fallback_to_first_affected_item_when_affected_omitted(self) -> None:
        adv = {
            "affected": [
                {"database_specific": {"severity": "HIGH", "cvss_score": 8.0}}
            ]
        }
        sev, score = extract_advisory_severity(adv)
        assert sev == "HIGH"
        assert score == pytest.approx(8.0)

    def test_class_thin_aliases_pass(self) -> None:
        adv = {"severity": [{"score": "5.0"}]}
        assert VulnerabilityMatcher._extract_severity_info(adv) == ("MEDIUM", 5.0)
        assert AdvisoryFeedBuilder._extract_severity_info(adv) == ("MEDIUM", 5.0)
        assert TransitiveDependencyAuditor._extract_severity_info(adv) == ("MEDIUM", 5.0)
        assert _extract_severity_info(adv) == ("MEDIUM", 5.0)


class TestSemverRangeEvaluation:
    """Test suite for discontinuous ranges and interval reconstruction."""

    def test_discontinuous_semver_ranges_pipeline(self) -> None:
        """Verify that discontinuous ranges do NOT misclassify intermediate versions.

        Range: [1.0, 1.2) and [2.0, 2.2)
        Intermediate version 1.5 must be NOT affected (False).
        """
        ranges = (
            RangeSpec(
                type=RangeType.SEMVER,
                events=(
                    EventSpec(introduced="1.0"),
                    EventSpec(fixed="1.2"),
                    EventSpec(introduced="2.0"),
                    EventSpec(fixed="2.2"),
                ),
            ),
        )

        assert not is_version_affected("0.9", ranges)
        assert is_version_affected("1.0", ranges)
        assert is_version_affected("1.1", ranges)
        assert cvss_is_version_affected("1.1", ranges)
        assert not is_version_affected("1.2", ranges)

        # Critical test: intermediate version between intervals
        assert not is_version_affected("1.5", ranges)
        assert not is_version_affected("1.9.9", ranges)

        # Second interval
        assert is_version_affected("2.0", ranges)
        assert is_version_affected("2.1", ranges)
        assert not is_version_affected("2.2", ranges)
        assert not is_version_affected("2.5", ranges)

    def test_is_version_in_ranges_dict_format(self) -> None:
        """Verify matcher dict-format ranges with discontinuous intervals."""
        ranges = [
            {
                "type": "SEMVER",
                "events": [
                    {"introduced": "1.0.0"},
                    {"fixed": "1.2.0"},
                    {"introduced": "2.0.0"},
                    {"fixed": "2.2.0"},
                ],
            }
        ]

        assert not is_version_in_ranges("0.9.0", ranges)
        assert is_version_in_ranges("1.0.0", ranges)
        assert is_version_in_ranges("1.1.5", ranges)
        assert not is_version_in_ranges("1.2.0", ranges)
        assert not is_version_in_ranges("1.5.0", ranges)
        assert is_version_in_ranges("2.1.0", ranges)
        assert not is_version_in_ranges("2.3.0", ranges)

    def test_zero_introduced_interval(self) -> None:
        ranges = (
            RangeSpec(
                type=RangeType.SEMVER,
                events=(EventSpec(introduced="0"), EventSpec(fixed="1.5.0")),
            ),
        )
        assert is_version_affected("0.0.1", ranges)
        assert is_version_affected("1.4.9", ranges)
        assert not is_version_affected("1.5.0", ranges)

    def test_last_affected_boundary(self) -> None:
        ranges = (
            RangeSpec(
                type=RangeType.SEMVER,
                events=(
                    EventSpec(introduced="1.0.0"),
                    EventSpec(last_affected="1.2.0"),
                ),
            ),
        )
        assert is_version_affected("1.0.0", ranges)
        assert is_version_affected("1.2.0", ranges)
        assert not is_version_affected("1.2.1", ranges)

    def test_limit_as_upper_bound(self) -> None:
        ranges = (
            RangeSpec(
                type=RangeType.SEMVER,
                events=(
                    EventSpec(introduced="1.0.0"),
                    EventSpec(limit="1.3.0"),
                ),
            ),
        )
        assert is_version_affected("1.2.9", ranges)
        assert not is_version_affected("1.3.0", ranges)

    def test_lenient_version_parsing(self) -> None:
        assert parse_version_lenient("v1.2.3") == Version("1.2.3")
        assert parse_version_lenient("1.0.0-RELEASE") == Version("1.0.0")
        assert parse_version_lenient("1.0.0-SNAPSHOT") == Version("1.0.0.dev0")
        assert parse_version_lenient("latest") == Version("9999.9999.9999")
        assert parse_version_lenient("invalid_tag") == Version("0.0.0")
