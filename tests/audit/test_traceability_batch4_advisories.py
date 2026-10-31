"""Empirical Traceability Test Suite for Batch 4 (CVE, GHSA & NVD Vulnerability Advisory Mappings)."""

import json
from pathlib import Path
import pytest
from mcp_vulnerabilities.validator import OsvValidator

VULNS_PATH = Path("docs/data/vulnerabilities.json")

@pytest.fixture(scope="module")
def vulnerabilities():
    with open(VULNS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)

def test_batch4_sample_schema_validity(vulnerabilities):
    # Validate OSV schema compliance across sampled batch
    validator = OsvValidator()
    sample_ids = ["CVE-2002-2036", "CVE-2025-49596", "CVE-2025-53818", "GHSA-29w2-fq35-v728"]
    vuln_map = {v["id"]: v for v in vulnerabilities}
    for vid in sample_ids:
        assert vid in vuln_map, f"Advisory {vid} missing from vulnerabilities.json"
        errors = validator.validate(vuln_map[vid])
        assert not errors, f"Advisory {vid} failed OSV validation: {errors}"
