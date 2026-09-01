"""Strict Template & Schema Conformance Verification for MCP OSV Vulnerabilities.

This test defines a canonical OSV 1.6 + MCP extension specification template
and validates that every advisory in data/vulnerabilities and in the compiled
vulnerabilities.json.gz snapshot strictly adheres to the format requirements.
"""

from __future__ import annotations

import gzip
import json
import re
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data" / "vulnerabilities"
SNAPSHOT_FILE = ROOT / "vulnerabilities.json.gz"

CWE_REGEX = re.compile(r"^CWE-[0-9]+$")
RFC3339_REGEX = re.compile(
    r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$"
)

# =========================================================================
# Canonical OSV 1.6 + MCP Extension Template Definition
# =========================================================================
OSV_TEMPLATE = {
    "required_fields": {
        "schema_version": str,
        "id": str,
        "summary": str,
        "details": str,
        "published": str,
        "modified": str,
        "affected": list,
    },
    "optional_fields": {
        "aliases": list,
        "related": list,
        "severity": list,
        "references": list,
        "withdrawn": (str, type(None)),
    },
    "allowed_range_types": {"SEMVER", "ECOSYSTEM", "GIT"},
    "allowed_severities": {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "NONE"},
}


def validate_osv_against_template(data: dict[str, Any], path_desc: str) -> list[str]:
    """Validate a single advisory dictionary strictly against the canonical OSV template."""
    errors: list[str] = []

    # 1. Top-Level Required Fields
    for field_name, expected_type in OSV_TEMPLATE["required_fields"].items():
        if field_name not in data:
            errors.append(f"{path_desc}: Missing required top-level field '{field_name}'")
        elif not isinstance(data[field_name], expected_type):
            errors.append(
                f"{path_desc}: Field '{field_name}' must be {expected_type}, got {type(data[field_name])}"
            )

    # 2. Timestamp Formats
    for time_field in ("published", "modified"):
        val = data.get(time_field)
        if isinstance(val, str) and not RFC3339_REGEX.match(val):
            errors.append(f"{path_desc}: Field '{time_field}' has invalid RFC 3339 format '{val}'")

    # 3. Affected Array
    affected = data.get("affected", [])
    if not isinstance(affected, list) or len(affected) == 0:
        errors.append(f"{path_desc}: 'affected' must be a non-empty list")
    else:
        for a_idx, aff in enumerate(affected):
            aff_desc = f"{path_desc} -> affected[{a_idx}]"
            if not isinstance(aff, dict):
                errors.append(f"{aff_desc}: Must be a dictionary")
                continue

            # Package spec
            pkg = aff.get("package")
            if not isinstance(pkg, dict):
                errors.append(f"{aff_desc}: Missing 'package' object")
            else:
                if not pkg.get("name"):
                    errors.append(f"{aff_desc} -> package: Missing 'name'")
                if not pkg.get("ecosystem"):
                    errors.append(f"{aff_desc} -> package: Missing 'ecosystem'")

            # Ranges spec
            ranges = aff.get("ranges", [])
            if isinstance(ranges, list):
                for r_idx, r in enumerate(ranges):
                    r_desc = f"{aff_desc} -> ranges[{r_idx}]"
                    r_type = r.get("type", "")
                    if r_type not in OSV_TEMPLATE["allowed_range_types"]:
                        errors.append(f"{r_desc}: Invalid range type '{r_type}'")

                    events = r.get("events", [])
                    if not isinstance(events, list) or len(events) == 0:
                        errors.append(f"{r_desc}: 'events' must be a non-empty list")

            # Database Specific Extensions (MCP extensions)
            db_spec = aff.get("database_specific")
            if db_spec and isinstance(db_spec, dict):
                # Check vulnerable_tools
                tools = db_spec.get("vulnerable_tools")
                if tools is not None and not isinstance(tools, list):
                    errors.append(f"{aff_desc} -> database_specific: 'vulnerable_tools' must be a list")

                # Check CWE IDs
                cwes = db_spec.get("cwe_ids")
                if cwes is not None:
                    if not isinstance(cwes, list):
                        errors.append(f"{aff_desc} -> database_specific: 'cwe_ids' must be a list")
                    else:
                        for cwe in cwes:
                            if isinstance(cwe, str) and not CWE_REGEX.match(cwe):
                                errors.append(f"{aff_desc} -> database_specific: Invalid CWE format '{cwe}'")

                # Check Severity
                sev = db_spec.get("severity")
                if sev is not None and str(sev).upper() not in OSV_TEMPLATE["allowed_severities"]:
                    errors.append(f"{aff_desc} -> database_specific: Invalid severity '{sev}'")

    # 4. References Array
    refs = data.get("references", [])
    if isinstance(refs, list):
        for r_idx, ref in enumerate(refs):
            ref_desc = f"{path_desc} -> references[{r_idx}]"
            if isinstance(ref, dict):
                url = ref.get("url", "")
                if not url or not (url.startswith("http://") or url.startswith("https://")):
                    errors.append(f"{ref_desc}: Reference URL must be a valid HTTP(S) URL, got '{url}'")

    return errors


def test_template_conformance_individual_advisories():
    """Verify that all individual OSV JSON advisory files strictly match the canonical template."""
    if not DATA_DIR.is_dir():
        pytest.skip(f"Data directory {DATA_DIR} does not exist")

    vuln_files = list(DATA_DIR.glob("*.json"))
    assert len(vuln_files) >= 500, f"Expected >= 500 advisories, found {len(vuln_files)}"

    all_errors: list[str] = []
    for vf in vuln_files:
        if vf.name in ("sync_state.json", "index.json"):
            continue
        try:
            content = json.loads(vf.read_text(encoding="utf-8"))
            errs = validate_osv_against_template(content, vf.name)
            if errs:
                all_errors.extend(errs)
        except Exception as exc:
            all_errors.append(f"{vf.name}: JSON parse error {exc}")

    assert len(all_errors) == 0, f"Template violations in {len(all_errors)} items:\n" + "\n".join(all_errors[:10])


def test_template_conformance_snapshot_payload():
    """Verify that all advisories inside vulnerabilities.json.gz strictly match the canonical template."""
    if not SNAPSHOT_FILE.is_file():
        pytest.skip(f"Snapshot file {SNAPSHOT_FILE} does not exist")

    with gzip.open(SNAPSHOT_FILE, "rt", encoding="utf-8") as f:
        snapshot = json.load(f)

    assert snapshot.get("schema_version") == "1.6.0"
    vulns = snapshot.get("vulnerabilities", {})
    assert len(vulns) >= 500

    all_errors: list[str] = []
    for vid, vdata in vulns.items():
        errs = validate_osv_against_template(vdata, f"snapshot:{vid}")
        if errs:
            all_errors.extend(errs)

    assert len(all_errors) == 0, f"Snapshot template violations in {len(all_errors)} items:\n" + "\n".join(all_errors[:10])
