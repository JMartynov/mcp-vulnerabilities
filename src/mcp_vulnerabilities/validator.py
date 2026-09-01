"""Validation engine for OSV v1.6.0 documents and MCP extensions."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.models import OsvVulnerability


class OsvValidationError(Exception):
    """Raised when an OSV vulnerability record fails schema validation."""


class OsvValidator:
    """Validates OSV v1.6.0 documents and MCP ecosystem extensions."""

    RFC3339_REGEX = re.compile(
        r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$"
    )
    CWE_REGEX = re.compile(r"^CWE-\d+$")
    CVSS_V3_REGEX = re.compile(r"^CVSS:3\.[01]/.*")
    CVSS_V4_REGEX = re.compile(r"^CVSS:4\.0/.*")
    PURL_REGEX = re.compile(r"^pkg:[a-zA-Z0-9.\-_]+/.+$")
    URL_SCHEME_REGEX = re.compile(r"^(https?|git|ftp|ftps|sftp)://")

    @classmethod
    def validate(cls, vuln: OsvVulnerability | dict[str, Any]) -> list[str]:
        """Validate an OsvVulnerability model or dict. Returns error list (empty if valid)."""
        if isinstance(vuln, dict):
            try:
                model = OsvVulnerability.from_dict(vuln)
            except Exception as exc:
                return [f"Failed to parse OSV dict: {exc}"]
        else:
            model = vuln

        errors: list[str] = []

        # 1. Mandatory Top-Level Fields
        if not model.id or not model.id.strip():
            errors.append("OSV document missing required 'id'.")
        if not model.summary or not model.summary.strip():
            errors.append("OSV document missing required 'summary'.")
        if not model.details or not model.details.strip():
            errors.append("OSV document missing required 'details'.")

        # 2. Schema version
        if not model.schema_version.startswith("1."):
            errors.append(
                f"Unsupported schema_version '{model.schema_version}', expected '1.6.0' or '1.x'."
            )

        # 3. Timestamps & Chronological Ordering
        pub_valid = False
        mod_valid = False
        if model.published:
            if not cls.RFC3339_REGEX.match(model.published):
                errors.append(f"Invalid RFC 3339 'published' timestamp: '{model.published}'.")
            else:
                pub_valid = True

        if model.modified:
            if not cls.RFC3339_REGEX.match(model.modified):
                errors.append(f"Invalid RFC 3339 'modified' timestamp: '{model.modified}'.")
            else:
                mod_valid = True

        if (
            pub_valid
            and mod_valid
            and model.published
            and model.modified
            and model.published > model.modified
        ):
            errors.append(
                f"Timestamp anomaly: 'published' ({model.published}) is after "
                f"'modified' ({model.modified})."
            )

        # 4. References Protocol Check
        for r_idx, ref in enumerate(model.references):
            if ref.url and not cls.URL_SCHEME_REGEX.match(ref.url):
                errors.append(
                    f"references[{r_idx}].url '{ref.url}' has invalid protocol "
                    "(must start with http://, https://, or git://)."
                )

        # 5. Affected Packages & Extensions
        if not model.affected:
            errors.append("OSV document must define at least one 'affected' package entry.")

        for i, aff in enumerate(model.affected):
            pkg = aff.package
            if not pkg.name or not pkg.name.strip():
                errors.append(f"affected[{i}].package missing 'name'.")
            if not pkg.ecosystem or not pkg.ecosystem.strip():
                errors.append(f"affected[{i}].package missing 'ecosystem'.")

            if pkg.purl and not cls.PURL_REGEX.match(pkg.purl):
                errors.append(f"affected[{i}].package.purl '{pkg.purl}' is invalid PURL format.")

            # Check ranges
            for r_idx, r in enumerate(aff.ranges):
                if not r.events:
                    errors.append(f"affected[{i}].ranges[{r_idx}] has no events.")
                for e_idx, ev in enumerate(r.events):
                    if not any([ev.introduced, ev.fixed, ev.last_affected, ev.limit]):
                        errors.append(
                            f"affected[{i}].ranges[{r_idx}].events[{e_idx}] "
                            "has no defined version boundary."
                        )

            # Check database_specific
            db_mcp = aff.database_specific
            if db_mcp.cvss_score is not None and not (0.0 <= db_mcp.cvss_score <= 10.0):
                errors.append(
                    f"affected[{i}].database_specific.cvss_score '{db_mcp.cvss_score}' "
                    "out of range [0.0, 10.0]."
                )
            if db_mcp.epss_score is not None and not (0.0 <= db_mcp.epss_score <= 1.0):
                errors.append(
                    f"affected[{i}].database_specific.epss_score '{db_mcp.epss_score}' "
                    "out of range [0.0, 1.0]."
                )
            if db_mcp.cvss_v3_vector and not cls.CVSS_V3_REGEX.match(db_mcp.cvss_v3_vector):
                errors.append(
                    f"affected[{i}].database_specific.cvss_v3_vector '{db_mcp.cvss_v3_vector}' "
                    "has invalid CVSS v3 vector format."
                )
            if db_mcp.cvss_v4_vector and not cls.CVSS_V4_REGEX.match(db_mcp.cvss_v4_vector):
                errors.append(
                    f"affected[{i}].database_specific.cvss_v4_vector '{db_mcp.cvss_v4_vector}' "
                    "has invalid CVSS v4 vector format."
                )
            for cwe in db_mcp.cwe_ids:
                if not cls.CWE_REGEX.match(cwe):
                    errors.append(
                        f"affected[{i}].database_specific.cwe_ids entry '{cwe}' "
                        "invalid format (expected CWE-\\d+)."
                    )

        return errors

    @classmethod
    def validate_directory(
        cls, directory: str | Path
    ) -> tuple[int, int, list[str]]:
        """Validate all OSV JSON files in a directory.

        Returns (valid_count, invalid_count, error_messages).
        """
        dir_path = Path(directory)
        valid_count = 0
        invalid_count = 0
        all_errors: list[str] = []

        if not dir_path.is_dir():
            return 0, 0, [f"Directory not found: {dir_path}"]

        for j_file in sorted(dir_path.rglob("*.json")):
            if j_file.name in ("index.json", "sync_state.json", ".vuln_index.pickle"):
                continue
            try:
                data = json.loads(j_file.read_text(encoding="utf-8"))
                errors = cls.validate(data)
                if errors:
                    invalid_count += 1
                    all_errors.extend(f"{j_file.name}: {e}" for e in errors)
                else:
                    valid_count += 1
            except Exception as exc:
                invalid_count += 1
                all_errors.append(f"{j_file.name}: failed to read JSON: {exc}")

        return valid_count, invalid_count, all_errors

    @classmethod
    def assert_valid(cls, vuln: OsvVulnerability | dict[str, Any]) -> None:
        """Validate and raise OsvValidationError if any rule fails."""
        errors = cls.validate(vuln)
        if errors:
            formatted = "\n".join(f"- {e}" for e in errors)
            raise OsvValidationError(f"OSV validation failed ({len(errors)} errors):\n{formatted}")
