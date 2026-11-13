"""CVSS vector calculations, severity extraction, and semver range evaluation utilities."""

from __future__ import annotations

import math
import re
from typing import Any

from packaging.version import InvalidVersion, Version


def calculate_cvss_v3_score(vector: str) -> float | None:
    match = re.search(
        r"AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([NLH])/I:([NLH])/A:([NLH])",
        vector,
    )
    if not match:
        return None

    av, ac, pr, ui, s, c, i, a = match.groups()

    av_weights = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    ac_weights = {"L": 0.77, "H": 0.44}
    pr_weights_U = {"N": 0.85, "L": 0.62, "H": 0.27}
    pr_weights_C = {"N": 0.85, "L": 0.68, "H": 0.50}
    ui_weights = {"N": 0.85, "R": 0.62}
    cia_weights = {"N": 0.0, "L": 0.22, "H": 0.56}

    iss = 1 - ((1 - cia_weights[c]) * (1 - cia_weights[i]) * (1 - cia_weights[a]))

    if iss <= 0:
        return 0.0

    if s == "U":
        impact = 6.42 * iss
        exploitability = (
            8.22 * av_weights[av] * ac_weights[ac] * pr_weights_U[pr] * ui_weights[ui]
        )
        base_score_raw = min(impact + exploitability, 10.0)
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
        exploitability = (
            8.22 * av_weights[av] * ac_weights[ac] * pr_weights_C[pr] * ui_weights[ui]
        )
        base_score_raw = min(1.08 * (impact + exploitability), 10.0)

    int_input = round(base_score_raw * 100000)
    if (int_input % 10000) == 0:
        return int_input / 100000.0
    else:
        return (math.floor(int_input / 10000) + 1) / 10.0


def score_to_severity(score: float) -> str:
    """Map numeric CVSS score to standardized severity level."""
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0.0:
        return "LOW"
    else:
        return "UNKNOWN"


def extract_advisory_severity(
    adv: dict[str, Any],
    affected: dict[str, Any] | None = None,
) -> tuple[str, float | None]:
    """Extract normalized severity tier and numeric CVSS score from an advisory.

    Consolidates extraction across feed, transitive, and audit matching modules.

    Args:
        adv: OSV advisory dictionary.
        affected: Optional affected package dictionary for contextual overrides.

    Returns:
        Tuple of (severity_string, cvss_score_or_none), e.g. ("HIGH", 7.5).
    """
    cvss_score: float | None = None
    nominal_severity: str | None = None

    for s in adv.get("severity", []):
        if not isinstance(s, dict):
            continue
        score_val = s.get("score")
        if score_val is None:
            continue
        score_str = str(score_val)

        # Try parsing CVSS v3 vector
        match = re.search(
            r"AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH]",
            score_str,
        )
        if match:
            cvss_score = calculate_cvss_v3_score(score_str)
            if cvss_score is not None:
                break

        # If vector parsing encounters an unknown/extended format, extract nominal severity
        if score_str.startswith("CVSS:"):
            if "C:H" in score_str and "I:H" in score_str and "A:H" in score_str:
                nominal_severity = "CRITICAL"
            elif "C:H" in score_str or "I:H" in score_str or "A:H" in score_str:
                nominal_severity = "HIGH"
            elif "C:L" in score_str or "I:L" in score_str or "A:L" in score_str:
                nominal_severity = "MEDIUM"
            else:
                nominal_severity = "LOW"

        try:
            cvss_score = float(score_str)
            break
        except (ValueError, TypeError):
            pass

    # Check database_specific severity
    db_spec = adv.get("database_specific", {}) if isinstance(adv, dict) else {}
    if affected and isinstance(affected, dict):
        aff_spec = affected.get("database_specific", {})
        if not db_spec.get("severity") and aff_spec.get("severity"):
            db_spec = aff_spec
        if cvss_score is None and aff_spec.get("cvss_score"):
            try:
                cvss_score = float(aff_spec["cvss_score"])
            except (ValueError, TypeError):
                pass
    elif not db_spec and adv.get("affected"):
        first_aff = adv["affected"][0]
        if isinstance(first_aff, dict):
            aff_spec = first_aff.get("database_specific", {})
            if not db_spec.get("severity") and aff_spec.get("severity"):
                db_spec = aff_spec
            if cvss_score is None and aff_spec.get("cvss_score"):
                try:
                    cvss_score = float(aff_spec["cvss_score"])
                except (ValueError, TypeError):
                    pass

    sev = db_spec.get("severity") or nominal_severity

    if not sev and cvss_score is not None:
        sev = score_to_severity(cvss_score)

    if not sev:
        sev = "UNKNOWN"

    return sev.upper(), cvss_score


# Backward-compatible alias for callers/tests importing private name
_extract_severity_info = extract_advisory_severity


def parse_version_lenient(v_str: str) -> Version:
    """Parse version string leniently, handling prefix 'v', Maven qualifiers, Go pseudo-versions, and fallbacks."""
    clean = v_str.lstrip("v=").strip()

    # Handle Maven qualifiers
    clean = re.sub(r"[\.\-]?(RELEASE|Final)$", "", clean, flags=re.IGNORECASE)
    clean = re.sub(r"[\.\-]?SNAPSHOT$", ".dev0", clean, flags=re.IGNORECASE)

    # Handle Go pseudo-versions: v0.0.0-20260101120000-abcdef123456
    if "-" in clean:
        parts = clean.split("-")
        if len(parts) >= 3 and len(parts[-2]) == 14 and parts[-2].isdigit():
            clean = f"{parts[0]}.dev{parts[-2]}"

    # Handle docker tags like "latest"
    if clean.lower() == "latest":
        return Version("9999.9999.9999")

    try:
        return Version(clean)
    except InvalidVersion:
        # Fallback for non-standard versions: strip suffixes
        m = re.match(r"^(\d+(\.\d+)*)", clean)
        if m:
            return Version(m.group(1))
        return Version("0.0.0")


def is_version_in_ranges(
    version_str: str | None,
    ranges: Any = None,
    versions: list[str] | tuple[str, ...] | None = None,
) -> bool:
    """Checks if a version is within the specified OSV ranges or version list.

    Reconstructs interval pairs to accurately evaluate discontinuous ranges
    (e.g. [{introduced: 1.0}, {fixed: 1.2}, {introduced: 2.0}, {fixed: 2.2}])
    without misclassifying intermediate versions.

    Args:
        version_str: Target version string to evaluate.
        ranges: Collection of RangeSpec objects or range dicts with 'events'.
        versions: Optional list of explicit vulnerable version strings.

    Returns:
        True if the version is affected, False otherwise.
    """
    if not version_str:
        return True  # Conservatively mark vulnerable if version unknown

    if not ranges and not versions:
        return True

    if versions and version_str in versions:
        return True

    try:
        target_v = parse_version_lenient(version_str)
    except Exception:
        return True

    if not ranges:
        return False

    # Filter to SEMVER ranges if typed ranges exist
    semver_ranges: list[Any] = []
    has_typed_ranges = False

    for r in ranges:
        r_type = getattr(r, "type", None) or (r.get("type") if isinstance(r, dict) else None)
        if r_type is not None:
            has_typed_ranges = True
            r_type_val = getattr(r_type, "value", str(r_type)).upper()
            if r_type_val == "SEMVER":
                semver_ranges.append(r)
        else:
            semver_ranges.append(r)

    # If all ranges were explicitly non-SEMVER (e.g. ECOSYSTEM or GIT), conservatively mark vulnerable
    if has_typed_ranges and not semver_ranges:
        return True

    for r in semver_ranges:
        raw_events = getattr(r, "events", None) or (r.get("events", []) if isinstance(r, dict) else [])
        intervals: list[tuple[Version | None, Version | None, Version | None]] = []
        curr_intro: Version | None = None
        curr_last_aff: Version | None = None

        for ev in raw_events:
            intro_raw = getattr(ev, "introduced", None) or (ev.get("introduced") if isinstance(ev, dict) else None)
            fixed_raw = getattr(ev, "fixed", None) or (ev.get("fixed") if isinstance(ev, dict) else None)
            last_aff_raw = getattr(ev, "last_affected", None) or (ev.get("last_affected") if isinstance(ev, dict) else None)
            limit_raw = getattr(ev, "limit", None) or (ev.get("limit") if isinstance(ev, dict) else None)
            if not fixed_raw and limit_raw and limit_raw != "*":
                fixed_raw = limit_raw

            if intro_raw is not None:
                if curr_intro is not None:
                    intervals.append((curr_intro, None, curr_last_aff))
                    curr_last_aff = None
                curr_intro = (
                    parse_version_lenient("0.0.0") if intro_raw == "0" else parse_version_lenient(intro_raw)
                )
            elif fixed_raw is not None:
                fix_v = parse_version_lenient(fixed_raw)
                intervals.append((curr_intro, fix_v, curr_last_aff))
                curr_intro = None
                curr_last_aff = None
            elif last_aff_raw is not None:
                curr_last_aff = parse_version_lenient(last_aff_raw)

        if curr_intro is not None or curr_last_aff is not None:
            intervals.append((curr_intro, None, curr_last_aff))

        for intro_v, fix_v, last_aff_v in intervals:
            in_interval = True
            if intro_v is not None and target_v < intro_v:
                in_interval = False
            if fix_v is not None and target_v >= fix_v:
                in_interval = False
            if last_aff_v is not None and target_v > last_aff_v:
                in_interval = False

            if in_interval and (
                intro_v is not None or fix_v is not None or last_aff_v is not None
            ):
                return True

    return False


def is_version_affected(
    version_str: str | None,
    ranges: Any,
) -> bool:
    """Evaluates if a given version is affected based on OSV RangeSpecs."""
    return is_version_in_ranges(version_str, ranges=ranges)


__all__ = [
    "calculate_cvss_v3_score",
    "score_to_severity",
    "extract_advisory_severity",
    "_extract_severity_info",
    "parse_version_lenient",
    "is_version_in_ranges",
    "is_version_affected",
]
