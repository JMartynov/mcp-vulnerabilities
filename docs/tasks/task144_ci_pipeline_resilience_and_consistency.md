# Task 144: CI Pipeline Resilience & Consistency Hardening

## Overview & Goal
Resolve the CI pipeline failures across GitHub Actions workflows:
1. `ci.yml` (CI Workflow - Matrix 3.12, 3.14)
2. `action_test.yml` (Test Action - Matrix 3.12)
3. `daily_sync.yml` (Daily MCP Vulnerability Ingestion & Sync)
4. `remediate_action.yml` (MCP Security PR Remediation Bot)
5. `audit_cards.yml` (Daily Web Card Audit)

---

## Detailed Root Causes & Fixes

### 1. Missing Runtime Dependency `rich` in `pyproject.toml`
- **Root Cause**:
  `src/mcp_vulnerabilities/cli.py` imported `from rich.console import Console` at module top-level (introduced in Task 118 for terminal output and Task 38 for interactive timelines). However, `rich` was not declared under `[project.dependencies]` in `pyproject.toml`.
  As a result:
  - `pip install -e ".[dev]"` in `ci.yml` did not install `rich`.
  - `python -m mcp_vulnerabilities.cli validate` failed immediately with:
    `ModuleNotFoundError: No module named 'rich'`.
  - `action_test.yml` and `remediate_action.yml` failed with the exact same error.
- **Fix**:
  - Add `"rich>=13.0.0"` to `[project.dependencies]` in `pyproject.toml`.
  - Alternatively, make `rich` import lazy/graceful in `cli.py` with standard `print` fallback so environments without `rich` still function.

### 2. Daily Web Card Audit Parity Alignment (`scripts/audit_web_cards.py`)
- **Root Cause**:
  `scripts/audit_web_cards.py` used an outdated, hardcoded severity parsing method (`adv.get("database_specific", {}).get("severity")`), which conflicted with the authoritative `site_builder.py` composite risk engine that extracts CVSS metrics and respects ecosystem scoping.
- **Fix**:
  - Update `scripts/audit_web_cards.py` to import and use the canonical `_extract_advisory_severity` and `_compute_composite_risk` from `mcp_vulnerabilities.site_builder`.
  - Filter OSV advisories by ecosystem matching before comparing expected vulnerability posture against catalog entries.
  - Sanitize homepage URL validation for raw gists or multiline strings.

### 3. PR Bot Local Execution in `remediate_action.yml`
- **Root Cause**:
  `remediate_action.yml` ran `pip install mcp-vulnerabilities`, which pulls from public PyPI rather than the current repository checkout.
- **Fix**:
  - Change to `pip install -e ".[dev]"` or `pip install .` to run against the checked-out codebase.

---

## Acceptance Criteria
- `pytest tests/` runs cleanly.
- `python -m mcp_vulnerabilities.cli validate --dir data/vulnerabilities` exits with code 0 without `ModuleNotFoundError`.
- `python scripts/audit_web_cards.py --strict` runs with 0 fatal discrepancies.
