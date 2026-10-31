# Task 107: Automated Daily Web Card & Advisory Parity Auditor (P2)

**Subsystem:** CI/CD Quality Pipeline (`scripts/audit_web_cards.py`, `.github/workflows/daily_web_audit.yml`, `docs/reports/daily_audits/`)  
**Priority:** `P2`  
**Parent Plan:** [master_plan_wave20_mcp_fingerprints_capability_adoption.md](master_plan_wave20_mcp_fingerprints_capability_adoption.md)

---

## 1. Objective & Problem Statement

As `docs/data/mcp_catalog_index.json`, shards (`docs/data/shards/*.json`), and OSV advisory feeds (`data/vulnerabilities/`) evolve daily through automated scraping and CVE correlation, discrepancies can silently emerge:
1. Shard reference drift: A server card in `mcp_catalog_index.json` references a `shard_file` that does not exist or does not contain that package's versions.
2. Advisory count drift: Card badges report `is_vulnerable: true` with count $X$, while the underlying OSV database has updated to $Y$.
3. Composite risk tier mismatch: Stale static tiers differing from computed CVE severity scores.
4. Broken links or zero-tool anomalies: Server cards indicating 0 tools despite tool definitions being present.

Modeled after `mcp_fingerprints.deep_zero_tool_auditor`, this task introduces an **Automated Daily Web Card & Advisory Parity Auditor (`scripts/audit_web_cards.py`)** and an automated GitHub Action workflow that verifies 100% parity across cards, shards, and advisories, publishing daily health reports under `docs/reports/daily_audits/`.

---

## 2. Detailed Technical Requirements

### 2.1 Web Card Auditor Script (`scripts/audit_web_cards.py`)
1. Create `scripts/audit_web_cards.py` with CLI arguments:
   - `--catalog`: Path to `docs/data/mcp_catalog_index.json` (default: `docs/data/mcp_catalog_index.json`)
   - `--shards-dir`: Path to shards directory (default: `docs/data/shards`)
   - `--vulnerabilities`: Path to `docs/data/vulnerabilities.json.gz` or advisory directory
   - `--report-dir`: Path to write markdown reports (default: `docs/reports/daily_audits`)
   - `--strict`: Exit code 1 on any parity error or missing shard reference
   - `--json`: Output summary telemetry in JSON format
2. Core Parity Verifications:
   - **Shard File Existence & Ingestion**:
     * Verify that every unique `shard_file` referenced in `mcp_catalog_index.json` exists on disk.
     * Verify that loading `shard_file` finds the exact `package_name`.
     * Check for orphaned shard files (shards on disk with zero references in catalog).
   - **Advisory & CVE Posture Parity**:
     * Match `package_name` against the OSV matcher engine.
     * Compare `is_vulnerable`, `highest_cve_severity`, and `vulnerable_versions_count` against actual OSV records.
     * Flag discrepancies where a card shows "Clean" but active CVEs exist, or vice-versa.
   - **Composite Risk Tier Verification**:
     * Recompute composite risk tier from static risk tier and highest CVE severity.
     * Flag mismatches between index `composite_risk_tier` and the canonical evaluation formula.
   - **Data Sanity Invariants**:
     * Assert valid URLs for `repository_url` and `homepage_url` (syntax, valid protocols).
     * Assert non-empty `package_name` and `ecosystem`.
     * Assert valid numeric ranges for `tools_count`, `prompts_count`, `resources_count`.
3. Report Generation:
   - Generate `docs/reports/daily_audits/audit_YYYYMMDD_HHMMSS.md` containing:
     * Executive Summary Table (Total Servers Audited, Clean Shards, Discrepancies Found).
     * Discrepancy Breakdown (Missing Shards, CVE Mismatches, Risk Tier Drift).
     * Recommendations and action items for automated resolution.
   - Generate machine-readable `docs/reports/daily_audits/audit_latest.json`.

### 2.2 Daily GitHub Actions Workflow (`.github/workflows/daily_web_audit.yml`)
1. Create workflow scheduled via cron:
   ```yaml
   name: Daily Web Card & Advisory Parity Audit

   on:
     schedule:
       - cron: '0 3 * * *' # Daily at 03:00 UTC
     workflow_dispatch:
     push:
       paths:
         - 'docs/data/**'
         - 'src/mcp_vulnerabilities/site_builder.py'

   jobs:
     audit-cards:
       runs-on: ubuntu-latest
       steps:
         - uses: actions/checkout@v4
         - uses: actions/setup-python@v5
           with:
             python-version: '3.11'
             cache: 'pip'
         - name: Install Dependencies
           run: pip install -e .
         - name: Run Web Card Parity Auditor
           run: python scripts/audit_web_cards.py --strict --report-dir docs/reports/daily_audits/
         - name: Upload Audit Artifacts
           uses: actions/upload-artifact@v4
           with:
             name: daily-card-audit-report
             path: docs/reports/daily_audits/
   ```

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_107_1 (100% Shard Resolvability):** Every server record in `docs/data/mcp_catalog_index.json` points to an existing shard file containing that server's version history.
- [ ] **INVARIANT_107_2 (Zero Stale Advisory Badges):** If an OSV advisory is added or removed for package $P$, the auditor detects any divergence between `mcp_catalog_index.json` and the OSV database.
- [ ] **INVARIANT_107_3 (Strict CI Failure Enforcement):** If a corrupted shard or missing package is simulated, `python scripts/audit_web_cards.py --strict` exits with code `1`.
- [ ] **INVARIANT_107_4 (Report Formatting & Idempotency):** The generated Markdown report renders cleanly in GitHub, with formatted tables, timestamps, and actionable triage steps.
- [ ] **INVARIANT_107_5 (Unit Test Coverage):** Add `tests/test_audit_web_cards.py` validating the auditor's detection logic with mock catalog and shard fixtures.

---

## 4. Deliverables

1. `scripts/audit_web_cards.py`: Parity auditor implementation with card-to-shard, card-to-advisory, and risk tier verification.
2. `.github/workflows/daily_web_audit.yml`: Scheduled GitHub Actions workflow for automated daily execution.
3. `tests/test_audit_web_cards.py`: Unit tests validating all verification algorithms and error handlers.
4. `docs/reports/daily_audits/`: Initial baseline audit report verifying current repository state.
