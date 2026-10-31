# Task Contract: Task 107 — Automated Daily Web Card & Advisory Parity Auditor (P2)

### 1. Context & Objective:
Implement an Automated Daily Web Card & Advisory Parity Auditor to detect drift across catalog cards, shards, and OSV advisories:
1. Create `scripts/audit_web_cards.py`:
   - CLI flags: `--catalog` (default: `docs/data/mcp_catalog_index.json`), `--shards-dir` (default: `docs/data/shards`), `--vulnerabilities` (path to OSV advisory dataset/dir), `--report-dir` (default: `docs/reports/daily_audits`), `--strict` (exit code 1 on discrepancies), `--json`.
   - Core verifications:
     * Shard File Existence & Ingestion: Every `shard_file` referenced in `mcp_catalog_index.json` must exist on disk and contain the referenced package. Check for orphaned shard files.
     * Advisory & CVE Posture Parity: Validate `is_vulnerable`, `highest_cve_severity`, and counts against OSV data.
     * Composite Risk Tier Verification: Ensure consistency between computed risk and recorded `composite_risk_tier`.
     * Data sanity: Non-empty `package_name`, valid URL formats, non-negative tool/prompt/resource counts.
   - Report generation:
     * Markdown summary report in `docs/reports/daily_audits/audit_YYYYMMDD_HHMMSS.md`.
     * Structured JSON summary in `docs/reports/daily_audits/audit_latest.json`.
2. Create `.github/workflows/daily_web_audit.yml`:
   - Daily cron schedule (`0 3 * * *`), workflow_dispatch, and paths trigger on `docs/data/**` and `src/mcp_vulnerabilities/site_builder.py`.
   - Runs `python scripts/audit_web_cards.py --strict --report-dir docs/reports/daily_audits/` and uploads artifacts.
3. Unit tests:
   - Add `tests/test_audit_web_cards.py` with mock catalog and shard fixtures verifying error detection and exit codes.
4. Baseline report:
   - Run the script or create initial baseline report under `docs/reports/daily_audits/`.

### 2. Files to Create/Modify:
- `scripts/audit_web_cards.py`
- `.github/workflows/daily_web_audit.yml`
- `tests/test_audit_web_cards.py`
- `docs/reports/daily_audits/audit_latest.json`

### 3. Strict Guardrails:
- Do NOT re-scrape external web sources. Use local files and mock fixtures for tests.
- Verify tests with `pytest tests/test_audit_web_cards.py`.

### 4. Defaults when blocked:
- If a rule above cannot be met, leave that part as it was, list it in the summary with the reason, and continue. Do not ask questions.

### 5. Completion Directive:
- Implement all requested changes, verify with unit tests, and finalize your response directly with a concise summary. Do not ask conversational follow-up questions, so the task cleanly transitions to Completed.
