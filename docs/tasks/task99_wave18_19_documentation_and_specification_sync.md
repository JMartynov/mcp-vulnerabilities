# Task 99: Wave 18 & Wave 19 Documentation & Specification Synchronization (P1)

**Target Wave:** Wave 19 (Post-Implementation Documentation Gate)  
**Priority:** `P1` (Mandatory Release Documentation Gate)  
**Master Plan:** [`docs/tasks/IMPLEMENTATION_PLAN_WAVE19_SUPPLY_CHAIN_INTEGRITY_AND_REMEDIATION.md`](IMPLEMENTATION_PLAN_WAVE19_SUPPLY_CHAIN_INTEGRITY_AND_REMEDIATION.md)

---

## 1. Architectural Context & Technical Objective

Waves 18 and 19 introduced substantial user-facing features, supply chain threat defenses, and portal intelligence enhancements:

### Wave 18: Web View & Security Intelligence Portal Enhancements (Tasks 89–95)
1. **Passports Pipeline & Data Engine (`site_builder.py`, `docs/data/`)**: Defaulted to `passports.json.gz`, extracted connection config schemas (`x-api-key`, `client_secret`) and transports (`streamable-http`, `sse`), and recompiled `mcp_catalog_index.json` (6,298 servers) and `analytics.json`.
2. **Directory Multi-Criteria Sorting & URL Deep-Linking (`docs/index.html`, `docs/app.js`, `docs/style.css`)**: Multi-criteria sorting dropdown (Risk, Advisories, Tools, A-Z) and bidirectional URL query state synchronization (`?q=`, `?server=`, `?tab=`, `?sort=`).
3. **Server Modal Remote Endpoints & Config Schema Panel (`docs/index.html`, `docs/app.js`, `docs/updates.js`, `docs/style.css`)**: Added 4th sub-tab "🌐 Endpoints & Schema" rendering live deployment URLs, connection types (`streamable-http`, `sse`), and config property schemas with HTTP plaintext warnings.
4. **In-Browser Config Auditor Sample Presets & Exporter (`docs/index.html`, `docs/app.js`, `docs/style.css`)**: 1-click sample vulnerable and clean preset buttons, plus "Download Fixed Config (.json)" and "Export Markdown Audit Report (.md)" buttons.
5. **Interactive Click-to-Filter Drilldowns on Analytics Portal (`docs/analytics.html`, `docs/app.js`)**: Made tools, OWASP categories, shadowed tools, and Zero-Day gap cards clickable to navigate to `index.html` with active search and filter parameters.
6. **Interactive Arbitrary Two-Version Diff Comparator (`docs/app.js`, `docs/updates.js`, `docs/style.css`)**: Baseline version selector inside `#server-modal` computing cumulative tool additions, removals, parameter mutations, and resolved/introduced CVEs.
7. **Release History Delta Calculation & Semantic Version Ordering (`updates_builder.py`, `docs/updates.js`)**: Release-over-release delta calculation for new/updated advisories and servers, plus client-side numerical SemVer sorting.

### Wave 19: Supply Chain Integrity, Attestation & Automated Remediation (Tasks 96–98)
1. **Sigstore Cosign Keyless Attestation & Verifiable Feed Pipeline (Task 96)**:
   - Module `src/mcp_vulnerabilities/attestation/` (`manifest.py`, `verifier.py`).
   - OIDC keyless signing of daily vulnerability feeds (`docs/data/vulnerabilities.json.gz`), wheels, and manifest in `.github/workflows/sign_release.yml`.
   - CLI command `mcp-vuln verify-feed --feed <path> [--manifest <path>] [--bundle <path>] [--identity <id>] [--issuer <url>]`.
2. **Typosquatting & LLM Hallucinated Package Detector (Task 97)**:
   - Module `src/mcp_vulnerabilities/analyzers/typosquat/` (`detector.py`, `corpus.py`).
   - Levenshtein distance, permutation, and homoglyph analysis to detect hallucinated or typosquatted MCP packages against authentic catalog corpus (`RiskTier.CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `CLEAN`).
   - CLI command `mcp-vuln audit-typosquat --config <path> [--threshold <int>] [--fix] [--json]`.
3. **Automated GitHub PR Remediation Bot (Task 98)**:
   - Module `src/mcp_vulnerabilities/bot/` (`scanner.py`, `pr_builder.py`).
   - Automated scanner discovering client configurations in repositories, computing safe version pins, and generating PRs with side-by-side diff previews and CVE tables.
   - CLI command `mcp-vuln remediate-pr [--repo-dir <path>] [--dry-run] [--auto-merge] [--assignee <user>] [--json]`.
   - GitHub Action `.github/workflows/remediate_action.yml`.

This task synchronizes all repository documentation (`README.md`, `docs/SPECIFICATION.md`, `docs/IMPLEMENTATION.md`, `CHANGELOG.md`, and `docs/tasks/README.md`) with Wave 18 and Wave 19 deliverables and updates the test suite metrics (390 passed tests).

---

## 2. Target Files & Isolation Boundaries

- **Primary Files:**
  - `README.md`
  - `docs/SPECIFICATION.md`
  - `docs/IMPLEMENTATION.md`
  - `CHANGELOG.md`
  - `docs/tasks/README.md`
- **Do NOT Modify:**
  - Do NOT modify test files or create any `tests/conftest.py`.
  - Do NOT touch existing application logic or data files.

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: CLI & Architecture Documentation Completeness (`INVARIANT_99_1A` – `INVARIANT_99_1D`)
- **Invariants**:
  - [ ] **INVARIANT_99_1A (`README.md` CLI & Feature Examples)**:
    - `README.md` documents `mcp-vuln verify-feed`, `mcp-vuln audit-typosquat`, and `mcp-vuln remediate-pr` with syntax, description, and flag examples.
    - `README.md` highlights the Wave 18 portal enhancements (Endpoints & Schema tab, multi-criteria sorting, URL deep-linking, diff comparator, config auditor exporter) and Wave 19 supply chain integrity features.
    - `README.md` reflects **390 automated tests (100% pass)**.
  - [ ] **INVARIANT_99_1B (`docs/SPECIFICATION.md` Formal Specifications)**:
    - Formal specification for Sigstore keyless attestation, bundle verification format, and `CATALOG_MANIFEST.json` schema.
    - Formal specification for Typosquatting & Hallucination detection algorithms (Damerau-Levenshtein, homoglyph character tables, Risk Tier classification).
    - Formal specification for Automated PR Remediation Bot (repository scanner discovery patterns, PR body markdown structure, git branch conventions `mcp-vuln/fix-<server>`).
    - Formal specification for the Wave 18 Endpoints & Schema panel and two-version diff comparator data models.
  - [ ] **INVARIANT_99_1C (`docs/IMPLEMENTATION.md` Module Breakdown)**:
    - Architecture sections documenting `src/mcp_vulnerabilities/attestation/` (`manifest.py`, `verifier.py`), `src/mcp_vulnerabilities/analyzers/typosquat/` (`detector.py`, `corpus.py`), and `src/mcp_vulnerabilities/bot/` (`scanner.py`, `pr_builder.py`).
    - Documentation of Wave 18 portal enhancements in `site_builder.py`, `docs/app.js`, `docs/updates.js`, and `docs/style.css`.
  - [ ] **INVARIANT_99_1D (`CHANGELOG.md` & `docs/tasks/README.md` Synchronization)**:
    - `CHANGELOG.md` includes dedicated sections for Wave 18 and Wave 19 (`## [Unreleased]` or `## [1.3.0]`), documenting Tasks 89–98 in detail following standard Keep a Changelog format.
    - `docs/tasks/README.md` correctly catalogs Task 99 as `Done` in Section 19.

---

## 4. Concrete Implementation Instructions

1. Update `README.md`:
   - Add documentation for `mcp-vuln verify-feed`, `mcp-vuln audit-typosquat`, and `mcp-vuln remediate-pr` in the CLI Reference and Feature Highlights sections.
   - Update Web Explorer portal section with Wave 18 features (URL deep-linking, Endpoints & Schema modal tab, Diff comparator, Preset buttons, and report exporter).
   - Update test suite metrics from 370+ to 390 passed tests.
2. Update `docs/SPECIFICATION.md`:
   - Add Section 7: Sigstore Keyless Attestation & Verifiable Feed Pipeline (Manifest format, Sigstore bundle verification, verification exit codes).
   - Add Section 8: Typosquatting & LLM Hallucinated Package Detector (Distance algorithms, homoglyphs, risk scoring, exit codes).
   - Add Section 9: Automated GitHub PR Remediation Bot (Repository scanning heuristics, git branch conventions, PR body format).
   - Add Section 10: Wave 18 Portal Schema Extensions (Remote endpoints, connection schemas, arbitrary diff computation).
3. Update `docs/IMPLEMENTATION.md`:
   - Add Section 17: Attestation Subsystem (`src/mcp_vulnerabilities/attestation/`).
   - Add Section 18: Typosquatting Analyzer Subsystem (`src/mcp_vulnerabilities/analyzers/typosquat/`).
   - Add Section 19: PR Remediation Bot Subsystem (`src/mcp_vulnerabilities/bot/`).
   - Add Section 20: Wave 18 Web View & Portal Intelligence Implementation.
4. Update `CHANGELOG.md`:
   - Prepend `## [1.3.0] - 2026-10-26` (or `## [Unreleased]`) documenting all Wave 18 (Tasks 89–95) and Wave 19 (Tasks 96–99) deliverables.
5. Update `docs/tasks/README.md`:
   - Add Task 99 under Section 19 and mark Tasks 96, 97, 98, and 99 as `Done`.
6. Verify all markdown files for correct formatting, link syntax, and ensure `.venv/bin/pytest tests/test_wave14_portal.py` passes.
7. Do **NOT** create `tests/conftest.py`.

---

## 5. Non-Interactive Completion Directive
This is an autonomous remote execution session. Complete all edits, verify formatting and tests, commit with `docs(sync): update documentation for Wave 18 and Wave 19 deliverables (Task 99) [skip ci]`, and exit cleanly. Do not pause to ask open-ended questions.
