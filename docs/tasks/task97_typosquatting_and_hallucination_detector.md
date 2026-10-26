# Task 97: Typosquatting & LLM Hallucinated Package Detector (`mcp-vuln audit-typosquat`) (P1)

**Blueprint Reference:** Strategic Roadmap Section 3 & 5 ([`docs/audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md`](../audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md))  
**Target Wave:** Wave 19 (Supply Chain Integrity, Attestation & Automated Remediation)  
**Priority:** `P1` (Supply Chain Threat Defense)

---

## 1. Architectural Context & Technical Objective

Recent security research into AI code generators and LLM assistants reveals a severe emerging threat vector: **AI Package Hallucination & MCP Typosquatting**. LLMs frequently generate slightly misspelled or plausible package names when recommending tool configurations (e.g. `mcp-server-filesystem` vs `mcp-server-filesytem`, `fetch-mcp` vs `mcp-fetch`, or `mcp_sqlite` vs `mcp-server-sqlite`). Threat actors proactively register these misspelled packages on npm and PyPI to deliver malicious payloads directly into developer environments.

Currently, `mcp-vuln audit` checks whether known versions match OSV records, but silently ignores packages that do not exist or differ slightly from known authentic packages.

This task creates a specialized **Typosquatting & Hallucination Defense Engine** (`mcp-vuln audit-typosquat`):
1. **Curated & Dynamic Authentic Registry Index**:
   - Compiles a corpus of verified, top-tier authentic MCP package names from the 6,298-server catalog (`mcp_catalog_index.json`), official `@modelcontextprotocol/*` namespaces, and top community repositories.
2. **Multi-Algorithm String Similarity & Distance Metrics**:
   - **Levenshtein Distance**: Flags package names with edit distance $1 \le d \le 2$ from popular packages.
   - **Homoglyph & Mixed-Script Analysis**: Detects look-alike Unicode characters (e.g. Cyrillic `а` vs Latin `a`, `о` vs `o`) designed to visually deceive developers.
   - **Prefix / Suffix Permutation**: Detects transposition of common prefixes (`mcp-server-*`, `mcp-*`, `server-*`, `@modelcontextprotocol/*`).
   - **Bit-Squatting / Keyboard Proximity**: Detects single bit-flip typos matching physical keyboard layouts.
3. **Comprehensive CLI Integration (`mcp-vuln audit-typosquat`)**:
   - Scans client configuration files (`claude_desktop_config.json`, `cline_mcp_settings.json`, Cursor, Windsurf, Zed).
   - Reports risk tier (`CRITICAL`, `HIGH`, `SUSPICIOUS`, `AUTHENTIC`), candidate legitimate package name, distance metric, and explanation.
   - Returns exit code `1` when critical/high typosquats or hallucinations are detected, and `0` when clean. Supports `--json` and `--fix` flags.

---

## 2. Target Files & Isolation Boundaries

- **New Package Files:**
  - `src/mcp_vulnerabilities/analyzers/typosquat/__init__.py`
  - `src/mcp_vulnerabilities/analyzers/typosquat/detector.py` (distance calculation, homoglyphs, brand corpus)
  - `src/mcp_vulnerabilities/analyzers/typosquat/corpus.py` (curated popular package corpus generator)
- **CLI Integration:**
  - `src/mcp_vulnerabilities/cli.py` (register `audit-typosquat` subcommand)
- **Test Suite:**
  - `tests/test_typosquat_detector.py`

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Levenshtein & Transposition Detection (`INVARIANT_97_1A` – `INVARIANT_97_1C`)
- **Preconditions**: Pass synthetic client configurations with known typosquat variations to `TyposquatDetector`.
- **Invariants**:
  - [ ] **INVARIANT_97_1A (Distance 1 Typosquat Flagged)**: Packages like `@modelcontextprotocol/server-filesytem` (missing 's') or `mcp-server-sqlte` are detected with distance 1 and flagged as `HIGH_RISK_TYPOSQUAT` suggesting `@modelcontextprotocol/server-filesystem` and `mcp-server-sqlite`.
  - [ ] **INVARIANT_97_1B (Prefix/Suffix Transposition Flagged)**: Configurations specifying `filesystem-mcp-server` instead of `mcp-server-filesystem` are flagged with `SUSPICIOUS_NAMING_PERMUTATION`.
  - [ ] **INVARIANT_97_1C (Authentic Packages Clean)**: Packages exactly matching authentic corpus entries return `RiskTier.AUTHENTIC` with zero false-positive warnings.

### Scenario 2: Homoglyph & Confusable Unicode Analysis (`INVARIANT_97_2A`)
- **Preconditions**: Test package names containing visually identical Unicode characters.
- **Invariants**:
  - [ ] **INVARIANT_97_2A (Homoglyph Spoofing Detection)**: A package name substituting Latin letters with Cyrillic or Greek look-alikes (e.g. `mсp-server-sqlite` with Cyrillic `с` U+0441) is immediately flagged as `CRITICAL_HOMOGLYPH_ATTACK`.

### Scenario 3: CLI `mcp-vuln audit-typosquat` Contract (`INVARIANT_97_3A` – `INVARIANT_97_3C`)
- **Preconditions**: Run `mcp-vuln audit-typosquat --config <path>`.
- **Invariants**:
  - [ ] **INVARIANT_97_3A (Exit Codes)**: Exits with code `1` if any `HIGH` or `CRITICAL` typosquat is detected; exits with code `0` if all packages are authentic or acknowledged.
  - [ ] **INVARIANT_97_3B (Interactive / Auto Fix)**: When `--fix` is passed, prompts user or updates the configuration file in-place with the suggested canonical package names.
  - [ ] **INVARIANT_97_3C (JSON Output)**: Supplies structured output under `--json` detailing `{ "analyzed_packages": [...], "typosquats_detected": [...], "risk_summary": {...} }`.

---

## 4. Concrete Implementation Instructions

1. Create `src/mcp_vulnerabilities/analyzers/typosquat/detector.py` implementing Levenshtein distance, Damerau-Levenshtein, and Unicode confusable skeleton matching.
2. Build authentic package corpus in `src/mcp_vulnerabilities/analyzers/typosquat/corpus.py` extracted from `mcp_catalog_index.json` and standard reference namespaces.
3. Expose `audit-typosquat` in `src/mcp_vulnerabilities/cli.py` accepting `--config`, `--fix`, `--threshold`, `--json`, and `--strict`.
4. Create comprehensive test suite in `tests/test_typosquat_detector.py` testing clean configurations, single-char typos, homoglyphs, and `--fix` in-place corrections.
5. Verify `.venv/bin/pytest tests/test_typosquat_detector.py` passes 100%.

---

## 5. Non-Interactive Completion Directive

Implement all detector algorithms, corpus loader, CLI subcommand, and unit tests directly. Ensure all tests pass cleanly before final review.
