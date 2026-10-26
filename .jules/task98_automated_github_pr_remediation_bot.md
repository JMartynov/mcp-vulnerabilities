# Task 98: Automated GitHub PR Remediation Bot (`mcp-vuln-bot`) (P1)

**Blueprint Reference:** Strategic Roadmap Section 3 & 5 ([`docs/audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md`](../audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md))  
**Target Wave:** Wave 19 (Supply Chain Integrity, Attestation & Automated Remediation)  
**Priority:** `P1` (Automated Remediation & Enterprise CI/CD Adoption)

---

## 1. Architectural Context & Technical Objective

Currently, `mcp-vuln fix` operates interactively on a developer's local machine, requiring manual CLI execution. To scale MCP security across engineering organizations, teams need an automated GitHub PR Remediation Bot (similar to Dependabot, Snyk, or Renovate, but purpose-built for Model Context Protocol client configurations).

When scheduled in a repository's GitHub Actions workflow, the bot:
1. **Discovers All Client Configs in Repository**:
   - Searches repository roots, `.cursor/mcp.json`, `.vscode/mcp.json`, `cline_mcp_settings.json`, `claude_desktop_config.json`, and Dockerfiles.
2. **Computes Safe Remediation Version Pins**:
   - Matches installed package versions against OSV advisories and catalog safe versions via `mcp_vulnerabilities.fixer` and `site_builder._compute_composite_risk`.
3. **Automated Branch & Pull Request Generation**:
   - Creates a dedicated Git branch `mcp-vuln/fix-<timestamp>-<pkg>`.
   - Modifies the configuration files with pinned safe versions.
   - Formulates a rich, informative Markdown PR body containing:
     - Side-by-side JSON diff preview.
     - CVE / GHSA table with CVSS scores and summaries.
     - Cryptographic toolset fingerprint delta (`old_hash` ➔ `new_hash`).
   - Uses GitHub CLI (`gh pr create`) or GitHub REST API to open or update existing PRs, avoiding duplicate PR spam.

---

## 2. Target Files & Isolation Boundaries

- **New Package Files:**
  - `src/mcp_vulnerabilities/bot/__init__.py`
  - `src/mcp_vulnerabilities/bot/scanner.py` (multi-path config discovery & vulnerability analysis)
  - `src/mcp_vulnerabilities/bot/pr_builder.py` (Markdown PR formulation, git branch & commit management)
- **CLI Integration:**
  - `src/mcp_vulnerabilities/cli.py` (register `bot-remediate` or `remediate-pr` subcommand)
- **Reusable Action:**
  - `.github/workflows/remediate_action.yml` (template / composite action for downstream repos)
- **Test Suite:**
  - `tests/test_remediation_bot.py`

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Multi-Config Discovery & Patch Calculation (`INVARIANT_98_1A` – `INVARIANT_98_1B`)
- **Preconditions**: Provide a mock repository structure containing `.cursor/mcp.json` and a root `claude_desktop_config.json` with vulnerable packages.
- **Invariants**:
  - [ ] **INVARIANT_98_1A (Recursive Config Discovery)**: Discovers all supported MCP client config files across repository subdirectories without inspecting ignored directories (`.git`, `node_modules`, `.venv`).
  - [ ] **INVARIANT_98_1B (Accurate Remediation Mapping)**: Identifies vulnerable packages and calculates the exact minimal safe version pin for each file without altering indentation style or comments.

### Scenario 2: Rich Markdown PR Body & Diff Generation (`INVARIANT_98_2A` – `INVARIANT_98_2B`)
- **Preconditions**: Execute `generate_remediation_pr_body(vulnerabilities, diffs)`.
- **Invariants**:
  - [ ] **INVARIANT_98_2A (Structured Security Advisory Table)**: PR body contains a Markdown table listing Package Name, Installed Version, Target Safe Version, CVE/GHSA IDs, and CVSS Severity Badges.
  - [ ] **INVARIANT_98_2B (JSON Diff Snippet)**: Includes a fenced code block highlighting line additions/removals clearly for reviewing engineers.

### Scenario 3: Git Branch & PR Idempotency (`INVARIANT_98_3A` – `INVARIANT_98_3C`)
- **Preconditions**: Execute bot runner with mock `Git` and `GitHubClient`.
- **Invariants**:
  - [ ] **INVARIANT_98_3A (Clean Exit When Clean)**: If repository contains zero vulnerable MCP servers, exits code `0` with message `"No vulnerable MCP servers detected. Repository is clean."` and opens zero branches.
  - [ ] **INVARIANT_98_3B (Deduplication / No PR Spam)**: If an open PR from `mcp-vuln/fix-*` already addresses the same package version pin, updates the existing branch instead of opening a duplicate PR.
  - [ ] **INVARIANT_98_3C (Dry-Run Mode)**: When `--dry-run` is passed, prints planned branches, files, and PR bodies to stdout without executing git write operations.

---

## 4. Concrete Implementation Instructions

1. Implement `src/mcp_vulnerabilities/bot/scanner.py` to scan directories for `.json`, `.jsonc`, and `.yaml` client configurations.
2. Implement `src/mcp_vulnerabilities/bot/pr_builder.py` providing Git worktree operations and GitHub PR formulation logic.
3. Expose `mcp-vuln remediate-pr` in `src/mcp_vulnerabilities/cli.py` accepting `--repo-dir`, `--dry-run`, `--auto-merge`, `--assignee`, and `--json`.
4. Author comprehensive test suite in `tests/test_remediation_bot.py` testing config discovery, PR body generation, dry-run mode, and idempotency.
5. Verify `.venv/bin/pytest tests/test_remediation_bot.py` passes 100%.

---

## 5. Non-Interactive Completion Directive

Implement all scanner modules, PR builder logic, CLI integration, and test fixtures directly. Ensure all tests pass before submitting.
