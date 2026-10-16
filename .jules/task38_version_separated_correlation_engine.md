# Task 38: Version-Separated Vulnerability & Passport Correlation Engine + CLI Expansion (P0)

## 1. Architectural Context & Technical Objective
Implement a version-separated vulnerability and passport correlation engine (`src/mcp_vulnerabilities/fingerprints/correlator.py`) that indexes security advisories on a strict per-version basis rather than collapsing them at the package level. Ingest upstream passport structural data from `mcp-fingerprints` (`passports.json.gz`), match exact server versions against OSV, GHSA, and NVD affected ranges, and establish version-specific vulnerability timelines. Expand the CLI with subcommands `mcp-vuln timeline <server>`, `mcp-vuln correlate`, and version-aware audit flags (`--target-version`).

## 2. Target Files & Documentation to Update
- `src/mcp_vulnerabilities/fingerprints/correlator.py`
- `src/mcp_vulnerabilities/models.py`
- `src/mcp_vulnerabilities/cli.py`
- `tests/test_correlator.py`
- `tests/test_cli_timeline.py`
- `docs/version_correlation.md`

## 3. EULIS Implementation & Branch Review Workflow
- Branch: `jules/review-task38`
- Implementation PR: `jules-gate pr --skip-ci`
- Offload Mode 2 EULIS Code Review: `jules-gate review-branch`
- Review verification: check `docs/reviews/review_task38.md`
- Test verification: run test suite via isolated subagent (`jules-gate verify`)
- Merge: `jules-gate pr-merge --skip-ci`

## 4. Acceptance & Verification Criteria
- [ ] Correlation engine accurately resolves complex SemVer ranges (`>=`, `<`, `^`, `~`) against passport versions.
- [ ] Computes per-version vulnerability states (affected vs fixed/safe) for every server release.
- [ ] CLI subcommand `mcp-vuln timeline` displays a visual terminal timeline of server releases and security states.
- [ ] `mcp-vuln correlate` outputs version-annotated correlation dataset.
- [ ] Unit tests verify edge cases (pre-releases, unbounded ranges, multiple advisory overlap).
