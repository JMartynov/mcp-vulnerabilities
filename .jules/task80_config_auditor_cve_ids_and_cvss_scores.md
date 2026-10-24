# Task 80: Config Auditor CVE IDs & CVSS Scores (P0)

**Defect:** W14-03 · **Files:** `docs/app.js`, `docs/style.css` · **Wave:** 15

## Problem
Task 77 Scenario 2 requires the posture report to list *CVE IDs, CVSS scores, and recommended safe versions*. `renderAuditResults()` (~L553–561) only prints `Found <pkg> which has known vulnerabilities. Recommended Fix: Pin to v<safe>`.

## Required Change
1. For each matched vulnerable server, cross-reference the already-loaded advisory list (`allAdvisories` / `vulnerabilities.json`) by package name (`affected[].package.name`, case-insensitive, ecosystem-aware).
2. If the config pins a version, only include advisories whose ranges affect that version when determinable; otherwise list all.
3. Render per advisory: ID (CVE/GHSA, linking to the advisory card or osv.dev), severity badge, CVSS score if present, summary (escaped via `escapeHtml`).
4. Summary header: count of vulnerable servers and total advisories.
5. If advisories are not yet loaded, load them lazily before rendering.

## Acceptance Criteria
- [ ] Pasting a config containing a known vulnerable package shows ≥1 advisory ID and its severity/CVSS.
- [ ] All dynamic text passes through `escapeHtml` (no XSS).
- [ ] Still 100% client-side; no new network calls except same-origin `data/` files.
- [ ] `node -c docs/app.js`; `.venv/bin/pytest -q` no regressions.

## Constraints
Minimal diff; reuse existing badge classes. Non-interactive completion.
