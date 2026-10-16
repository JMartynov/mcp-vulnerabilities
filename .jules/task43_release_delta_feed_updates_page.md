# Task 43: Per-Update Release Delta Feed & Dedicated Updates Web Page (docs/updates.html) (P0)

## 1. Architectural Context & Technical Objective
Generate a per-update release delta feed (`docs/feed.json`, `docs/feed.xml`) and build a dedicated 'Updates & Threat Advisories' web page (`docs/updates.html`). Highlight newly published vulnerabilities, severity changes, and remediation actions for popular MCP servers in a reverse-chronological timeline. Provide RSS/Atom feeds and JSON endpoints for automated security alert consumption by DevSecOps pipelines.

## 2. Target Files & Documentation to Update
- `src/mcp_vulnerabilities/feed.py`
- `docs/updates.html`
- `docs/updates.js`
- `tests/test_feed.py`
- `docs/feed_specification.md`

## 3. EULIS Implementation & Branch Review Workflow
- Branch: `jules/review-task43`
- Implementation PR: `jules-gate pr --skip-ci`
- Offload Mode 2 EULIS Code Review: `jules-gate review-branch`
- Review verification: check `docs/reviews/review_task43.md`
- Test verification: run test suite via isolated subagent (`jules-gate verify`)
- Merge: `jules-gate pr-merge --skip-ci`

## 4. Acceptance & Verification Criteria
- [ ] `FeedGenerator` creates valid RSS 2.0, Atom 1.0, and JSON Feed 1.1 documents.
- [ ] `docs/updates.html` renders interactive timeline of security updates with severity filters.
- [ ] Each feed item contains CVE/GHSA ID, affected server/tool, severity badge, and remediation advice.
- [ ] Feeds are validated for W3C / RSS spec compliance.
- [ ] Unit tests in `tests/test_feed.py` verify feed generation, item formatting, and date parsing.
