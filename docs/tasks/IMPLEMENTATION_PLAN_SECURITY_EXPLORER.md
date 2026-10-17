# Implementation Plan: MCP Security Explorer & GitHub Pages Live Deployment

## 1. Executive Summary
This implementation plan organizes the enhancement of the MCP Vulnerabilities project into three discrete, testable, and independent engineering tasks. Together, they resolve the broken public web deployment, build the automated version/remediation metadata engine, and deliver an interactive web Security Explorer that allows users to switch between MCP server versions and see how to upgrade to a safe release.

---

## 2. Engineering Tasks & Board Cards

| Task ID | Title | Key Deliverables | Status | Task Card Link |
| :---: | :--- | :--- | :---: | :---: |
| **Task 47** | **GitHub Pages Deployment & Live Web Portal / Feed Reference Fix** | `.github/workflows/pages.yml`, relative path audit, HTTP 200 verification for live portal & feed | `Pending` | [task47_github_pages_live_portal_feed_fix.md](task47_github_pages_live_portal_feed_fix.md) |
| **Task 48** | **MCP Server Multi-Version Vulnerability & Remediation Metadata Pipeline** | SemVer sorting, per-version OSV evaluation, `recommended_version` computation, upgrade command generation | `Pending` | [task48_version_remediation_metadata_pipeline.md](task48_version_remediation_metadata_pipeline.md) |
| **Task 49** | **Searchable MCP Security Explorer with Interactive Version Switcher & Remediation UI** | Instant search, interactive version switcher, dynamic safe vs vulnerable feedback, remediation action card | `Pending` | [task49_security_explorer_version_switcher_remediation_ui.md](task49_security_explorer_version_switcher_remediation_ui.md) |

---

## 3. Detailed Implementation Plan & Checklists

### Phase 1: Task 47 — Fix Live Web Portal & Feed References
- [ ] **1.1. Create GitHub Pages Deployment Workflow**
  - [ ] Add `.github/workflows/pages.yml` with `workflow_dispatch` and `push: branches: [main]`.
  - [ ] Configure `actions/configure-pages@v5`, `actions/upload-pages-artifact@v3` (`path: docs`), and `actions/deploy-pages@v4`.
  - [ ] Grant necessary job permissions: `contents: read`, `pages: write`, `id-token: write`.
- [ ] **1.2. Audit Relative Paths in Frontend Assets**
  - [ ] Inspect `docs/index.html` and `docs/updates.html` for root-relative links (`/data/` vs `./data/` or `data/`).
  - [ ] Verify `docs/app.js` and `docs/updates.js` fetch paths work under both local preview (`localhost:8000/`) and GitHub Pages base path (`/mcp-vulnerabilities/`).
- [ ] **1.3. End-to-End Verification**
  - [ ] Verify static server locally (`python3 -m http.server 8080 --directory docs`).
  - [ ] Verify both `index.html` (portal) and `updates.html` (feed) load cleanly without 404 console errors.

---

### Phase 2: Task 48 — Ingestion & Remediation Metadata Pipeline
- [ ] **2.1. Multi-Version Data Model**
  - [ ] Extend `src/mcp_vulnerabilities/fingerprints/correlator.py` to capture complete released version lists per server.
  - [ ] Integrate SemVer sorting so versions are ordered chronologically and hierarchically.
- [ ] **2.2. Version Vulnerability Correlator**
  - [ ] Evaluate each released version against OSV affected ranges (`introduced`, `fixed`).
  - [ ] Map each version to an explicit security posture: `is_vulnerable: bool`, `advisories: list[str]`, `severity: str`.
- [ ] **2.3. Remediation Target Calculation**
  - [ ] Compute `recommended_version`: lowest safe version `>= current_version`, or latest secure release.
  - [ ] Generate package-manager specific upgrade command (`npm install ...`, `pip install ...`, `docker pull ...`).
  - [ ] Support unpatched/zero-day cases where no fix is currently available (`no_fix_available: true`).
- [ ] **2.4. Data Artifact Serialization & Sharding**
  - [ ] Update `src/mcp_vulnerabilities/site_builder.py` to export version matrices and remediation objects to `docs/data/`.
  - [ ] Add automated tests in `tests/test_version_remediation_pipeline.py`.

---

### Phase 3: Task 49 — Interactive Security Explorer UI
- [ ] **3.1. Directory Search & Filters**
  - [ ] Fast, real-time client-side search across server name, tool name, CVE ID, and keywords in `docs/app.js`.
  - [ ] Status filters: "All Servers", "Vulnerable Only", "Has Remediation Patch".
- [ ] **3.2. Interactive Version Switcher**
  - [ ] Render a version selector dropdown or pill group on each server card.
  - [ ] Attach `change` listener to update server card state in-place without page reloading.
- [ ] **3.3. Dynamic Safe vs. Vulnerable Visual Posture**
  - [ ] Display red/amber warning badges and detailed problem breakdown when viewing a vulnerable version.
  - [ ] Display green "Clean / Unaffected" badge when viewing a safe version.
- [ ] **3.4. Remediation Card & Copy Command**
  - [ ] Render prominent remediation box stating target safe version to update to.
  - [ ] Provide one-click "Copy Upgrade Command" button with tooltip confirmation.
- [ ] **3.5. Styling & Accessibility**
  - [ ] Refine responsive CSS in `docs/style.css` matching modern dark/light themes.
  - [ ] Add unit and DOM tests in `tests/test_web_ui.py`.

---

## 4. Acceptance Criteria & Quality Gates
- **Zero Broken Links:** Both `https://jmartynov.github.io/mcp-vulnerabilities/` and `https://jmartynov.github.io/mcp-vulnerabilities/updates.html` return HTTP 200.
- **Accurate Version Switching:** Changing version accurately reflects whether that version has CVEs.
- **Actionable Remediation:** Every vulnerable server displays the precise version to update to and the command to run.
- **Full Test Suite Passing:** All new and existing pytest tests pass 100%.
