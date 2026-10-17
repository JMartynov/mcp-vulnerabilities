# Task 49: Searchable MCP Security Explorer with Interactive Version Switcher & Remediation UI (P0)

## 1. Architectural Context & Technical Objective
Users navigating the MCP Security Explorer require an intuitive, interactive tool to assess MCP server risks. The user must be able to:
1. Search and filter across all known MCP servers that have identified security issues.
2. Select any MCP server and view its full problem breakdown (vulnerabilities, CVE/GHSA IDs, severity ratings, descriptions, OWASP categories).
3. **Switch between different versions** of the server dynamically using an interactive version picker (dropdown or chip selector).
4. Instantly see visual feedback for the selected version: whether that specific version is vulnerable or clean/safe.
5. Receive **actionable remediation guidance**: clearly displaying which safe version to update to and offering a one-click copyable upgrade command to fix the issue.

---

## 2. Target Files & Documentation
- `docs/index.html` (Markup for version switcher and remediation card)
- `docs/app.js` (State management, version switcher event handlers, remediation renderer)
- `docs/style.css` (Visual styling for version picker, status badges, and remediation callout)
- `tests/test_web_ui.py` (End-to-end / DOM / script unit tests)
- `docs/web_portal_user_guide.md`
- `docs/tasks/README.md`

---

## 3. Acceptance Scenarios & Criteria

### Scenario 1: Searchable MCP Server Catalog
- [x] GIVEN the user loads the Security Explorer
- [x] WHEN typing into the search input (e.g. server name, tool name, CVE ID, or keyword)
- [x] THEN the list filters in real time (< 50ms latency) showing matching MCP servers with identified issues.
- [x] AND an active filter button allows toggling between "All Servers", "Vulnerable Only", and "Servers with Available Fixes".

### Scenario 2: Interactive Version Switcher
- [x] GIVEN an MCP server card with multiple released versions (e.g. `v0.1.0`, `v0.2.0`, `v1.0.0`)
- [x] WHEN the user clicks the version switcher dropdown or version pill
- [x] THEN the card dynamically updates in place without a full page reload
- [x] AND reflects the selected version's exact security posture.

### Scenario 3: Real-Time Version Posture Feedback
- [x] GIVEN the user switches to a version known to have vulnerabilities
- [x] THEN the UI displays a warning/critical badge, lists the active CVE/GHSA advisories, and outlines the specific problem description.
- [x] GIVEN the user switches to a version that is NOT vulnerable (safe release)
- [x] THEN the UI switches to a green "Clean / Unaffected" badge, confirming that this version does not suffer from the selected issues.

### Scenario 4: Prominent Remediation Guidance ("Which Version to Update To")
- [x] GIVEN a server displayed in a vulnerable version state
- [x] WHEN viewing the card
- [x] THEN a highlighted **Remediation Box** is rendered stating:
  - "⚠️ Remediation: Update to version **X.Y.Z** or higher to resolve this issue."
  - A copyable terminal snippet (e.g., `npm install <server>@^X.Y.Z` or `pip install <server>>=X.Y.Z`) with a one-click "Copy Command" button.
- [x] GIVEN a vulnerability with no upstream fix yet published
- [x] THEN the UI clearly states "No fixed version available upstream yet" and displays recommended mitigations or sandbox isolation rules.

### Scenario 5: Accessibility, Responsiveness & Deep Linking
- [x] GIVEN users on desktop or mobile viewports
- [x] THEN the layout adapts responsively with touch-friendly version controls.
- [x] AND URL query parameters (e.g. `?server=mcp-server-git&version=0.1.2`) support direct deep-linking to a specific server and version.

---

## 4. Implementation Steps
- [x] 1. Update `docs/index.html` structure to include version selector elements and remediation container in server card template.
- [x] 2. Update `docs/style.css` with styling for:
  - `.version-selector` dropdown / pill list
  - `.remediation-box` with distinct accent styling (green/amber border, code block, copy button)
  - Safe vs vulnerable state badges (`.badge-safe`, `.badge-vuln`).
- [x] 3. Update `docs/app.js`:
  - Enhance server rendering function to populate the version switcher from server metadata.
  - Implement version change listener updating card status and vulnerability details dynamically.
  - Implement one-click "Copy Command" utility with visual tooltip feedback.
  - Add URL hash/query param synchronization for deep-linking.
- [x] 4. Add test coverage in `tests/test_web_ui.py` validating that data payloads, version keys, and remediation instructions render properly.
