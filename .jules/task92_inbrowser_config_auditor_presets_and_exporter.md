# Task 92: In-Browser Config Auditor Sample Presets & Report Exporter (P1)

**Subsystem:** Client-Side Auditing (`docs/index.html`, `docs/app.js`, `docs/style.css`)  
**Priority:** `P1`  
**Parent Plan:** [IMPLEMENTATION_PLAN_WAVE18_WEB_VIEW_ENHANCEMENTS.md](IMPLEMENTATION_PLAN_WAVE18_WEB_VIEW_ENHANCEMENTS.md)

---

## 1. Objective & Problem Statement
Currently on Tab 3 ("🛡️ Audit My MCP Setup"), users must drag or paste their own client configuration file to see the auditor in action. Adding 1-click sample presets allows security evaluators to immediately experience the CVE cross-matching, CVSS scoring, and auto-remediation features. Furthermore, users currently only have a "Copy Pinned Config" button; adding downloadable report exporters (`.json` and `.md`) makes the tool indispensable for security compliance reporting.

---

## 2. Detailed Technical Requirements

### 2.1 One-Click Sample Presets (`docs/index.html` & `docs/app.js`)
1. In `docs/index.html` inside `#config-audit-zone` (directly above or below the dropzone area), add a styled preset button row:
   ```html
   <div class="audit-presets-container">
     <span class="presets-label">⚡ Try an example config:</span>
     <button type="button" class="btn-preset" data-preset="claude">Claude Desktop (Vulnerable Tools)</button>
     <button type="button" class="btn-preset" data-preset="cursor">Cursor AI (Mixed Stdio & Remote)</button>
     <button type="button" class="btn-preset" data-preset="clean">Clean / Secured Config</button>
   </div>
   ```
2. In `docs/app.js`, define realistic preset configuration payloads:
   - **`claude`**: Contains vulnerable servers (e.g. `5ire`, `1Panel`, `@aborruso/ckan-mcp-server`) with pinned vulnerable versions.
   - **`cursor`**: Contains mixed servers (`mcpServers` with remote endpoints and local packages).
   - **`clean`**: Contains popular non-vulnerable servers pinned to safe releases.
3. Clicking a preset button loads the JSON into the auditor, triggers `auditConfigContent()`, and renders the complete posture report.

### 2.2 Downloadable Remediation & Audit Report Exporters (`docs/app.js`)
1. In the audit results toolbar (alongside the existing "Copy Pinned Config" button), add:
   - `<button id="btn-download-config" class="btn btn-secondary">💾 Download Fixed Config (.json)</button>`
   - `<button id="btn-export-report-md" class="btn btn-secondary">📄 Export Markdown Audit Report</button>`
2. Implement file download helper using `Blob` and `URL.createObjectURL`:
   - `btn-download-config`: Downloads `<client>_config_fixed.json`.
   - `btn-export-report-md`: Generates a structured Markdown security audit report containing:
     * Header: Timestamp, Client format, Total servers analyzed, Total vulnerable, Total CVEs.
     * Table of Vulnerable Servers: Package name, Installed version, CVE ID, CVSS score, Recommended safe version, and remediation diff.

---

## 3. Acceptance Criteria
- [ ] 3 preset buttons render cleanly above/below the dropzone.
- [ ] Clicking any preset executes instant parsing and renders the expected posture report.
- [ ] Clicking "Download Fixed Config" triggers browser download of clean JSON.
- [ ] Clicking "Export Markdown Audit Report" triggers browser download of `.md` security report.
- [ ] 100% in-browser memory execution; zero external network requests or beacons.
- [ ] `node -c docs/app.js` passes with zero syntax errors.

---

## 4. Operational Directives
- **Non-Interactive Completion Directive:** Complete implementation autonomously.
- **Privacy Assurance:** Retain strict client-side isolation (no data leakage).
