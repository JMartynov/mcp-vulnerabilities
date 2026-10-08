### Task: Web Explorer UI Enhancement for OSV 1.6 Extensions

#### 1. Architectural Context & Problem Analysis:
The repository serves an interactive, client-side Web Explorer on GitHub Pages from the `docs/` directory (`docs/index.html`, `docs/app.js`, `docs/style.css`).
While the application displays standard vulnerability metadata (ID, summary, CVSS badge, affected package, and external references), it completely omits the **MCP-specific security extensions** standardized in `docs/SPECIFICATION.md`:
1. **Vulnerable MCP Tools** (`database_specific.vulnerable_tools`): e.g. `cypher_query`, `write_file`, `execute_command`.
2. **OWASP MCP Top 10 Category** (`database_specific.owasp_mcp_category`): e.g. `MCP01 — Tool Poisoning & RCE`.
3. **Actionable Remediation Guidance** (`database_specific.remediation_guidance`): specific operational mitigation instructions for developers and autonomous security agents.

Surfacing these fields transforms the static dashboard into a specialized MCP threat intelligence portal.

#### 2. Codebase References:
* `docs/app.js`:
  * Lines 52–74: Severity calculation.
  * Lines 210–260: Modal rendering function `showModal(adv)`.
* `docs/index.html`: Modal DOM container (`#advisory-modal`, `#modal-body`).
* `docs/style.css`: Visual component styling.
* `src/mcp_vulnerabilities/site_builder.py`: Exports `docs/data/vulnerabilities.json`.

#### 3. Engineering & Implementation Blueprint:
1. In `src/mcp_vulnerabilities/site_builder.py`:
   - Ensure the static JSON serializer preserves `database_specific` fields (`vulnerable_tools`, `owasp_mcp_category`, `remediation_guidance`, `cvss_score`, `verity_condition_id`).
2. In `docs/app.js`:
   - Update `showModal(adv)`:
     * **Vulnerable Tools Chip Group**: If `vulnerable_tools` array is present, render badges:
       ```html
       <div class="mcp-tools-section">
         <span class="section-label">Vulnerable Tools:</span>
         <span class="tool-tag">cypher_query</span>
       </div>
       ```
     * **OWASP Category Tag**: Render a category badge (e.g. `MCP01 — Tool Poisoning`).
     * **Remediation Callout Box**: If `remediation_guidance` is present, render an actionable alert block:
       ```html
       <div class="remediation-callout">
         <strong>🛡️ Actionable Remediation:</strong>
         <p>${escapeHtml(remediation)}</p>
       </div>
       ```
3. In `docs/style.css`:
   - Add modern dark-theme styles for `.tool-tag`, `.owasp-badge`, and `.remediation-callout`.

#### 4. Guardrails & UI Invariants:
* **Zero External CDN Dependencies**: Maintain vanilla JavaScript and CSS without introducing heavy external UI frameworks.
* **Graceful Degradation**: For standard CVE/GHSA records lacking MCP extensions, the modal must render cleanly without empty tags, undefined labels, or visual glitches.
* **XSS Defense**: Ensure all text inputs rendered into DOM innerHTML pass through strict HTML entity escaping (`escapeHtml()`).

#### 5. Acceptance Criteria & Test Plan:
- [ ] Clicking an advisory card in the Web Explorer modal displays vulnerable tools and OWASP category if present.
- [ ] Remediation guidance renders in an alert callout box.
- [ ] Legacy advisories lacking MCP extensions degrade gracefully without visual defects.
- [ ] Unit test in `tests/test_site_builder.py` asserts that `site_builder.py` exports `vulnerable_tools`, `owasp_mcp_category`, and `remediation_guidance` into `docs/data/vulnerabilities.json`.
- [ ] All tests pass cleanly (`pytest -v`).
