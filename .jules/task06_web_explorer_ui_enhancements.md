### Task: Web Explorer UI Enhancement for OSV 1.6 Extensions

#### 1. Overview & Context:
The GitHub Pages Web Explorer in `docs/` currently displays standard vulnerability metadata, but omits the OSV 1.6 MCP security extensions: **vulnerable tools** (e.g. `cypher_query`), **OWASP MCP Top 10 categories** (e.g. `MCP01 — Tool Poisoning`), and **remediation guidance**.

#### 2. Codebase References:
* `docs/app.js`:
  * Lines 52–74: Severity and scoring logic.
  * Lines 210–260: Modal rendering function `showModal()`.
* `docs/index.html`: Modal DOM markup.
* `docs/style.css`: Modal styling.
* `src/mcp_vulnerabilities/site_builder.py`: Static data compiler (`docs/data/vulnerabilities.json`).

#### 3. Implementation Details:
1. In `src/mcp_vulnerabilities/site_builder.py`:
   - Ensure `database_specific` fields (`vulnerable_tools`, `owasp_mcp_category`, `remediation_guidance`, `cvss_score`) are serialized into the exported static JSON.
2. In `docs/app.js`:
   - In `showModal(adv)`:
     - Render "Vulnerable MCP Tools" chip group if `vulnerable_tools` is present.
     - Render "OWASP MCP Category" badge.
     - Render "Actionable Remediation Guidance" alert box.
3. In `docs/style.css`:
   - Add styling for tool chips (`.mcp-tool-tag`), OWASP category badge, and remediation callout box.

#### 4. Strict Guardrails:
- Pure vanilla HTML/CSS/JS; zero external CDN frameworks.
- Advisories lacking MCP extensions must degrade gracefully without blank or broken UI boxes.

#### 5. Acceptance Criteria & Tests:
* [ ] Clicking an advisory card in the Web Explorer modal shows vulnerable tools and OWASP category if present.
* [ ] Remediation guidance renders in an alert callout box.
* [ ] Unit test in `tests/test_site_builder.py` asserts that `site_builder.py` serializes all MCP extension fields into `docs/data/vulnerabilities.json`.
* [ ] All tests pass with `pytest`.
