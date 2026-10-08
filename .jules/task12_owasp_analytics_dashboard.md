### Task: OWASP MCP Top 10 & CWE Analytics Dashboard

#### 1. Architectural Context & Purpose:
The repository houses 519+ curated MCP security advisories. Currently, the Web Explorer in `docs/` only displays individual advisory search cards. Security leadership and researchers lack high-level analytical visibility into the broader threat landscape:
* Which MCP tools are most frequently exploited (e.g. `cypher_query`, `write_file`, `execute_command`)?
* What is the breakdown across OWASP MCP Top 10 categories (`MCP01 — Tool Poisoning`, `MCP02 — Context Injection`, etc.)?
* What is the ecosystem vulnerability distribution (npm vs PyPI vs Go vs crates.io)?

Adding a dedicated static analytics view (`docs/analytics.html`) powered by pre-compiled metrics from `site_builder.py` delivers visual intelligence for researchers.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/site_builder.py`: Generates static datasets.
* `docs/index.html`: Main navigation.
* `docs/app.js`: Client data loader.

#### 3. Implementation Details:
1. In `src/mcp_vulnerabilities/site_builder.py`:
   - Compute aggregate distributions:
     * Top 10 vulnerable tools with count and average CVSS score.
     * OWASP MCP category breakdown with percentage and severity spread.
     * Ecosystem distribution.
   - Export to `docs/data/analytics.json`.
2. Create `docs/analytics.html`:
   - Responsive dashboard featuring CSS bar charts and metric KPI cards.
   - Zero external chart dependencies (pure SVG/CSS flexbox charts for fast load and offline capability).
3. Link `analytics.html` in the header navigation of `docs/index.html`.

#### 4. Acceptance Criteria:
- [ ] `site_builder.py` exports `docs/data/analytics.json` with tool and category counts.
- [ ] `docs/analytics.html` renders top vulnerable tools and OWASP breakdown accurately.
- [ ] Unit test in `tests/test_site_builder.py` asserts analytics metric calculations.
