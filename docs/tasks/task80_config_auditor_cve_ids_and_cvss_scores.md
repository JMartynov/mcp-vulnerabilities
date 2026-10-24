# Task 80: In-Browser Config Auditor CVE IDs, CVSS Scores & Posture Report Enrichment (P0)

**Defect Reference:** `DEFECT-W14-03` ([`docs/reports/code_review_wave14_portal_and_analytics.md`](../reports/code_review_wave14_portal_and_analytics.md))  
**Target Wave:** Wave 15A (Wave 14 Code Review Remediation)  
**Priority:** `P0` (Missing Acceptance Deliverable Fix)

---

## 1. Architectural Context & Technical Objective

Task 77 Scenario 2 (`INVARIANT_2B`) specifies that the in-browser Config Auditor posture report must display:
> *"Number of vulnerable servers with CVE IDs, CVSS scores, and recommended safe versions."*

Currently, `auditConfigContent()` and `renderAuditResults()` in `docs/app.js` (~lines 370–575) only match against `catalogIndex` and output generic text:
```html
<p>Found <strong>${escapeHtml(res.parsedPackage)}</strong> which has known vulnerabilities.</p>
```
Because it never cross-references `allAdvisories` (already loaded in memory from `docs/data/vulnerabilities.json`), users auditing their MCP configurations are never shown **which CVE/GHSA advisories** affect their server, **what the CVSS scores or severity tiers are**, or **what the advisory summaries describe**. Furthermore, if a user has already pinned their configuration to the `recommended_safe_version` (or a version >= the fixed version), `auditConfigContent()` currently still flags it as vulnerable if `matchedServer.is_vulnerable` is `true` at the package level.

This task enriches `auditConfigContent()` and `renderAuditResults()` in `docs/app.js` (and styles in `docs/style.css`) to cross-reference `allAdvisories`, evaluate pinned versions against `recommended_safe_version` / advisory fixed versions, and render structured CVE ID badges, CVSS scores, severity tiers, and escaped summaries in the posture report.

---

## 2. Target Files & Isolation Boundaries

- **Primary Files:**
  - `docs/app.js`
  - `docs/style.css`
- **Constraints:** Maintain 100% client-side, zero-telemetry execution. Sanitize all rendered strings with `escapeHtml()`.

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Advisory Cross-Referencing & Pinned Safe Version Check (`INVARIANT_80_1A`)
- **Preconditions**: `allAdvisories` and `catalogIndex` are loaded in memory; user drops or pastes a client configuration containing a vulnerable MCP package (e.g., `mcp-neo4j-cypher` or `@modelcontextprotocol/server-filesystem`).
- **Invariants**:
  - [ ] **INVARIANT_80_1A (Advisory Matching)**: `findMatchingAdvisoriesForPackage(pkgName, ecosystem, pinnedVersion)` matches `allAdvisories` entries where any `affected[].package.name` matches `pkgName` (case-insensitive, normalizing `_` and `-` for PyPI packages) or matches `matchedServer.package_name`.
  - [ ] **INVARIANT_80_1B (Pinned Version Awareness)**: If the user's config pins a specific `parsed.version` that equals `matchedServer.recommended_safe_version` (or is `>= fixed` in all matched advisories), the server is marked clean (`isVulnerable = false`) rather than falsely flagging an already-remediated pin.
  - [ ] **INVARIANT_80_1C (Advisory Metadata Extraction)**: Each matched advisory object exposes:
    - `id`: Primary advisory ID (e.g. `CVE-2025-10193` or `GHSA-...`, plus any `CVE-*` alias from `adv.aliases`),
    - `severity`: Normalized uppercase severity (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`),
    - `cvss_score`: Numeric CVSS score (from `adv.database_specific?.cvss_score` or `adv.affected?.[0]?.database_specific?.cvss_score`),
    - `summary`: Advisory summary text.

### Scenario 2: Posture Report Rendering with CVE IDs & CVSS Scores (`INVARIANT_80_2A`)
- **Preconditions**: `renderAuditResults()` renders a vulnerable server item in `#audit-results-container`.
- **Invariants**:
  - [ ] **INVARIANT_80_2A (CVE & CVSS Rendering)**: Inside `.audit-server-vuln-info`, render a structured `.audit-cve-list` listing every matched advisory with:
    - Monospace advisory ID badge (and primary CVE alias if the ID is a GHSA),
    - Severity & CVSS badge (e.g. `<span class="badge risk-critical">CRITICAL • CVSS 9.8</span>` or `<span class="badge risk-high">HIGH</span>` when CVSS score is absent),
    - Escaped advisory summary (`escapeHtml(adv.summary)`).
  - [ ] **INVARIANT_80_2B (DOM XSS Immunity)**: All advisory IDs, CVSS scores, summaries, package names, and version strings pass through `escapeHtml()`.

---

## 4. Concrete Implementation Instructions

1. In `docs/app.js`, add helper `findMatchingAdvisoriesForPackage(pkgName, pinnedVersion, safeVersion)`:
   ```javascript
   function normalizePkgName(name) {
     return String(name || "").trim().toLowerCase().replace(/_/g, "-");
   }

   function findMatchingAdvisoriesForPackage(pkgName, pinnedVersion, safeVersion) {
     if (!pkgName || !Array.isArray(allAdvisories)) return [];
     const target = normalizePkgName(pkgName);
     const matched = [];

     for (const adv of allAdvisories) {
       const affectedList = Array.isArray(adv.affected) ? adv.affected : [];
       let pkgMatch = false;
       let dbSpec = adv.database_specific || {};

       for (const aff of affectedList) {
         const affName = normalizePkgName(aff.package?.name);
         if (affName && (affName === target || affName.endsWith("/" + target) || target.endsWith("/" + affName))) {
           pkgMatch = true;
           if (aff.database_specific) dbSpec = { ...dbSpec, ...aff.database_specific };
           break;
         }
       }
       if (!pkgMatch) continue;

       const cveAlias = Array.isArray(adv.aliases) ? adv.aliases.find((a) => String(a).startsWith("CVE-")) : null;
       const displayId = cveAlias && !String(adv.id).startsWith("CVE-") ? `${adv.id} (${cveAlias})` : (adv.id || "UNKNOWN-ADVISORY");
       const severity = String(dbSpec.severity || getSeverity(adv) || "HIGH").toUpperCase();
       const cvss = dbSpec.cvss_score !== undefined && dbSpec.cvss_score !== null ? Number(dbSpec.cvss_score) : null;

       matched.push({
         id: adv.id || "UNKNOWN",
         displayId,
         severity,
         cvssScore: !Number.isNaN(cvss) && cvss !== null ? cvss.toFixed(1) : null,
         summary: adv.summary || "Known MCP vulnerability affecting this package."
       });
     }
     return matched;
   }
   ```
2. In `auditConfigContent()` (`docs/app.js` ~lines 400–430):
   - Check if `parsed?.version && safeVersion && parsed.version === safeVersion`; if so, treat the server as already pinned to the safe version (`isVuln = false`).
   - Call `const advisories = isVuln ? findMatchingAdvisoriesForPackage(matchedServer?.package_name || parsed?.packageName, parsed?.version, safeVersion) : [];` and include `advisories` on each item pushed to `auditResults`.
3. In `renderAuditResults()` (`docs/app.js` ~lines 535–570), render `res.advisories` inside `.audit-server-vuln-info` as `.audit-cve-list` items displaying the ID, severity/CVSS badge (`.badge.risk-${sev.toLowerCase()}`), and summary.
4. Add clean styling for `.audit-cve-list` and `.audit-cve-item` in `docs/style.css`.
5. Validate syntax via `node -c docs/app.js` and run `.venv/bin/pytest -q`.

---

## 5. Non-Interactive Completion Directive

Complete all implementation steps, verify all invariants locally, and commit directly without asking open-ended questions so the session cleanly transitions to `Completed`.
