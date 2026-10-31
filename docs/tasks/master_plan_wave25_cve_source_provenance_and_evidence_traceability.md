# Master Implementation Plan: Wave 25 — Authoritative CVE Source Provenance, Upstream Evidence Traceability & Cross-Platform Linking (Task 141)

## 1. Executive Summary & Provenance Mandate

The **Wave 25 Architecture** focuses on **Authoritative Upstream Traceability & Source Provenance**.

In previous waves (Waves 1–24), `mcp-vulnerabilities` built extensive discovery pipelines, dynamic risk tiers, AST reachability analysis, reverse proxy interceptors, and 17-client workstation auditors. However, when vulnerabilities were presented to end users and automated consumers (across `docs/app.js`, `docs/updates.js`, and the CLI suite), the link between an advisory and its authoritative upstream source of truth remained fragile or incomplete:

1. **Aggregator Single-Hop Fallback**: Most components previously displayed plain text badges or routed exclusively through `osv.dev` as a generic aggregator, omitting direct clickable access to the primary **CVE Numbering Authority (CVE.org)**, the **National Vulnerability Database (NVD / NIST)**, or the **GitHub Advisory Database (GHSA)**.
2. **Upstream Evidence Discard**: Rich advisory metadata—including vendor advisories, bug reports, pull requests, commit diffs, and Zero Day Initiative (ZDI) bulletins—were dropped or truncated (e.g. `f.references[0]` in CLI).
3. **Multi-Surface Inconsistency**: Modals, dropzones, update feeds, and CLI commands provided inconsistent levels of provenance detail.

**Wave 25** establishes absolute provenance parity across the entire ecosystem:
- **Task 141 (`P0`)**: CVE Source Provenance URLs in Web Portal and CLI.

---

## 2. Work Breakdown Structure & Specification Matrix

| Task ID | Task Title | Priority | Subsystem & Target Files | Contract Specification |
| :---: | :--- | :---: | :--- | :--- |
| **Task 141** | **CVE Source Provenance URLs in Web Portal and CLI** | `P0` | Web Portal & Security CLI (`docs/app.js`, `docs/updates.js`, `docs/index.html`, `docs/updates.html`, `src/mcp_vulnerabilities/`) | [`task141_cve_source_provenance_urls_web_and_cli.md`](task141_cve_source_provenance_urls_web_and_cli.md) |

---

## 3. System Architecture & End-to-End Provenance Flow

```mermaid
flowchart TD
    subgraph DataModel["Advisory Ingestion & Data Model"]
        OSV["OSV Advisory JSON\n(id, aliases, references, affected)"]
        Resolver["Provenance Resolution Engine\n(resolve_provenance_urls / resolveAdvisorySourceUrls)"]
        OSV --> Resolver
    end

    subgraph Authorities["Authoritative Origin Registries"]
        CVE["CVE.org Official Record\nhttps://www.cve.org/CVERecord?id={id}"]
        NVD["NIST NVD Details\nhttps://nvd.nist.gov/vuln/detail/{id}"]
        GHSA["GitHub Security Advisory\nhttps://github.com/advisories/{id}"]
        OSVDev["OSV Open Aggregator\nhttps://osv.dev/vulnerability/{id}"]
        Upstream["Upstream Evidence & Fixes\n(Vendor Bulletins, Commits, PRs, ZDI)"]
    end

    Resolver --> CVE
    Resolver --> NVD
    Resolver --> GHSA
    Resolver --> OSVDev
    Resolver --> Upstream

    subgraph WebSurface["Web Portal Interfaces (docs/)"]
        ServerModal["#server-modal (Deep-Dive Version Matrix)"]
        ConfigDrop["#drop-zone (In-Browser Config Auditor)"]
        AdvisoryFeed["Advisory Explorer Cards & Updates Portal"]
        AdvisoryModal["Advisory Inspector Modal"]
        
        CVE -.-> ServerModal
        NVD -.-> ServerModal
        GHSA -.-> ServerModal
        OSVDev -.-> ServerModal
        Upstream -.-> ServerModal

        CVE -.-> ConfigDrop
        NVD -.-> ConfigDrop
        GHSA -.-> ConfigDrop
        OSVDev -.-> ConfigDrop

        CVE -.-> AdvisoryFeed
        GHSA -.-> AdvisoryFeed
        
        CVE -.-> AdvisoryModal
        NVD -.-> AdvisoryModal
        GHSA -.-> AdvisoryModal
        OSVDev -.-> AdvisoryModal
        Upstream -.-> AdvisoryModal
    end

    subgraph CLISurface["Security CLI Suite (mcp-vuln)"]
        CLIAudit["mcp-vuln audit (Text, JSON, SARIF)"]
        CLISearch["mcp-vuln search"]
        CLILookup["mcp-vuln lookup"]
        CLIHub["mcp-vuln hub (Interactive Cockpit)"]

        CVE -.-> CLIAudit
        NVD -.-> CLIAudit
        GHSA -.-> CLIAudit
        OSVDev -.-> CLIAudit
        Upstream -.-> CLIAudit

        CVE -.-> CLISearch
        CVE -.-> CLILookup
        CVE -.-> CLIHub
    end
```

---

## 4. Verification & Quality Gates

Wave 25 enforces five invariants (`INVARIANT_141_1` through `INVARIANT_141_5`):
1. **Deterministic URL Resolution**: Direct mappings to CVE.org, NVD, GHSA, and OSV.
2. **Web Surface Parity**: Clickable links on all five web surfaces.
3. **Exhaustive Upstream Reference Preservation**: Zero truncation of reference lists.
4. **CLI Terminal Usability**: Terminal formatting with copyable/clickable URLs.
5. **Safe DOM Sanitization**: Strict protocol allowlist (`https://`, `http://`) and `escapeHtml()`.
