# Task 74: Cryptographic MCP Fingerprints & Complete Primitives UI Integration (P0)

## 1. Architectural Context & Technical Objective

The `mcp-vulnerabilities` catalog and `mcp-fingerprints` backend maintain rich cryptographic data across 5,820 passports and 6,159 sharded servers:
- Canonical SHA-256 toolset hashes (`toolset_canonical_hash`) and individual tool hashes (`canonical_hash`, `description_hash`)
- Prompts (`prompt_signatures`) and Resources (`resource_signatures`)
- Transport modes (`transport`: `stdio`, `sse`, `stream`), remote endpoints, and authentication schemes
- Declared environment variable requirements (`required_env_vars`)
- Supply chain maintenance health (`is_unpublished`, `http_status: 404`, `archival_reason`)

Currently, the web portals hide 100% of this cryptographic and structural intelligence, presenting MCP servers as if they only consist of tools and descriptions.

This task integrates cryptographic fingerprints, complete MCP primitives, transport boundaries, required environment variables, and supply chain flags into both `docs/index.html` and `docs/updates.html`.

---

## 2. Target Files & Isolation Boundaries
- Scope: `docs/app.js`, `docs/updates.js`, `docs/style.css`, `src/mcp_vulnerabilities/site_builder.py`
- Test Suite: `.venv/bin/pytest tests/test_site_builder.py`
- Deliverable: Fingerprint badges with one-click copy, Prompts & Resources inspection sub-tabs, transport tags, and required environment variables in cards and modals.

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Cryptographic Fingerprints Surfacing
- **Preconditions**: Render server cards and deep-dive inspector modals.
- **Invariants**:
  - [x] **INVARIANT_1A (Card Fingerprint Badge)**: Render a compact cryptographic fingerprint badge: `🔑 sha256:abcd...` with a one-click copy button and copied tooltip notification.
  - [x] **INVARIANT_1B (Modal Contract Panel)**: In `#server-modal`, display the full `toolset_canonical_hash` and verification status (`🛡️ Verified Toolset Contract`).

### Scenario 2: Complete MCP Primitives (Prompts & Resources)
- **Preconditions**: Ingest shards containing `prompts` and `resources`.
- **Invariants**:
  - [x] **INVARIANT_2A (Primitive Counters)**: On cards, display comprehensive primitive tallies: `🔧 N Tools • 📄 N Prompts • 📦 N Resources`.
  - [x] **INVARIANT_2B (Modal Sub-Tabs)**: In `#server-modal`, provide separate sub-tabs for **Tools**, **Prompts**, and **Resources**, rendering prompt argument schemas and resource URI templates.

### Scenario 3: Transport Modes, Required Secrets & Supply Chain Health
- **Preconditions**: Render servers with specific transports (`stdio` vs `sse`), required env vars, or archived status.
- **Invariants**:
  - [x] **INVARIANT_3A (Transport Tag)**: Tag each server card with its transport topology (`🖥️ Local Stdio` vs `🌐 Remote SSE Gateway`).
  - [x] **INVARIANT_3B (Required Env Vars)**: Render required environment variables (`🔑 GITHUB_TOKEN`, etc.) in cards and inspector modals so operators know required secrets prior to installation.
  - [x] **INVARIANT_3C (Supply Chain Health Flag)**: Flag servers whose repositories returned 404 or were archived with a prominent `⚠️ Repo 404 / Archived` badge.
