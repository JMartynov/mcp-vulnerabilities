# Task 76: Updates Portal Polish, Historical Sparkline & Syndication Feeds (P1)

## 1. Architectural Context & Technical Objective

The What's New & Sync Updates portal (`docs/updates.html`) provides transparency on changes between daily snapshot runs. However, the current implementation has several UX limitations:
1. **No Change-Type Filtering:** Users only have a single `[ ] Has Tools Only` checkbox; there is no way to filter specifically for **Patched Versions Available** (actionable fixes) or **Newly Disclosed Vulnerabilities** (urgent alerts).
2. **Missing Historical Velocity Visualization:** `docs/data/updates/updates_history.json` contains time-series telemetry across 11 releases (v1.0.0 through v1.0.10), but neither page visualizes the growth trends of new advisories, patched servers, or new packages.
3. **Hidden Syndication Feeds:** The backend produces authoritative `data/feed.atom` and `data/feed.json` feeds, but neither web page links to them.
4. **No Toolset Delta Comparison:** When a server is updated from a vulnerable release to a patched release, users cannot see which specific tools or parameters changed.

This task adds change-type filter chips, an SVG historical velocity trendline, syndication feed buttons, and toolset delta diffs to `docs/updates.html`.

---

## 2. Target Files & Isolation Boundaries
- Scope: `docs/updates.html`, `docs/updates.js`, `docs/style.css`
- Deliverable: Change-type filter chips, SVG release sparkline, Atom/JSON feed subscription buttons, and toolset delta diff inspector.

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Change-Type Filter Chips
- **Preconditions**: Load release update delta servers in `docs/updates.html`.
- **Invariants**:
  - [x] **INVARIANT_1A (Filter Chips)**: Provide interactive filter chips:
    - `All Updates`
    - `🟢 Patched Versions Available (Actionable Upgrades)`
    - `🔴 New Security Vulnerabilities (New Threats)`
    - `🆕 Newly Tracked Servers`
  - [x] **INVARIANT_1B (Live Dynamic Counts)**: Display dynamic counts on each chip reflecting the active release delta.

### Scenario 2: Historical Velocity Sparkline & Feed Syndication
- **Preconditions**: Fetch `docs/data/updates/updates_history.json`.
- **Invariants**:
  - [x] **INVARIANT_2A (SVG Sparkline)**: Render a lightweight, responsive SVG sparkline/timeline displaying advisory growth and patch velocity over time.
  - [x] **INVARIANT_2B (Syndication Buttons)**: Add prominent `📡 Atom Feed` and `💾 JSON Feed` buttons in the header and footer linking to `data/feed.atom` and `data/feed.json`.

### Scenario 3: Toolset Delta Comparison in Modal
- **Preconditions**: Inspect an updated server with multiple versions in `#server-modal`.
- **Invariants**:
  - [x] **INVARIANT_3A (Tool Diffs)**: Highlight tools added in green (`+ tool_name`) and deprecated/removed tools in red (`- tool_name`).
  - [x] **INVARIANT_3B (Fingerprint Evolution)**: Display fingerprint transition: `sha256:old... ➔ sha256:new...`.

---

---

## 4. Execution Directives & Non-Interactive Completion
- **Non-Interactive Completion Directive**: Implement the required changes directly, ensure all acceptance criteria and invariants are satisfied, run relevant local tests to confirm pass, and finalize directly without asking open-ended questions so the remote VM cleanly transitions to Completed.
- **Heavy Dataset Guard**: Do NOT execute full dataset compilation or multi-megabyte builds (passports.json.gz). Use test mocks/fixtures.
- **Documentation Parity**: Keep comments, type annotations, and docstrings intact.
