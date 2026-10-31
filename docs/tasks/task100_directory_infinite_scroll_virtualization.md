# Task 100: Directory Infinite Scroll & DOM Virtualization (P0)

**Subsystem:** Front-End Explorer (`docs/index.html`, `docs/app.js`, `docs/style.css`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave20_mcp_fingerprints_capability_adoption.md](master_plan_wave20_mcp_fingerprints_capability_adoption.md)

---

## 1. Objective & Problem Statement

Currently, `docs/app.js` truncates the directory view using `filteredServers.slice(0, 100)`. In a catalog of over 6,280+ indexed MCP servers, this hard limit makes more than 6,180 servers completely invisible and unreachable unless the user enters an exact keyword or filter. Conversely, removing the slice and rendering all 6,280+ cards simultaneously creates over 150,000 DOM elements, triggering catastrophic browser freezing, memory bloat (500MB+ heap), and mobile browser crashes.

This task implements a high-performance **`IntersectionObserver` Sentinel Batching Virtualization Engine** that dynamically appends batches of 48 cards as the user scrolls, maintaining smooth 60 FPS performance, low memory footprint, and full directory discoverability.

---

## 2. Detailed Technical Requirements

### 2.1 DOM Sentinel & Indicator Structure (`docs/index.html`)
1. In `docs/index.html`, locate `<div class="servers-grid" id="servers-container"></div>` inside Tab 1.
2. Immediately below `#servers-container`, insert:
   ```html
   <div id="scrollSentinel" class="scroll-sentinel" aria-hidden="true"></div>
   <div id="scrollLoadingSpinner" class="scroll-loading-spinner" style="display: none;" role="status">
     <div class="spinner-dot"></div>
     <span>Loading more MCP servers...</span>
   </div>
   ```
3. Ensure the sentinel and spinner do not break the CSS grid layout of `#servers-container` (place them as sibling block elements).

### 2.2 Progressive Batching Engine (`docs/app.js`)
1. Define batching state variables in directory scope:
   ```javascript
   const BATCH_SIZE = 48;
   let currentRenderIndex = 0;
   let directoryObserver = null;
   ```
2. Replace `filteredServers.slice(0, 100)` in `renderDirectoryCards()` with progressive rendering:
   - `renderDirectoryCards()` initiates a new render lifecycle: resets `currentRenderIndex = 0`, clears `el.serversContainer.innerHTML = ""`, updates `#directory-results-count`, and calls `renderNextBatch()`.
   - Implement `renderNextBatch()`:
     - Slices `filteredServers` from `currentRenderIndex` to `currentRenderIndex + BATCH_SIZE`.
     - Generates card HTML strings for that chunk using the existing card template.
     - Appends the chunk using `el.serversContainer.insertAdjacentHTML("beforeend", chunkHtml)`.
     - Increments `currentRenderIndex += BATCH_SIZE`.
     - Shows or hides `#scrollLoadingSpinner` accordingly.
     - If `currentRenderIndex >= filteredServers.length`, disconnects the observer and hides the sentinel.
3. Wire the `IntersectionObserver`:
   - Initialize `directoryObserver = new IntersectionObserver(onSentinelIntersect, { root: null, rootMargin: "300px", threshold: 0.1 });`.
   - `onSentinelIntersect(entries)`: If `entry.isIntersecting` and `currentRenderIndex < filteredServers.length`, trigger `renderNextBatch()`.
   - Re-observe `#scrollSentinel` after each reset or filter change.
4. Convert per-card Inspect button listeners to high-performance **Event Delegation** on `#servers-container`:
   - Listen for `click` events at the container level.
   - Extract `data-pkg` and `data-shard` from `.btn-inspect` targets and dispatch `openServerModal()`.

### 2.3 Visual Styling & Loading UI (`docs/style.css`)
1. Style `.scroll-sentinel`:
   - Height: `20px`, width: `100%`, margin-top: `1rem`, clear: `both`, zero opacity.
2. Style `.scroll-loading-spinner`:
   - Flex container with centered alignment, padding `1.5rem`, color `var(--text-muted)`.
   - Animated spinner dot or pulse ring matching existing dark theme accents (`#38bdf8`, `#818cf8`).

### 2.4 Filter, Search & History State Compatibility
1. Any mutation to `searchTerm`, `statusFilter`, `riskTierFilter`, `ecosystemFilter`, `toolsOnlyFilter`, or `sortSelect` must reset `currentRenderIndex = 0` and re-anchor scroll position to top.
2. Disconnect and re-observe cleanly to prevent zombie callbacks or infinite loops when result sets contain fewer than 48 items.

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_100_1 (Complete Catalog Reachability):** Users can browse past the 100th server down to server 6,280+ without manual filtering by simply scrolling.
- [ ] **INVARIANT_100_2 (Batch Size & Chunking Precision):** Initial page load renders exactly `min(48, filteredServers.length)` cards. Subsequent sentinel triggers render exactly 48 cards per intersection.
- [ ] **INVARIANT_100_3 (Filter Reset & DOM Cleanup):** Typing a search query (e.g. "github") clears the container, resets `currentRenderIndex` to 0, renders the first 48 matches, and disconnects the sentinel if total matches $\le 48$.
- [ ] **INVARIANT_100_4 (Event Delegation Integrity):** Clicking "Inspect Server & Versions" on any dynamically appended card (e.g. card 250) opens `#server-modal` with complete data without memory leaks.
- [ ] **INVARIANT_100_5 (Syntax & Console Cleanliness):** `node -c docs/app.js` passes with zero errors; no uncaught exceptions in browser console.

---

## 4. Deliverables

1. `docs/index.html`: Sentinel and loading spinner elements added below `#servers-container`.
2. `docs/app.js`: Sentinel observer, `renderNextBatch()`, event delegation for card inspection, and filter reset hooks.
3. `docs/style.css`: Responsive CSS styling for sentinel and loading indicator.
