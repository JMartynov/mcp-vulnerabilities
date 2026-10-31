# Task 102: Web Cross-Server Tool Collision Warning Banner (P0)

**Subsystem:** Safety Analyzer (`docs/app.js`, `docs/updates.js`, `docs/index.html`, `docs/style.css`)  
**Priority:** `P0`  
**Parent Plan:** [master_plan_wave20_mcp_fingerprints_capability_adoption.md](master_plan_wave20_mcp_fingerprints_capability_adoption.md)

---

## 1. Objective & Problem Statement

In the Model Context Protocol specification, AI client runtime environments (such as Claude Desktop, Cursor, or Zed) aggregate all tools declared across configured servers into a flat namespace. When a user configures multiple MCP servers that export identical tool names (e.g. two filesystem servers exporting `read_file`, or multiple command runners exporting `execute_command`), the AI client exhibits non-deterministic tool dispatch, prompt injection confusion, or silent shadowing where one server overrides another without warning.

This task integrates a real-time **Cross-Server Tool Collision Analyzer** into the configuration workflow:
1. Analyzes the tool signatures of all servers selected in the Configuration Basket (`configBasket`).
2. Detects overlapping tool names across the selected servers.
3. Renders a prominent, high-visibility warning banner inside the `#configModal` detailing the exact colliding tool names and the specific servers contributing to each collision, with recommended namespacing remedies.

---

## 2. Detailed Technical Requirements

### 2.1 Tool Collision Detection Algorithm (`docs/app.js` & `docs/updates.js`)
1. Implement `detectCollisions(selectedServers)`:
   ```javascript
   function detectCollisions(servers) {
     const toolToServers = new Map(); // toolName -> Set<packageName>
     
     for (const server of servers) {
       // Check tools_sample from catalog index or full tools from loaded shard cache
       const tools = server.tools_sample || (server.tools ? server.tools.map(t => typeof t === "string" ? t : t.name) : []);
       for (const tool of tools) {
         if (!tool) continue;
         const cleanName = tool.trim();
         if (!toolToServers.has(cleanName)) {
           toolToServers.set(cleanName, new Set());
         }
         toolToServers.get(cleanName).add(server.package_name || server.display_name);
       }
     }

     const collisions = [];
     for (const [toolName, serverSet] of toolToServers.entries()) {
       if (serverSet.size > 1) {
         collisions.push({
           tool: toolName,
           servers: Array.from(serverSet)
         });
       }
     }
     return collisions;
   }
   ```
2. Sort detected collisions alphabetically by tool name for predictable display.
3. If a selected server has on-demand shard data cached (`shardCache[server.shard_file]`), inspect the full toolset of its representative/recommended safe version rather than only `tools_sample` (5 tools), ensuring comprehensive collision detection for large toolsets.

### 2.2 Collision Warning Alert UI (`docs/index.html` & `docs/app.js`)
1. In `#configModal`, inject container `#configCollisionBanner`:
   ```html
   <div id="configCollisionBanner" class="alert-banner alert-warning" role="alert" style="display: none;">
     <div class="alert-icon">⚠️</div>
     <div class="alert-content">
       <h4 class="alert-title" id="collisionTitle">Cross-Server Tool Collisions Detected</h4>
       <p class="alert-desc" id="collisionDesc"></p>
       <div class="collision-list" id="collisionList"></div>
       <div class="alert-remedy">
         💡 <strong>Remediation:</strong> Rename duplicate tools, namespace prefixes, or use <code>mcp-vuln resolve-config --strategy prefix</code> to auto-namespace conflicting tools before loading into AI clients.
       </div>
     </div>
   </div>
   <div id="configNoCollisionBanner" class="alert-banner alert-success" style="display: none;">
     <span>✅ <strong>Zero Collisions:</strong> All selected servers export unique tool namespaces.</span>
   </div>
   ```
2. When `#configModal` opens or when basket items change:
   - Call `detectCollisions(Array.from(configBasket.values()))`.
   - If collisions exist:
     * Hide `#configNoCollisionBanner`.
     * Show `#configCollisionBanner`.
     * Populate `#collisionList` with badges showing `<span class="collision-tool">tool_name</span> exported by <span class="collision-pkg">pkg_a</span> and <span class="collision-pkg">pkg_b</span>`.
   - If zero collisions and `configBasket.size > 1`:
     * Hide `#configCollisionBanner`.
     * Show `#configNoCollisionBanner`.
   - If only 1 server selected:
     * Hide both banners (collisions require at least 2 servers).

### 2.3 Visual Styling (`docs/style.css`)
1. Style `.alert-banner`:
   - Rounded border (`border-radius: 8px`), padding `1rem`, margin-bottom `1.25rem`.
   - `.alert-warning`: Amber border & background (`border: 1px solid #f59e0b; background: rgba(245, 158, 11, 0.1); color: #fbbf24`).
   - `.alert-success`: Emerald border & background (`border: 1px solid #10b981; background: rgba(16, 185, 129, 0.1); color: #34d399`).
2. Style `.collision-list`:
   - Max height `160px`, overflow-y `auto`, custom dark scrollbar.
   - List items with monospace tool tags and subtle badge borders.

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_102_1 (Deterministic Collision Detection):** When selecting two servers that both export `read_file` (e.g. `@modelcontextprotocol/server-filesystem` and a third-party filesystem tool), `detectCollisions()` returns exactly 1 collision for `read_file` with both package names.
- [ ] **INVARIANT_102_2 (No False Positives on Unique Toolsets):** Selecting servers with completely disjoint toolsets (e.g. `server-postgres` and `server-github`) triggers `#configNoCollisionBanner` with zero warning alerts.
- [ ] **INVARIANT_102_3 (Single Server Invariant):** Selecting a single server displays neither banner.
- [ ] **INVARIANT_102_4 (Full Shard Cache Inspection):** If full shard data is available in memory for any selected server, all 40+ tools are evaluated, not just the initial 5-tool sample.
- [ ] **INVARIANT_102_5 (Syntax & Console Cleanliness):** `node -c docs/app.js && node -c docs/updates.js` passes without syntax errors.

---

## 4. Deliverables

1. `docs/app.js` & `docs/updates.js`: Implemented `detectCollisions()` algorithm, dynamic banner population, and shard toolset expansion.
2. `docs/index.html` & `docs/updates.html`: Collision alert banner markup inside `#configModal`.
3. `docs/style.css`: Alert banner, collision tag, and monospace list styling.
