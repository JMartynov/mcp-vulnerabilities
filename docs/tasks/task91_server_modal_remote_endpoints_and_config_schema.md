# Task 91: Server Modal Remote Endpoints & Config Schema Panel (P1)

**Subsystem:** Front-End Modal & Security Inspection (`docs/index.html`, `docs/app.js`, `docs/updates.js`, `docs/style.css`)  
**Priority:** `P1`  
**Parent Plan:** [IMPLEMENTATION_PLAN_WAVE18_WEB_VIEW_ENHANCEMENTS.md](IMPLEMENTATION_PLAN_WAVE18_WEB_VIEW_ENHANCEMENTS.md)

---

## 1. Objective & Problem Statement
In `data/passports.json.gz`, over 1,377 server versions specify active connection architectures (`deploymentUrl` for remote `streamable-http` or `sse` gateways, authentication types, and `configSchema` properties). Currently, the `#server-modal` only renders Tools, Prompts, and Resources, leaving remote endpoints and required configuration schemas invisible to developers and security auditors.

---

## 2. Detailed Technical Requirements

### 2.1 Modal Sub-Tab Addition: Endpoints & Config Schema
1. In `docs/index.html` and `docs/updates.html` within `#server-modal .primitive-tabs-nav`, add a 4th sub-tab:
   - `<button class="primitive-tab-btn" data-tab="connections" id="tab-btn-connections">🌐 Endpoints & Schema (<span id="connections-count-label">0</span>)</button>`
2. In the modal body, add `<div id="modal-connections-container" class="primitive-tab-pane" style="display: none;"></div>`.

### 2.2 Connection Card & Schema Rendering (`docs/app.js` & `docs/updates.js`)
1. In `selectVersion(v)`, extract `v.connections || []` (and top-level `server.connections || []` or `remote_endpoint`):
   - Update `connections-count-label`.
   - If empty and `transport === "stdio"`, render an informative local connection card:
     * `🖥️ Local Process Transport (Standard I/O)`
     * Command execution templates for `npx`, `uvx`, or `docker`.
   - If connections exist, render styled cards for each connection:
     * Connection Type Badge: `streamable-http`, `sse`, or `stdio`.
     * Deployment URL: Live clickable endpoint (e.g. `https://.../mcp`) with 1-click copy button.
     * Auth Type: `none`, `bearer`, `api-key`, or `oauth`.
     * Configuration Schema Table: Render parameter names, types, descriptions, and required flags from `configSchema.properties` (e.g., `x-api-key`, `client_id`, `wallet_private_key`).
2. Add security callout:
   - If remote endpoint uses plain `http://` instead of `https://`, display an unencrypted transport warning: `⚠️ Unencrypted HTTP Transport: Risk of credential and prompt interception in transit.`

---

## 3. Acceptance Criteria
- [ ] 4th sub-tab "🌐 Endpoints & Schema" renders in both `index.html` and `updates.html`.
- [ ] Servers with remote connections display deployment URLs and configuration property schemas.
- [ ] Plain HTTP endpoints trigger an unencrypted transport security warning.
- [ ] Switching between modal versions updates the connection count and card view.
- [ ] `node -c docs/app.js` and `node -c docs/updates.js` pass with zero syntax errors.

---

## 4. Operational Directives
- **Non-Interactive Completion Directive:** Execute autonomously to completion.
- **XSS Immunity:** Ensure all deployment URLs, connection types, and property names are sanitized via `escapeHtml()`.
