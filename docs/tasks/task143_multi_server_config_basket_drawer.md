# Task 143: Multi-Server Configuration Basket Drawer & Client Export Engine

## Overview & Goal
Implement the interactive **Multi-Server Configuration Basket** (`+ Add to Basket` / `✓ In Basket`) and client export engine in the web portal (`docs/app.js`, `docs/index.html`, `docs/style.css`), enabling users to batch-select MCP servers and export configuration JSON for all 6 supported AI clients:
1. **Claude Desktop** (`claude_desktop_config.json` with `{"mcpServers": { ... }}`)
2. **Cursor** (`~/.cursor/mcp.json` with `{"mcpServers": { ... }}`)
3. **Windsurf** (`~/.codeium/windsurf/mcp_config.json` with `{"mcpServers": { ... }}`)
4. **Cline** (`cline_mcp_settings.json` with `{"mcpServers": { ... }}`)
5. **Continue.dev** (`config.json` with `{"mcpServers": [ { "name": ..., "command": ..., "args": ... } ]}`)
6. **Zed** (`settings.json` with `{"context_servers": { ... }}`)

---

## Detailed Requirements & Invariants

### 1. `window.toggleBasket(packageName)` Implementation in `docs/app.js`
- Define and export `window.toggleBasket(packageName)`:
  - If `selectedServers.has(packageName)`, remove it (`selectedServers.delete(packageName)`).
  - If not in `selectedServers`, add it (`selectedServers.add(packageName)`).
- Update button visual states for all buttons matching that package:
  - Text: `+ Add to Basket` ↔ `✓ In Basket`
  - Classes: toggle `.active` class.
- Update `#basket-count` in `#config-basket-drawer` to reflect `selectedServers.size`.
- Update `#config-basket-drawer` visibility:
  - If `selectedServers.size > 0`, display drawer (e.g. `display: block` or class `.open`).
  - If `selectedServers.size === 0`, hide drawer (`display: none` or remove `.open`).
- Trigger `window.detectCollisions()` to warn if any selected servers share duplicate tool names.
- Update active client tab preview textarea `#basketConfigOutput` using `window.generateMultiClientConfig(activeClient)`.

### 2. Drawer UX & Controls
- Add a close / clear button to `#config-basket-drawer` header:
  - Clear all button (`Clear Basket`) that empties `selectedServers`, resets all card buttons, and hides the drawer.
  - Close / minimize drawer toggle.
- Add client tab switching between all 6 clients (`claude`, `cursor`, `zed`, `windsurf`, `cline`, `continue`).
- Implement copy feedback (`"Copied to clipboard!"` toast or button text update `📋 Copied!`).

### 3. Client Schema Invariants in `generateMultiClientConfig`
- Ensure accurate schema generation for each client:
  - **Claude / Cursor / Windsurf / Cline**:
    ```json
    {
      "mcpServers": {
        "<server_name>": {
          "command": "npx" | "uvx",
          "args": ["-y", "<package_name>"],
          "env": { ... }
        }
      }
    }
    ```
  - **Zed**:
    ```json
    {
      "context_servers": {
        "<server_name>": {
          "command": "npx" | "uvx",
          "args": ["-y", "<package_name>"],
          "env": { ... }
        }
      }
    }
    ```
  - **Continue.dev**:
    ```json
    {
      "mcpServers": [
        {
          "name": "<server_name>",
          "command": "npx" | "uvx",
          "args": ["-y", "<package_name>"],
          "env": { ... }
        }
      ]
    }
    ```

### 4. Automated Tests
- Create `tests/test_web_basket_export.py` verifying:
  - `window.toggleBasket` is defined and properly toggles package in `selectedServers`.
  - All 6 client types produce valid JSON adhering to client specifications.
  - `#config-basket-drawer` elements and clear controls exist in `docs/index.html`.
