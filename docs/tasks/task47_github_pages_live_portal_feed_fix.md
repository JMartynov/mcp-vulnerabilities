# Task 47: GitHub Pages Deployment & Live Web Portal / Feed Reference Fix (P0)

## 1. Architectural Context & Technical Objective
The public links for the MCP Vulnerability Explorer and Threat Updates Feed are currently returning 404 / unavailable:
- Live Portal: [https://jmartynov.github.io/mcp-vulnerabilities/](https://jmartynov.github.io/mcp-vulnerabilities/)
- Live Feed: [https://jmartynov.github.io/mcp-vulnerabilities/updates.html](https://jmartynov.github.io/mcp-vulnerabilities/updates.html)

The objective is to implement a robust GitHub Actions deployment workflow (`.github/workflows/pages.yml`) using official GitHub Pages actions (`actions/configure-pages@v5`, `actions/upload-pages-artifact@v3`, `actions/deploy-pages@v4`) that deploys the `docs/` directory upon push to `main` and on workflow dispatch. Additionally, all asset references (CSS, JS, JSON data feeds, icons) must be validated for proper relative routing without 404 errors.

---

## 2. Target Files & Documentation
- `.github/workflows/pages.yml` (New GitHub Actions workflow)
- `.github/workflows/daily_sync.yml` (Trigger pages deployment after daily sync if data changes)
- `docs/index.html` (Validate relative paths and feed links)
- `docs/updates.html` (Validate relative paths and feed links)
- `README.md` (Verify badges and documentation links)
- `docs/tasks/README.md` (Update task board status)

---

## 3. Acceptance Scenarios & Criteria

### Scenario 1: Automated GitHub Pages Deployment Workflow
- [ ] GIVEN a push to `main` branch or a manual `workflow_dispatch` trigger
- [ ] WHEN `.github/workflows/pages.yml` executes
- [ ] THEN it configures GitHub Pages, uploads the `docs/` directory as artifact, and deploys to GitHub Pages environment with `id-token: write` and `pages: write` permissions.

### Scenario 2: Live Portal Accessibility (`index.html`)
- [ ] GIVEN a user navigating to `https://jmartynov.github.io/mcp-vulnerabilities/`
- [ ] WHEN the page loads in the browser
- [ ] THEN HTTP status is 200, stylesheet `style.css` and script `app.js` load without 404 errors, and core catalog metrics are rendered.

### Scenario 3: Live Threat Updates Feed Accessibility (`updates.html`)
- [ ] GIVEN a user navigating to `https://jmartynov.github.io/mcp-vulnerabilities/updates.html`
- [ ] WHEN the page loads in the browser
- [ ] THEN HTTP status is 200, `updates.js` loads, and the latest release delta feed entries are fetched and displayed in reverse-chronological order.

### Scenario 4: Relative Resource & Feed Link Integrity
- [ ] GIVEN users accessing both the live portal and the live feed
- [ ] WHEN clicking between "Recent Updates" on index.html and "Directory Explorer" on updates.html
- [ ] THEN navigation transitions seamlessly without broken relative URLs.
- [ ] AND feed endpoints (`data/feed.json`, `data/feed.atom`) are reachable.

---

## 4. Implementation Steps
- [ ] 1. Create `.github/workflows/pages.yml` with permissions (`contents: read`, `pages: write`, `id-token: write`) and concurrency controls.
- [ ] 2. Audit all `<link>`, `<script>`, `fetch()` and `<img>` URLs in `docs/index.html`, `docs/updates.html`, `docs/app.js`, and `docs/updates.js` to ensure they use relative paths (e.g., `./data/...` or `data/...` instead of absolute root `/data/...`).
- [ ] 3. Verify static site locally using lightweight HTTP server (`python3 -m http.server --directory docs`).
- [ ] 4. Update documentation and README links if needed.
