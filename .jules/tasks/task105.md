# Task Contract: Task 105 — AST Protocol Behavior Annotations & Safety Badges (P1)

### 1. Context & Objective:
Modern MCP servers provide AST protocol-level behavioral annotations on tools:
`readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`.
This task integrates AST Protocol Behavior Annotations across the pipeline and UI:
1. In `src/mcp_vulnerabilities/site_builder.py` and `src/mcp_vulnerabilities/catalog.py`:
   - Preserve `ToolSecurityAssessment.annotations` (dict of `str -> bool`) when writing shard JSON files:
     ```python
     "annotations": {
         "readOnlyHint": bool(t.annotations.get("readOnlyHint", False)),
         "destructiveHint": bool(t.annotations.get("destructiveHint", False)),
         "idempotentHint": bool(t.annotations.get("idempotentHint", False)),
         "openWorldHint": bool(t.annotations.get("openWorldHint", False)),
     }
     ```
   - In `mcp_catalog_index.json` summary records:
     Aggregate protocol hints across version tools:
     ```python
     "protocol_hints": {
         "has_destructive": any(t.get("annotations", {}).get("destructiveHint") for t in tools),
         "destructive_count": sum(1 for t in tools if t.get("annotations", {}).get("destructiveHint")),
         "read_only_count": sum(1 for t in tools if t.get("annotations", {}).get("readOnlyHint")),
     }
     ```
   - Graceful backward compatibility: if passport annotations is missing or None, default to `{}`.
2. In `docs/app.js` (`openServerModal()`):
   - For each tool in the modal, inspect `tool.annotations` and render hint badges:
     * `readOnlyHint`: `<span class="badge badge-hint badge-readonly" title="Declared safe read-only operation">🛡️ Read-Only</span>`
     * `destructiveHint`: `<span class="badge badge-hint badge-destructive" title="Declared destructive operation (modifies/deletes state)">⚠️ Destructive</span>`
     * `idempotentHint`: `<span class="badge badge-hint badge-idempotent" title="Declared idempotent operation (safe to repeat)">🔄 Idempotent</span>`
     * `openWorldHint`: `<span class="badge badge-hint badge-openworld" title="Declared open-world interaction (fetches external network data)">🌍 Open World</span>`
   - In `#server-modal` top metadata bar, if `has_destructive` is true, render a summary pill: `<span class="badge badge-warning" title="Server exports tools with destructive capabilities">⚠️ Contains Destructive Tools</span>`.
3. In `docs/style.css`:
   - Add styles for `.badge-hint`, `.badge-readonly`, `.badge-destructive`, `.badge-idempotent`, `.badge-openworld`.
4. Unit testing:
   - Add tests in `tests/test_site_builder.py` asserting that `annotations` round-trip through tool assessment serialization.

### 2. Files to Modify/Create:
- `src/mcp_vulnerabilities/site_builder.py`
- `src/mcp_vulnerabilities/catalog.py`
- `docs/app.js`
- `docs/style.css`
- `tests/test_site_builder.py`

### 3. Strict Guardrails:
- Do NOT run full site builds or compile large datasets (e.g. `passports.json.gz`) inside the VM. Write and verify using unit tests with mock tool fixtures.
- Verify with `pytest tests/test_site_builder.py` and `node -c docs/app.js`.

### 4. Defaults when blocked:
- If a rule above cannot be met, leave that part as it was, list it in the summary with the reason, and continue. Do not ask questions.

### 5. Completion Directive:
- Implement all requested changes, verify with unit tests, and finalize your response directly with a concise summary. Do not ask conversational follow-up questions, so the task cleanly transitions to Completed.
