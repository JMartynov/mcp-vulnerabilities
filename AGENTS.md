# AGENTS.md — MCP Vulnerabilities (`mcp-vulnerabilities`)

> **Scope**: Operational guide for [`mcp-vulnerabilities`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities) (MIT, Python `>=3.10`, depends on `mcp-fingerprints>=1.3.3`). OSV 1.6.0-compliant MCP vulnerability advisory database, multi-client auditor, AST reachability analyzer, and runtime defense toolkit.

---

## 1. Repository Layout & Specs

- **Package & CLIs**: `mcp-vulnerabilities` (`mcp-vuln` / `mcp-vulnerabilities`, `src/mcp_vulnerabilities/cli.py`, `pyproject.toml`)
- **Dataset & Snapshot**: `data/vulnerabilities/`, `vulnerabilities.json.gz`, `data/mcp_catalog_state.json`
- **Specs & Tasks**: [`docs/SPECIFICATION.md`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/docs/SPECIFICATION.md) | [`docs/cross_repo_architecture.md`](file:///Users/ivan/Project/3t.tools.intellij/mcp-vulnerabilities/docs/cross_repo_architecture.md) | `docs/tasks/`

---

## 2. Hard Guardrails

- **Code & Tests Only for DeepSeek**: Restrict `aider_bridge.py` (`dispatch` / `turn`) to production code and test files (`*.py`, `*.sh`, `Dockerfile`, CI workflows). Handle routine Markdown, doc, and task/board status syncs (`README.md`, `CHANGELOG.md`, `docs/tasks/*.md`) directly in ephemeral Antigravity `flash` / `flash_lite` subagents.
- **No Read-Only `--plan-align` Audits**: Never invoke `aider_bridge.py --plan-align` for read-only repo audits (use Antigravity `research` `flash` subagents or `aider_bridge.py scope`). Use `--plan-align` only when true architectural ambiguity exists.
- **Deterministic Guards & Zero Secrets**: Keep OSV matching, AST reachability, and Sigstore checks deterministic; never fabricate advisories or commit `.env` secrets.

---

## 3. Shared `.env` & DeepSeek Worktree Workflow (`aider_bridge.py`)

`DEEPSEEK_API_KEY` lives in `/Users/ivan/Project/3t.tools.intellij/verityredteam/.env`. Source it before invoking `aider_bridge.py`:

```bash
set -a && source /Users/ivan/Project/3t.tools.intellij/verityredteam/.env && set +a
```

1. **Commit Test Contracts First**: Commit failing unit/acceptance tests before `--worktree` so `--read-files` passes preflight (avoids exit `14`).
2. **Pass 1 — Dispatch in Isolated Worktree**:
   ```bash
   python3 ~/.gemini/config/skills/aider-deepseek/scripts/aider_bridge.py dispatch \
     --task-id "<task_id>" --worktree --no-auto-merge \
     --files <explicit_editable_files> \
     --read-files <locked_tests_or_specs> \
     --test-cmd "uv run pytest <test_file>" \
     --message "<Concrete spec. Zero unrelated edits.>"
   ```
   - **Prompts Containing Backticks**: `aider_bridge.py` accepts `--message` (no `--message-file` flag); load backticked prompts with a single-quoted heredoc (`MSG=$(cat <<'EOF' ... EOF)`) and pass `--message "$MSG"`.
   - **Cost Guards**: `aider_bridge.py` automatically shields `data/`, `*.json`, `uv.lock`, and unrequested files `>100` KB, and trips `--max-context-kb` (default `256`) before calling DeepSeek.
   - **Interactive Questions (Exit `10`)**: Run `aider_bridge.py inspect --task-id "<task_id>" --json`, then `aider_bridge.py reply --task-id "<task_id>" --answer "..."`.
3. **Pass 2 — Risk-Gated Self-Review (`--restore`)**: Run Pass 2 **only** for high-risk changes (security guards, AST/reachability, proxy/concurrency/locks, breaking API changes, or `>150` LOC); skip on small fixes, scaffolds, and docs when `ruff` + `pytest` pass:
   ```bash
   python3 ~/.gemini/config/skills/aider-deepseek/scripts/aider_bridge.py turn \
     --task-id "<task_id>" --restore --worktree --no-auto-merge \
     --files <explicit_editable_files> \
     --read-files <locked_tests_or_specs> \
     --message "PASS 2 CODE REVIEW: Verify scope adherence, security/AST edge cases, type hints, and zero unrelated edits."
   ```
4. **Locked Merge THEN Cleanup**: Only after all verification gates pass, run:
   ```bash
   python3 ~/.gemini/config/skills/aider-deepseek/scripts/aider_bridge.py merge-worktree --task-id "<task_id>"
   python3 ~/.gemini/config/skills/aider-deepseek/scripts/aider_bridge.py cleanup --task-id "<task_id>"
   ```

---

## 4. Verification Gates (matches `.github/workflows/ci.yml`)

```bash
ruff check src/
python -m mcp_vulnerabilities.cli validate --dir data/vulnerabilities
pytest -v tests/
```
