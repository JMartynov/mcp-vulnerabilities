# Task 37: Unified Container/VM Sandbox Drivers, Pre-Commit Security Hooks & API Route Bugfix (P0)

## 1. Architectural Context & Technical Objective
Consolidate container and VM sandbox execution drivers (`DockerSandboxRunner`, `IncusSandboxRunner`, fallback `HostRunner`) within `src/mcp_vulnerabilities/sandbox/`. Harden execution with `--network none`, `--read-only`, non-root user execution, and strict CPU/memory limits. Author and distribute `.pre-commit-hooks.yaml` exposing `mcp-vuln-audit` to audit client configs and lockfiles during pre-commit. Remediate any lingering API route parameter mismatches or transport startup exceptions in `src/mcp_vulnerabilities/api/routes.py`.

## 2. Target Files & Documentation to Update
- `src/mcp_vulnerabilities/sandbox/drivers.py`
- `src/mcp_vulnerabilities/sandbox/runner.py`
- `.pre-commit-hooks.yaml`
- `src/mcp_vulnerabilities/api/routes.py`
- `tests/test_sandbox_drivers.py`
- `tests/test_pre_commit_hooks.py`
- `docs/sandboxing_and_hooks.md`

## 3. EULIS Implementation & Branch Review Workflow
- Branch: `jules/review-task37`
- Implementation PR: `jules-gate pr --skip-ci`
- Offload Mode 2 EULIS Code Review: `jules-gate review-branch`
- Review verification: check `docs/reviews/review_task37.md`
- Test verification: run test suite via isolated subagent (`jules-gate verify`)
- Merge: `jules-gate pr-merge --skip-ci`

## 4. Acceptance & Verification Criteria
- [ ] Unified sandbox drivers support Docker, Podman, and Incus with graceful fallback to host isolation.
- [ ] Sandboxed containers enforce airgapped isolation (`--network none`, read-only root filesystem, dropped capabilities).
- [ ] `.pre-commit-hooks.yaml` configured and tested against sample configuration files.
- [ ] API routes `/api/v1/scan/probe` and `/api/v1/identify` handle arguments cleanly without 500 errors.
- [ ] Unit and live acceptance tests pass cleanly.
