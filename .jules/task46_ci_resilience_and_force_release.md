# Task 46: CI Resilience, PyPI Graceful Fallback & Force-Release Support

## Objective & Scope
Harden `.github/workflows/daily_sync.yml` in `mcp-vulnerabilities` to ensure scheduled, dispatch, and manual CI runs always succeed:
1. Add `force_release` boolean input to `workflow_dispatch` to allow manual workflow triggers to bump version, build updates, tag, and publish releases on demand.
2. Trigger version bump and release if `[ -n "$VULN_CHANGES" ] || [ "${{ inputs.force_release }}" = "true" ]`.
3. Add `continue-on-error: true` to the `pypi-release` job so PyPI Trusted Publishing OIDC validation warnings do not fail the overall workflow run.

## Target Files
1. `.github/workflows/daily_sync.yml`

## Implementation Details
1. **In `on.workflow_dispatch`**:
   ```yaml
   on:
     schedule:
       - cron: "0 3 * * *"
     workflow_dispatch:
       inputs:
         force_release:
           description: 'Force version bump and release'
           required: false
           default: false
           type: boolean
     repository_dispatch:
       types: [upstream_fingerprints_updated]
   ```
2. **In `Commit and push updated security advisories & snapshot`**:
   Condition check:
   ```bash
   if [ -n "$VULN_CHANGES" ] || [ "${{ inputs.force_release }}" = "true" ]; then
   ```
3. **In `pypi-release` job**:
   ```yaml
     pypi-release:
       needs: sync-mcp-vulnerabilities
       if: needs.sync-mcp-vulnerabilities.outputs.release_created == 'true'
       continue-on-error: true
       permissions:
         id-token: write
         contents: read
       uses: ./.github/workflows/release.yaml
   ```
4. **Verification**:
   Run `.venv/bin/python -m pytest tests/ -q --tb=short` and ensure all tests pass.

## Non-Interactive Completion Directive
Apply changes directly and verify. Do not prompt the user or ask open-ended questions. Cleanly transition the remote VM session to Completed.
