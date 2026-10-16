# Task 44: Updates Payload Optimization and Documentation Synchronization

## Objective
Optimize delta filtering in the updates builder to keep payload size well under 1 MB, compile updates JSON, and synchronize task README documentation.

## Tasks
1. **Optimize Delta Filtering**:
   - Update `src/mcp_vulnerabilities/updates_builder.py` so only servers with `is_vulnerable == True` or genuinely updated records where `change_type` is in `("NEW_VULNERABILITY", "NEW_SERVER", "NEW_VERSION", "PATCHED_VERSION")` are included in the delta updates payload.
2. **Compile Updates JSON**:
   - Compile `docs/data/updates/latest_update.json` and verify that the file size is strictly `< 1 MB`.
3. **Synchronize Documentation**:
   - Update `docs/tasks/README.md` setting Tasks 38–43 to `Done` and updating test count status to `268 passed in 40.9s`.

## Non-Interactive Completion Directive
Complete all tasks successfully, run tests/checks, commit changes, and finish directly without asking open-ended questions.
