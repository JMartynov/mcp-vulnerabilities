# Task 157C: Atomic Resilient Sync State Management and Corrupted State Recovery

## Objective
Harden `data/vulnerabilities/sync_state.json` and `data/mcp_catalog_state.json` synchronization against crash faults, network drops, and file corruption using atomic writes and self-healing fallback mechanisms.

## Requirements
1. In `src/mcp_vulnerabilities/state.py` (or `sync_manager.py` / `pipeline.py`):
   - Implement `atomic_save_json(path, data)`:
     - Writes to `<path>.tmp.<pid>`.
     - Flushes and fsyncs to disk.
     - Atomically renames (`os.replace`) to target path.
   - Implement `safe_load_sync_state(path)`:
     - Attempts to parse JSON.
     - If file does not exist, returns initialized default state.
     - If JSON is corrupted / partial (e.g. power cut mid-write), logs a warning, attempts to read backup file (`<path>.bak` if exists), or resets corrupted source markers gracefully without crashing the pipeline.
2. In `src/mcp_vulnerabilities/pipeline.py`:
   - Use atomic saving whenever persisting `sync_state.json`.
3. In `tests/test_sync_state_resilience.py`:
   - Unit tests verifying:
     - Atomic write succeeds and creates valid JSON.
     - Loading corrupted/truncated JSON falls back gracefully to default/backup state without throwing unhandled `JSONDecodeError`.
     - Concurrent saves do not produce corrupt files.
4. Verify all tests pass (`pytest`).
