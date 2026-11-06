# Task 152: Site Builder Linux Multiprocessing Deadlock Immunity & Daily Sync CI Hardening (P0)

**Target Wave:** Wave 28 (Runtime Edge Cases, Subsystems & CI Resilience)  
**Priority:** `P0` (Critical - Resolves 6-hour CI job timeouts in `daily_sync.yml`)  
**Status:** `Done`  

---

## 1. Architectural Context & Technical Objective

The daily synchronization workflow `.github/workflows/daily_sync.yml` consistently exceeded GitHub Actions' 6-hour execution ceiling on Linux runners (`ubuntu-latest`). Step telemetry and process analysis identified a thread-fork deadlock in `pytest -v` at `tests/test_site_builder.py::test_build_site_data`:

1. **Multiprocessing Fork Deadlock**:
   - `build_site_parallel` in `src/mcp_vulnerabilities/site_builder.py` spawns `ProcessPoolExecutor(max_workers=workers)` using Python's default start method.
   - On Linux with Python 3.12, the default start method is `fork`. Because preceding tests in `pytest` initialize threads, background workers, and asyncio loops, forking workers inside the test session causes a classic deadlock on internal locks (logging, import locks) that were acquired by parent threads.
2. **Missing Passports Isolation in Unit Tests**:
   - `test_build_site_data` in `tests/test_site_builder.py` passes `passports_path=None`.
   - `site_builder.py` line 548 falls back to `data/passports.json.gz`, loading all 6,280+ production passports and submitting them to the process pool during what should be an isolated unit test.
3. **Unbounded CI Execution**:
   - `.github/workflows/daily_sync.yml` lacked a job-level `timeout-minutes: 30`, allowing any hung process to exhaust runner minutes for 6 hours.

---

## 2. Invariant Specifications

- **INVARIANT_152_1 (Sequential Fallback for Single-Worker Execution)**:
  In `build_site_parallel` (`src/mcp_vulnerabilities/site_builder.py`), if `workers <= 1`, batches must be executed sequentially in-process without spawning `ProcessPoolExecutor`.
- **INVARIANT_152_2 (Spawn Context on Multiprocessing)**:
  When `workers > 1`, `ProcessPoolExecutor` must explicitly use `mp_context=multiprocessing.get_context("spawn")` to eliminate thread-fork deadlocks on Linux runners.
- **INVARIANT_152_3 (Isolated Test Fixtures)**:
  `test_build_site_data` in `tests/test_site_builder.py` must use a temporary/mock passports file or explicitly isolate its input so it does not evaluate 6,280 production passports from `data/passports.json.gz`.
- **INVARIANT_152_4 (Workflow Timeout & Test Guardrails)**:
  In `.github/workflows/daily_sync.yml`:
  - Add `timeout-minutes: 30` to `sync-mcp-vulnerabilities` job.
  - In `Validate OSV Dataset Integrity & Schemas`, run `pytest -v --timeout=60`.

---

## 3. Target Files & Isolation Boundaries

- **Files to Modify:**
  - `src/mcp_vulnerabilities/site_builder.py`
  - `tests/test_site_builder.py`
  - `.github/workflows/daily_sync.yml`
  - `docs/tasks/README.md`
- **Boundaries:**
  - Preserve all existing data formats, schemas, and CLI behavior.
  - Ensure bit-for-bit SHA-256 deterministic output across `workers=1` and `workers>1`.
