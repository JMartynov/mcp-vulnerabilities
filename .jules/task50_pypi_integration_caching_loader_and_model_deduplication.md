# Task 50: PyPI Integration, Caching Loader & Core Model Deduplication (P0)

## 1. Architectural Context & Technical Objective

`mcp-vulnerabilities` currently maintains duplicate copies of several core modules in `src/mcp_vulnerabilities/fingerprints/`:
- `models.py` (duplicates `ServerPackageSpec`, `VersionFingerprint`, `ToolContractSignature`)
- `canonicalizer.py` (duplicates canonical tool hashing and version fingerprinting)
- `matcher.py` (duplicates `FingerprintMatcher`)

Furthermore, while `mcp-fingerprints` is published to PyPI, its distribution wheel is only 134 KB (code only), omitting the 14 MB compiled `passports.json.gz`. When installed as a standard pip package, `McpIdentifier()` and `FingerprintMatcher()` look for `Path("data/fingerprints")`, which does not exist in standard Python site-packages.

### Core Objectives:
1. **In `mcp-fingerprints`**:
   - Implement `mcp_fingerprints.data_loader` with multi-tier snapshot resolution:
     - Tier 1: Local repository checkout (`passports.json.gz` or `data/fingerprints`).
     - Tier 2: User cache directory (`~/.cache/mcp-fingerprints/passports.json.gz`).
     - Tier 3: On-demand download from the latest GitHub release CDN with ETag / SHA-256 validation.
   - Update `McpIdentifier` and `FingerprintMatcher.load_default()` to use this loader.
   - Release and tag version `v1.0.14`.
2. **In `mcp-vulnerabilities`**:
   - Add `mcp-fingerprints>=1.0.14` to `pyproject.toml` dependencies.
   - Deduplicate `src/mcp_vulnerabilities/fingerprints/`:
     - Re-export `ServerPackageSpec`, `VersionFingerprint`, `ToolContractSignature` from `mcp_fingerprints.models`.
     - Re-export canonicalizer utilities from `mcp_fingerprints.canonicalizer`.
     - Re-export `FingerprintMatcher` from `mcp_fingerprints.matcher`.
     - Retain vulnerability-specific models (`CorrelatedTimeline`, `VersionVulnerabilityState`, `VulnerabilityCorrelator`).
   - Refactor `sync_manager.py` to leverage the unified caching loader.

---

## 2. Target Files & Documentation
- `pyproject.toml`
- `src/mcp_vulnerabilities/fingerprints/models.py`
- `src/mcp_vulnerabilities/fingerprints/canonicalizer.py`
- `src/mcp_vulnerabilities/fingerprints/matcher.py`
- `src/mcp_vulnerabilities/sync_manager.py`
- `tests/test_pypi_integration_and_deduplication.py`
- `docs/tasks/README.md`

---

## 3. Super Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Multi-Tier Snapshot Resolution Invariant
- **Preconditions**: `mcp-fingerprints` is installed in a clean Python environment where `data/fingerprints` does not exist in the working directory.
- **Test Steps**:
  1. Call `get_passports_path()`.
  2. If cache `~/.cache/mcp-fingerprints/passports.json.gz` is absent, verify that it downloads from GitHub releases CDN and persists to the cache.
  3. Call `get_passports_path()` a second time.
- **Invariants**:
  - [x] **INVARIANT_1A (Cache Hit)**: The second call MUST return the cached file without performing network I/O.
  - [x] **INVARIANT_1B (Valid Content)**: The resolved file MUST be valid gzip JSON parseable into a dictionary with $>5,000$ server entries.
  - [x] **INVARIANT_1C (Offline Guard)**: When `download_if_missing=False` and no local cache exists, it MUST raise `FileNotFoundError` with a descriptive message rather than failing with an unhandled network error.

### Scenario 2: Model Deduplication & Backward Compatibility Invariant
- **Preconditions**: Existing codebase components import from `mcp_vulnerabilities.fingerprints.models`.
- **Test Steps**:
  1. Import `ServerPackageSpec`, `VersionFingerprint`, `ToolContractSignature` from `mcp_vulnerabilities.fingerprints.models`.
  2. Instantiate each model from test dictionary fixtures.
  3. Verify type equality: `isinstance(spec, mcp_fingerprints.models.ServerPackageSpec)`.
- **Invariants**:
  - [x] **INVARIANT_2A (Identity)**: The imported classes MUST be identical to `mcp_fingerprints.models` classes (`ServerPackageSpec is mcp_fingerprints.models.ServerPackageSpec`).
  - [x] **INVARIANT_2B (No Attribute Regression)**: All serialized fields (`to_dict()`, `from_dict()`, `toolset_canonical_hash`) MUST produce identical output to prior versions.
  - [x] **INVARIANT_2C (Vulnerability Extensions Preserved)**: `CorrelatedTimeline` and `VersionVulnerabilityState` MUST remain available and fully functional in `mcp_vulnerabilities.fingerprints.models`.

### Scenario 3: Canonicalizer Delegation Invariant
- **Preconditions**: Test functions invoke `compute_toolset_canonical_hash` and `build_version_fingerprint`.
- **Test Steps**:
  1. Pass identical tool definitions to both `mcp_vulnerabilities.fingerprints.canonicalizer` and `mcp_fingerprints.canonicalizer`.
- **Invariants**:
  - [x] **INVARIANT_3A (Hash Parity)**: The computed SHA-256 toolset canonical hashes MUST be bit-for-bit identical across both import paths.
  - [x] **INVARIANT_3B (Whitespace & Order Normalization)**: Both functions must normalize tool argument ordering and unicode whitespace identically.

### Scenario 4: Cross-Repository Synchronization Resilience
- **Preconditions**: `CrossRepoSyncManager` runs during daily CI sync or local updates.
- **Test Steps**:
  1. Invoke `CrossRepoSyncManager.fetch_latest_passports()`.
- **Invariants**:
  - [x] **INVARIANT_4A**: If local repository `passports.json.gz` exists, it is utilized directly.
  - [x] **INVARIANT_4B**: If network is unavailable, it gracefully falls back to the user cache without corrupting existing data.

---

## 4. Implementation Steps

1. In `../mcp-fingerprints`:
   - Author `src/mcp_fingerprints/data_loader.py` implementing `get_passports_path()` and `load_passports()`.
   - Update `McpIdentifier` and `FingerprintMatcher` to delegate default path resolution to `get_passports_path()`.
   - Bump version to `v1.0.14` in `pyproject.toml` and release package.
2. In `mcp-vulnerabilities`:
   - Update `pyproject.toml` dependencies with `"mcp-fingerprints>=1.0.14"`.
   - Replace duplicate code in `src/mcp_vulnerabilities/fingerprints/models.py`, `canonicalizer.py`, and `matcher.py` with re-exports from `mcp_fingerprints`.
   - Update `src/mcp_vulnerabilities/sync_manager.py` to use `get_passports_path()`.
   - Author comprehensive test suite in `tests/test_pypi_integration_and_deduplication.py`.
   - Verify `pytest -q` passes 100%.
