# Task 22 Contract: MCP Fingerprints Integration & Unlabelled Server Detection Engine

## Objective
Integrate the `mcp-fingerprints` knowledge base (5,033+ server passports) and structural AST/JSON-RPC canonicalization engine into `mcp-vulnerabilities`. Enable the platform to probe any running or remote MCP server, compute deterministic toolset hashes, detect what MCP server package/repository it is, and detect multi-server tool shadowing/collisions in client configurations.

---

## Architectural Specification

### 1. New Subsystem: `src/mcp_vulnerabilities/fingerprints/`
Create package `src/mcp_vulnerabilities/fingerprints/` containing:
- `models.py`:
  - `ToolContractSignature`: `name`, `canonical_hash`, `description`, `property_keys`, `required_keys`, `parameter_types`, `input_schema`, `output_schema`, `description_hash`. Includes `to_dict()` and `from_dict()`.
  - `PromptSignature`: `name`, `description`, `argument_keys`, `required_arguments`, `arguments_schema`.
  - `VersionFingerprint`: `version`, `toolset_canonical_hash`, `release_date`, `dependencies`, `capabilities`, `tool_signatures` (tuple of `ToolContractSignature`), `prompt_signatures`.
  - `ServerPackageSpec`: `package_name`, `purl`, `ecosystem`, `display_name`, `description`, `repository_url`, `homepage_url`, `versions` (tuple of `VersionFingerprint`), `security_profile`.
  - `FingerprintMatchResult`: `package_name`, `ecosystem`, `version`, `repository_url`, `confidence_score` (0.0 to 1.0), `match_type` ("toolset_exact", "tool_hash", "fuzzy_topological"), `matched_tools_count`, `total_tools_count`.
- `canonicalizer.py`:
  - `canonicalize_json(obj: Any) -> str`: Sorts dictionary keys recursively, produces compact separators `(',', ':')` without extraneous whitespace.
  - `compute_sha256(data: str | bytes) -> str`: Returns `sha256:<hex_digest>`.
  - `extract_tool_signature(tool_def: dict[str, Any]) -> ToolContractSignature`: Normalizes properties, sorts parameter keys, sorts required keys, extracts types, and computes SHA-256 canonical hash.
  - `compute_toolset_canonical_hash(tools: list[dict[str, Any]]) -> str`: Deterministically sorts all extracted tool canonical hashes and combines with `|` to form the order-independent toolset SHA-256 hash.
- `matcher.py`:
  - `FingerprintMatcher`:
    - Loads `data/passports.json.gz` (checks `Path("data/passports.json.gz")`, package resources, and cache). Handles gzip decompression gracefully.
    - Builds in-memory fast lookup indexes:
      - `by_toolset_hash: dict[str, list[tuple[ServerPackageSpec, VersionFingerprint]]]`
      - `by_tool_hash: dict[str, set[str]]` (maps tool canonical hash to package names)
      - `by_tool_name: dict[str, set[str]]` (maps tool name to package names)
    - `match_tools(tools: list[dict[str, Any]]) -> list[FingerprintMatchResult]`:
      - 1. Checks exact `toolset_canonical_hash`. If found, returns 1.0 confidence match.
      - 2. Checks individual tool canonical hashes.
      - 3. Computes Jaccard similarity across tool names and schema property keys.
      - Returns sorted list of match candidates by confidence score.
- `conflict_detector.py`:
  - `ConflictDetector`:
    - `detect_conflicts(config_data: dict[str, Any]) -> list[dict[str, Any]]`:
      - Parses server entries in client configs (e.g. `mcpServers` dict).
      - Checks tool names exposed by each server (or known from passport specs if package name is identified).
      - Flags collisions: when two different servers expose tools with the same name, warning about potential tool hijacking or LLM confusion.

---

### 2. CLI Integration (`src/mcp_vulnerabilities/cli.py`)
- **New Subcommand: `mcp-vuln identify`**:
  - Arguments:
    - `--command`: Stdio command to launch and probe (e.g. `uvx mcp-server-fetch`).
    - `--url`: Remote HTTP/SSE URL to probe.
    - `--timeout`: Handshake timeout in seconds (default 30).
    - `--format`: `text` (rich colorized output), `json`.
  - Behavior:
    - Connects to the server using the existing probe infrastructure (`probe_mcp_server`).
    - Requests `tools/list` via JSON-RPC.
    - Passes the resulting tool definitions to `FingerprintMatcher.match_tools()`.
    - Outputs detected identity: Package Name, Ecosystem, PURL, Repository URL, Matched Version, Confidence %, and Tool Count.
- **Enhanced `mcp-vuln probe`**:
  - Automatically runs fingerprint identification during probing and prints:
    `[+] Detected MCP Server: <package_name> (<ecosystem>) | Confidence: 100% | Repo: <repository_url>`
- **Enhanced `mcp-vuln audit-config`**:
  - Add flag `--detect-collisions`: Runs `ConflictDetector` on the targeted config file and displays collision warnings if servers expose overlapping tool names.

---

### 3. Verification & Acceptance Criteria
- Full test coverage in `tests/test_fingerprints.py`:
  1. `test_canonical_tool_hashing`: Verifies identical hashes for tool schemas regardless of key ordering or whitespace.
  2. `test_toolset_canonical_hash`: Verifies that order of tools in array does not alter `toolset_canonical_hash`.
  3. `test_fingerprint_matcher_exact`: Verifies matching against a mock/loaded passport with 100% confidence.
  4. `test_fingerprint_matcher_fuzzy`: Verifies partial matching with Jaccard distance when tool definitions are partially modified.
  5. `test_conflict_detector`: Verifies detection of colliding tool names between two mock server configs.
  6. `test_cli_identify_stdio`: Tests `mcp-vuln identify --command` with a mocked stdio runner.
- All existing 113+ tests in `.venv/bin/pytest` must pass without regressions.
- Non-Interactive Completion Directive: Complete all edits and test runs autonomously and cleanly exit so the session status transitions to `Completed`.
