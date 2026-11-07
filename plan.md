1. **Fix `mcp_vulnerabilities/audit/tui.py` Initialization & Data Loading:**
   - Add imports for `asyncio`, `platform`, `Path` (from `pathlib`), and `ClientConfigParser` (from `.parsers`).
   - Create a `load_advisories()` function to resolve `self.matcher = VulnerabilityMatcher(load_advisories())` or directly initialize using `VulnerabilityMatcher.from_snapshot(Path('vulnerabilities.json.gz'))` if it exists, otherwise `from_directory(Path('data/vulnerabilities'))`.
   - Update `_load_data` to respect `self.args.config`. If a config is provided, scan it using `ClientConfigParser.parse_file`. Otherwise, scan all clients using `self.scanner.scan_all_clients()`.
   - Include discovered network listeners from `self.net_scanner` in `self.servers` by running `asyncio.run(self.net_scanner.scan_target(...))` or similar and converting results to `DiscoveredClientServer` when `mcp_handshake == True`.

2. **Fix `mcp_vulnerabilities/audit/tui.py` UI/Header (`_draw`):**
   - Use `platform.system()` for OS substitution.
   - Compute Posture: determine real posture from matched vulnerabilities (e.g. if any server has CRITICAL findings, posture is CRITICAL, else HIGH/MED/SECURE).

3. **Update Unit Tests in `tests/audit/test_tui.py`:**
   - Add a test for initialization matching the exact string substitutions (`--config`, OS mapping, etc.).
   - Verify that when `--config` is passed, `_load_data` invokes `parse_file`.
   - Ensure the new logic is covered.

4. **Complete Pre-Commit Steps:**
   - Run `pre_commit_instructions` tool to run required checks before committing changes.
