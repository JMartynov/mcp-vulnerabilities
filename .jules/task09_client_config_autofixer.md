### Task: AI Client Config Auto-Fixer (cli fix-config)

#### 1. Architectural Context & Purpose:
Developers running Claude Desktop, Cursor, or Zed currently execute `python -m mcp_vulnerabilities.cli audit --config <path>` to identify vulnerable MCP servers. However, remediation is completely manual: users must look up fixed versions, research safe releases, and edit JSON configurations by hand.
Adding an automated remediation command (`fix-config`) will inspect detected vulnerable servers, calculate the minimum safe non-vulnerable version from the OSV database, and automatically rewrite the client configuration safely with backups.

#### 2. Codebase References:
* `src/mcp_vulnerabilities/audit/parsers.py`: `ClientConfigParser` (parses Claude Desktop, Cursor configs).
* `src/mcp_vulnerabilities/audit/matcher.py`: `VulnerabilityMatcher`.
* `src/mcp_vulnerabilities/cli.py`: Subcommand interface.

#### 3. Implementation Details:
1. Create `src/mcp_vulnerabilities/audit/fixer.py`:
   - Class `ClientConfigFixer`:
     - Loads client config (e.g. `claude_desktop_config.json`).
     - Parses server arguments looking for vulnerable package versions (e.g. `npx -y @modelcontextprotocol/server-postgres@0.6.1`).
     - Queries `VulnerabilityMatcher` to find the minimum fixed semver (e.g. `0.6.2`).
     - Creates an atomic timestamped backup: `<config>.bak.<timestamp>`.
     - Rewrites server arguments with the safe version string.
2. In `src/mcp_vulnerabilities/cli.py`:
   - Add subcommand `fix-config`:
     ```bash
     python -m mcp_vulnerabilities.cli fix-config --config path/to/claude_desktop_config.json [--dry-run]
     ```

#### 4. Acceptance Criteria:
- [ ] Running `cli fix-config --dry-run` displays proposed version upgrades without modifying the file.
- [ ] Running `cli fix-config` updates vulnerable package versions in client config and creates a `.bak` backup.
- [ ] Unit tests in `tests/test_audit.py` cover safe version calculation and JSON rewriting.
