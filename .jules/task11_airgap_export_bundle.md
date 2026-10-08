### Task: Offline Air-Gapped Enterprise Export Bundle

#### 1. Architectural Context & Purpose:
Enterprise security teams and defense organizations operate in isolated, air-gapped enclaves with zero outbound internet access. They cannot query live APIs or download snapshots on demand.
Providing an offline export bundle command packages the entire OSV advisory database, the search index, and an embedded zero-dependency Python search script into a portable compressed tarball (`mcp-vulnerabilities-offline.tar.gz`).

#### 2. Codebase References:
* `src/mcp_vulnerabilities/snapshot.py`: Snapshot compilation.
* `src/mcp_vulnerabilities/audit/matcher.py`: Offline matcher logic.
* `src/mcp_vulnerabilities/cli.py`: CLI interface.

#### 3. Implementation Details:
1. In `src/mcp_vulnerabilities/snapshot.py`, implement `export_airgap_bundle()`:
   - Packages `data/vulnerabilities/*.json`, `index.json`, `vulnerabilities.json.gz`.
   - Embeds a standalone, zero-dependency `query.py` script allowing air-gapped systems to run `python query.py --package <name>@<version>` without installing any pip packages.
   - Compresses into `dist/mcp-vulnerabilities-offline.tar.gz` with a SHA-256 checksum manifest.
2. In `cli.py`:
   - Add CLI subcommand: `python -m mcp_vulnerabilities.cli export-airgap --output dist/mcp-offline.tar.gz`.

#### 4. Acceptance Criteria:
- [ ] Running `cli export-airgap` generates a self-contained tarball and `.sha256` checksum file.
- [ ] The embedded `query.py` executes successfully using only Python standard library on an isolated test machine.
- [ ] Unit test in `tests/test_snapshot.py` verifies archive creation and extraction integrity.
