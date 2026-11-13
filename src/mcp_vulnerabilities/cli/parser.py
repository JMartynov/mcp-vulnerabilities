"""CLI argument parser configuration for MCP Vulnerability Database."""

from __future__ import annotations

import argparse
from mcp_vulnerabilities import __version__


def create_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="MCP Vulnerability Advisory Database CLI"
    )
    parser.add_argument("--version", "-v", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # proxy command
    proxy_parser = subparsers.add_parser("proxy", help="Inline JSON-RPC Reverse Proxy")
    proxy_parser.add_argument("--package", help="Package name for vulnerabilities")
    proxy_parser.add_argument("--mode", choices=["block", "audit"], default="block")
    proxy_parser.add_argument("--block-tool", action="append", default=[], dest="blocked_tools")
    proxy_parser.add_argument("--strict-passport", action="store_true")
    proxy_parser.add_argument("--no-payload-guardrails", action="store_false", dest="enable_payload_guardrails")
    proxy_parser.add_argument("--audit-log", help="Path to audit log file")
    proxy_parser.add_argument("--dir", help="Path to vulnerabilities directory")
    proxy_parser.add_argument("--sandbox", choices=["docker", "subprocess", "none"], default="none", help="Sandbox execution driver")
    proxy_parser.add_argument("--canary-detection", action="store_true", help="Enable canary secret leak detection")
    proxy_parser.add_argument("command_args", nargs=argparse.REMAINDER, help="-- <command> [args...]")


    # Site Build
    site_build_p = subparsers.add_parser(
        "site-build", help="High-performance parallel site builder"
    )
    site_build_p.add_argument("--data-dir", default="data/vulnerabilities", help="Vulnerabilities directory")
    site_build_p.add_argument("--output-dir", default="docs/data", help="Output directory")
    site_build_p.add_argument("--passports", default=None, help="Passports file path")
    site_build_p.add_argument("--workers", type=int, default=0, help="Worker concurrency (default: CPU count)")
    site_build_p.add_argument("--no-cache", action="store_true", help="Force complete re-evaluation without cache")
    site_build_p.add_argument("--benchmark", action="store_true", help="Print detailed timing breakdown")

    # Discover
    disc_p = subparsers.add_parser(
        "discover", help="Run multi-registry MCP server discovery"
    )
    disc_p.add_argument(
        "--catalog-file", default="data/mcp_servers.json", help="Output catalog path"
    )

    # Enrich
    enrich_p = subparsers.add_parser(
        "enrich", help="Enrich missing versions in the MCP servers catalog"
    )
    enrich_p.add_argument(
        "--catalog-file", default="data/mcp_servers.json", help="Catalog file path"
    )
    enrich_p.add_argument(
        "--limit", type=int, default=None, help="Maximum number of packages to enrich"
    )
    enrich_p.add_argument(
        "--workers", type=int, default=10, help="Number of concurrent workers"
    )
    enrich_p.add_argument(
        "--force", action="store_true", help="Force enrichment even if version exists"
    )
    disc_p.add_argument("--no-npm", action="store_true", help="Skip npm discovery")
    disc_p.add_argument("--no-pypi", action="store_true", help="Skip PyPI discovery")
    disc_p.add_argument(
        "--no-github", action="store_true", help="Skip GitHub discovery"
    )
    disc_p.add_argument(
        "--no-registries", action="store_true", help="Skip crates/ruby/docker discovery"
    )
    disc_p.add_argument(
        "--no-smithery", action="store_true", help="Skip Smithery.ai discovery"
    )
    disc_p.add_argument(
        "--no-glama", action="store_true", help="Skip Glama.ai discovery"
    )
    disc_p.add_argument("--prune", action="store_true", help="Prune dead or tombstoned servers")
    disc_p.add_argument("--prune-archived", action="store_true", help="Prune archived repositories")
    disc_p.add_argument("--prune-deleted", action="store_true", help="Prune deleted repositories")
    disc_p.add_argument("--offline-backoff", action="store_true", help="Enable exponential backoff for offline endpoints")

    # network-scan
    network_scan_p = subparsers.add_parser("network-scan", help="Scan local and network TCP ports for active MCP servers and unauthenticated listeners")
    network_scan_p.add_argument("--target", "-t", default="127.0.0.1", help="Target IP address or hostname to scan.")
    network_scan_p.add_argument("--ports", "-p", default="3000-8800", help="Port range or 'common'.")
    network_scan_p.add_argument("--cidr", default=None, help="CIDR subnet range for LAN discovery.")
    network_scan_p.add_argument("--timeout", type=float, default=1.0, help="Connection and probe timeout in seconds per port.")
    network_scan_p.add_argument("--concurrency", type=int, default=64, help="Maximum concurrent asynchronous socket connections.")
    network_scan_p.add_argument("--format", choices=["table", "json"], default="table", help="Output format.")
    network_scan_p.add_argument("--output", "-o", default=None, help="Optional file path to write results.")

    # tui
    tui_p = subparsers.add_parser("tui", help="Launch split-pane curses terminal dashboard for interactive security exploration")
    tui_p.add_argument("--target", default="localhost", help="Network target to probe.")
    tui_p.add_argument("--ports", default="*", help="Ports to probe.")
    tui_p.add_argument("--config", "-c", default=None, help="Path to specific AI client config file to inspect.")
    tui_p.add_argument("--theme", choices=["dark", "light", "high-contrast"], default="dark", help="Terminal color theme.")
    tui_p.add_argument("--no-color", action="store_true", help="Disable terminal ANSI color output.")

    # monitor
    monitor_p = subparsers.add_parser("monitor", help="Run background monitoring daemon to continuously detect MCP port drift and config mutations")
    monitor_p.add_argument("--daemon", action="store_true", help="Run in background detached daemon mode.")
    monitor_p.add_argument("--interval", type=int, default=300, help="Monitoring interval in seconds (default: 300).")
    monitor_p.add_argument("--targets", default="localhost", help="Target host specification (default: localhost).")
    monitor_p.add_argument("--ports", default="3000-8800", help="Port range or list to scan (default: 3000-8800).")
    monitor_p.add_argument("--notify", action="store_true", help="Enable native desktop notifications (macOS / Linux).")
    monitor_p.add_argument("--webhook", default=None, help="Webhook URL for real-time alerts (Slack / Discord).")
    monitor_p.add_argument("--status", action="store_true", help="Check status of running monitor daemon.")
    monitor_p.add_argument("--stop", action="store_true", help="Stop running monitor daemon.")
    monitor_p.add_argument("--install-service", action="store_true", help="Generate and install OS service (launchd / systemd).")
    monitor_p.add_argument("--log-file", default="~/.mcp-vuln/logs/monitor.log", help="Path to monitor daemon log file.")
    monitor_p.add_argument("--pid-file", default="~/.mcp-vuln/run/monitor.pid", help="Path to monitor daemon PID file.")

    # bridge
    bridge_p = subparsers.add_parser("bridge", help="Run secure local loopback bridge server for static web portal workstation scanning")
    bridge_p.add_argument("--port", type=int, default=8765, help="Local TCP port to bind.")
    bridge_p.add_argument("--host", default="127.0.0.1", help="Host address to bind.")
    bridge_p.add_argument("--cors-origins", default="https://jmartynov.github.io,http://localhost:*,http://127.0.0.1:*", help="Comma-separated list of allowed CORS origins.")
    bridge_p.add_argument("--simulate", "--mock", action="store_true", help="Run in simulated demonstration mode emitting synthetic progress events.")
    bridge_p.add_argument("--allowed-origin", dest="cors_origins", help="Additional CORS allowed origin URL.")
    bridge_p.add_argument("--no-auth", action="store_true", help="Disable session token requirement (for local testing).")
    bridge_p.add_argument("--open-browser", action="store_true", help="Automatically open docs/index.html in default browser on launch.")

    # Sync
    sync_p = subparsers.add_parser(
        "sync", help="Run multi-source vulnerability ingestion pipeline"
    )
    sync_p.add_argument(
        "--output", default="data/vulnerabilities", help="Output directory"
    )
    sync_p.add_argument("--state-file", default=None, help="State file path")
    sync_p.add_argument(
        "--catalog-state-file",
        default="data/mcp_catalog_state.json",
        help="Version cache state path",
    )
    sync_p.add_argument(
        "--servers-catalog",
        default="data/mcp_servers.json",
        help="Servers catalog path",
    )
    sync_p.add_argument(
        "--markdown-dir", nargs="*", default=None, help="Markdown advisory directories"
    )
    sync_p.add_argument(
        "--cvelistv5-dir",
        nargs="*",
        default=None,
        help="CVEListV5 repository directories",
    )
    sync_p.add_argument(
        "--gitlab-dir", nargs="*", default=None, help="GitLab advisory directories"
    )
    sync_p.add_argument(
        "--include-gitlab", action="store_true", help="Sync GitLab Advisory Database"
    )
    sync_p.add_argument(
        "--live-api", action="store_true", help="Query live GHSA and OSV.dev APIs"
    )
    sync_p.add_argument(
        "--nvd-api", action="store_true", help="Query live NIST NVD 2.0 API"
    )

    sync_p.add_argument(
        "--cvelist-delta",
        action="store_true",
        help="Ingest recent CVE commits from GitHub",
    )
    sync_p.add_argument(
        "--reset-state", action="store_true", help="Reset sync state checkpoints"
    )
    sync_p.add_argument(
        "--snapshot",
        action="store_true",
        default=True,
        help="Compile snapshot after sync",
    )
    sync_p.add_argument(
        "--notify-webhooks",
        action="store_true",
        help="Dispatch webhooks for new critical/high advisories",
    )
    sync_p.add_argument("--prune", action="store_true", help="Prune dead or tombstoned servers")
    sync_p.add_argument("--prune-archived", action="store_true", help="Prune archived repositories")
    sync_p.add_argument("--prune-deleted", action="store_true", help="Prune deleted repositories")
    sync_p.add_argument("--offline-backoff", action="store_true", help="Enable exponential backoff for offline endpoints")

    # Search
    search_p = subparsers.add_parser(
        "search", help="Search for vulnerabilities by keyword, ID, or package"
    )
    search_p.add_argument(
        "query", help="Keyword, CVE ID, or package name to search for"
    )
    search_p.add_argument(
        "--min-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Minimum severity threshold",
    )
    search_p.add_argument(
        "--ecosystem", default=None, help="Filter by ecosystem (e.g., npm, pypi)"
    )
    search_p.add_argument(
        "--format", choices=["table", "json"], default="table", help="Output format"
    )
    search_p.add_argument(
        "--data-dir", default="data/vulnerabilities", help="Directory of OSV advisories"
    )
    search_p.add_argument(
        "--snapshot",
        default="vulnerabilities.json.gz",
        help="Path to consolidated snapshot file",
    )

    # Lookup
    lookup_p = subparsers.add_parser(
        "lookup", help="Lookup a specific vulnerability by exact ID or alias"
    )
    lookup_p.add_argument(
        "id_or_alias", help="Vulnerability ID (e.g., GHSA-... or CVE-...)"
    )
    lookup_p.add_argument(
        "--format", choices=["table", "json"], default="table", help="Output format"
    )
    lookup_p.add_argument(
        "--data-dir", default="data/vulnerabilities", help="Directory of OSV advisories"
    )
    lookup_p.add_argument(
        "--min-epss", type=float, default=0.0, help="Minimum EPSS score (0.0 to 1.0) to display findings"
    )
    lookup_p.add_argument(
        "--snapshot",
        default="vulnerabilities.json.gz",
        help="Path to consolidated snapshot file",
    )

    # Validate
    val_p = subparsers.add_parser(
        "validate", help="Validate OSV vulnerability files in directory"
    )
    val_p.add_argument(
        "--dir", default="data/vulnerabilities", help="Directory of OSV JSON files"
    )

    # Export OSV Bucket
    export_p = subparsers.add_parser(
        "export-osv",
        help="Export OSV vulnerability records into a bucket format (all.zip and manifest.json)",
    )
    export_p.add_argument(
        "--data-dir", default="data/vulnerabilities", help="Directory of OSV JSON files"
    )
    export_p.add_argument(
        "--output-dir",
        default="dist/osv",
        help="Directory to output all.zip and manifest.json",
    )

    # Snapshot
    snap_p = subparsers.add_parser(
        "snapshot", help="Compile all advisories into consolidated .json.gz"
    )
    snap_p.add_argument(
        "--data-dir", default="data/vulnerabilities", help="Advisories data directory"
    )
    snap_p.add_argument(
        "--output-gz", default="vulnerabilities.json.gz", help="Output gzip file path"
    )
    snap_p.add_argument(
        "--output-json", default=None, help="Optional uncompressed JSON output path"
    )

    # Export Airgap
    exp_p = subparsers.add_parser(
        "export-airgap", help="Export offline air-gapped bundle"
    )
    exp_p.add_argument(
        "--output",
        default="dist/mcp-vulnerabilities-offline.tar.gz",
        help="Output tarball path",
    )
    exp_p.add_argument(
        "--data-dir", default="data/vulnerabilities", help="Advisories data directory"
    )

    # Audit
    aud_p = subparsers.add_parser("audit", aliases=["audit-config"], help="Audit AI client MCP servers or packages against OSV database")
    aud_p.add_argument(
        "--verify-signatures",
        action="store_true",
        help="Verify tools runtime signatures against baseline passport hashes to detect tampering",
    )
    aud_p.add_argument(
        "--strict-integrity",
        action="store_true",
        help="Exit with non-zero code if signature tampering is detected",
    )
    aud_p.add_argument("--config", default=None, help="Path to AI client config file (e.g. claude_desktop_config.json)")
    aud_p.add_argument("--package", default=None, help="Specific package to audit, e.g. @modelcontextprotocol/server-neo4j@0.6.1")
    aud_p.add_argument("--all-clients", action="store_true", help="Audit all 9 supported AI clients (Claude, Cursor, VS Code, Zed, Cline, Windsurf, Continue, LibreChat, OpenWebUI)")
    aud_p.add_argument("--client", default=None, help="Audit a specific AI client (claude, cursor, vscode, zed, cline, windsurf, continue, librechat, openwebui)")
    aud_p.add_argument("--global", dest="audit_global", action="store_true", help="Audit globally installed npm/npx MCP packages")
    aud_p.add_argument("--custom-config", default=None, help="Audit custom config file path (JSON/YAML)")
    aud_p.add_argument("--data-dir", default="data/vulnerabilities", help="Directory of OSV advisories")
    aud_p.add_argument("--snapshot", default="vulnerabilities.json.gz", help="Path to consolidated snapshot file")
    aud_p.add_argument("--severity-threshold", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=None, help="Minimum severity threshold")
    aud_p.add_argument("--min-epss", type=float, default=0.0, help="Minimum EPSS score (0.0 to 1.0) to display findings")
    aud_p.add_argument("--format", choices=["table", "json", "sarif", "cyclonedx", "sbom"], default="table", help="Output format")
    aud_p.add_argument("--save-baseline", default=None, help="Save scanned client server inventory as an approved baseline snapshot file")
    aud_p.add_argument("--diff", "--diff-baseline", dest="diff_baseline", default=None, help="Path to approved baseline snapshot JSON file to compare against current state")
    aud_p.add_argument("--fail-on-drift", action="store_true", help="Exit with exit code 2 if baseline drift is detected")

    # Audit Transitive
    
    # Audit Typosquat
    typo_p = subparsers.add_parser(
        "audit-typosquat", help="Detect AI hallucinated and typosquatted MCP packages"
    )
    typo_p.add_argument("--config", required=True, help="Path to AI client configuration file")
    typo_p.add_argument("--fix", action="store_true", help="Auto-fix typosquats in configuration file")
    typo_p.add_argument("--threshold", type=int, default=2, help="Levenshtein distance threshold")
    typo_p.add_argument("--json", dest="output_json", action="store_true", help="Output results in JSON format")
    typo_p.add_argument("--strict", action="store_true", help="Strict mode for typosquat detection")

    trans_p = subparsers.add_parser("audit-transitive", help="Audit third-party dependencies of MCP servers")
    trans_p.add_argument("--manifest", required=True, help="Path to package.json or requirements.txt")
    trans_p.add_argument("--severity-threshold", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], default=None, help="Minimum severity threshold")
    trans_p.add_argument("--format", choices=["table", "json", "sarif"], default="table", help="Output format")
    trans_p.add_argument("--source-dir", default=None, help="Source directory for reachability analysis")
    trans_p.add_argument("--reachable-only", action="store_true", help="Filter for REACHABLE findings only")

    # Hub
    hub_p = subparsers.add_parser(
        "hub",
        help="Launch the interactive MCP Security Command Hub",
    )
    hub_p.add_argument("--json", action="store_true", help="Output machine-readable JSON (Non-interactive)")
    hub_p.add_argument("--batch", action="store_true", help="Run in non-interactive batch mode")

    # Bot Remediate PR
    bot_p = subparsers.add_parser(
        "remediate-pr",
        help="Automated GitHub PR Remediation Bot for MCP configurations.",
    )
    bot_p.add_argument("--repo-dir", default=".", help="Repository root directory to scan")
    bot_p.add_argument("--dry-run", action="store_true", help="Print planned branches and PR bodies to stdout without git writes")
    bot_p.add_argument("--auto-merge", action="store_true", help="Enable auto-merge on created PRs")
    bot_p.add_argument("--assignee", default=None, help="GitHub username to assign PRs to")
    bot_p.add_argument("--json", dest="output_json", action="store_true", help="Output machine-readable JSON summary")
    bot_p.add_argument("--data-dir", default="data/vulnerabilities", help="Directory of OSV advisories")
    bot_p.add_argument("--snapshot", default="vulnerabilities.json.gz", help="Path to consolidated snapshot file")

    # Fix Config
    fix_p = subparsers.add_parser(
        "fix",
        aliases=["fix-config"],
        help="Automatically remediate vulnerable servers in a client config",
    )
    fix_p.add_argument(
        "--config",
        required=False,
        help="Path to AI client config file (e.g. claude_desktop_config.json)",
    )
    fix_p.add_argument(
        "--client",
        type=str,
        help="Name of the specific AI client to fix (e.g. claude, zed, cursor)",
    )
    fix_p.add_argument(
        "--all-clients",
        action="store_true",
        help="Fix configurations across all 9 supported AI clients",
    )
    fix_p.add_argument(
        "--dry-run",
        action="store_true",
        help="Display proposed version upgrades without modifying the file (default unless --write is passed)",
    )
    fix_p.add_argument(
        "--write",
        action="store_true",
        help="Write changes to disk (creates atomic timestamped backups)",
    )
    fix_p.add_argument(
        "--data-dir", default="data/vulnerabilities", help="Directory of OSV advisories"
    )
    fix_p.add_argument(
        "--snapshot",
        default="vulnerabilities.json.gz",
        help="Path to consolidated snapshot file",
    )

    # Probe Safe
    probe_safe_p = subparsers.add_parser(
        "probe-safe", help="Pre-Execution Sandboxed Network Prober"
    )
    probe_safe_p.add_argument("--url", required=True, help="Target MCP endpoint URL (http/sse) or command string (stdio).")
    probe_safe_p.add_argument("--sandbox-type", choices=["docker", "subprocess"], default="docker", help="Sandbox isolation engine: docker | subprocess (default: docker).")
    probe_safe_p.add_argument("--timeout", type=int, default=30, help="Execution timeout in seconds (default: 30).")
    probe_safe_p.add_argument("--no-canary-detection", dest="canary_detection", action="store_false", help="Disable synthetic honeytoken exfiltration analysis.")
    probe_safe_p.add_argument("--allow-outbound", action="store_true", help="Allow outbound network access beyond target host (default: false).")
    probe_safe_p.add_argument("--json", dest="output_json", action="store_true", help="Output raw JSON verdict for automation/scripts.")

    # Probe
    identify_p = subparsers.add_parser(

        "identify", help="Probe and identify an MCP server using fingerprints"
    )
    identify_p.add_argument(
        "--command",
        dest="server_command",
        type=str,
        help="Command to start the MCP server (e.g. 'uvx mcp-server-fetch')",
    )
    identify_p.add_argument(
        "--url",
        type=str,
        help="URL for HTTP/SSE MCP server",
    )
    identify_p.add_argument(
        "--timeout",
        type=float,
        default=30.0,
        help="Timeout in seconds for discovery handshake",
    )
    identify_p.add_argument(
        "--format",
        choices=["text", "json", "cyclonedx", "sbom"],
        default="text",
        help="Output format",
    )
    identify_p.add_argument(
        "--correlate",
        action="store_true",
        help="Correlate identified version with known vulnerabilities",
    )
    identify_p.add_argument(
        "--min-confidence",
        type=float,
        default=0.85,
        help="Minimum confidence threshold for attribution",
    )
    identify_p.add_argument(
        "--header",
        action="append",
        default=[],
        help="Inject custom HTTP header (e.g. 'Key: Value')",
    )
    identify_p.add_argument(
        "--data-dir",
        type=str,
        default="data",
        help="Directory containing passports.json.gz",
    )

    probe_p = subparsers.add_parser(
        "probe", help="Live protocol probe and tool auditor"
    )
    probe_p.add_argument(
        "--command",
        dest="server_command",
        help="Command to start stdio MCP server (e.g. 'python server.py')",
    )
    probe_p.add_argument(
        "--url",
        dest="server_url",
        help="URL of SSE MCP server (e.g. 'http://localhost:8000/sse')",
    )
    probe_p.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Connection and read timeout in seconds",
    )
    probe_p.add_argument(
        "--auth-header",
        help="Inject custom authorization header (e.g. 'Authorization: Bearer <token>')",
    )
    probe_p.add_argument(
        "--header",
        action="append",
        default=[],
        help="Inject custom HTTP header, can be used multiple times (e.g. 'Key: Value')",
    )
    probe_p.add_argument(
        "--surfaces",
        choices=["tools", "prompts", "resources", "all"],
        default="all",
        help="Controls which surfaces to query (default: all)",
    )
    probe_p.add_argument(
        "--format", choices=["table", "json", "sarif", "cyclonedx", "sbom"], default="table", help="Output format"
    )
    probe_p.add_argument(
        "--data-dir", default="data/vulnerabilities", help="Directory of OSV advisories"
    )
    probe_p.add_argument(
        "--snapshot",
        default="vulnerabilities.json.gz",
        help="Path to consolidated snapshot file",
    )
    probe_p.add_argument(
        "--analyzers",
        type=str,
        default="all",
        help="Comma-separated list of analyzers to run (threat,osv,all)",
    )
    probe_p.add_argument(
        "--fail-on",
        type=str,
        default=None,
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        help="Gate pipelines based on threat findings",
    )
    probe_p.add_argument(
        "--readiness",
        action="store_true",
        help="Injects readiness scorecard into probe results",
    )
    probe_p.add_argument(
        "--compliance", choices=["owasp-mcp-top-10", "owasp-llm-2025"], default=None, help="Evaluate against compliance frameworks"
    )
    probe_p.add_argument(
        "--fail-on-non-compliant", action="store_true", help="Fail with exit code 1 if compliance tier is NON_COMPLIANT"
    )

    # Scan Source
    scan_p = subparsers.add_parser(
        "scan-source", help="Run static AST source code taint analyzer"
    )
    scan_p.add_argument("path", help="Path to directory or file to scan")
    scan_p.add_argument(
        "--format", choices=["text", "json", "sarif"], default="text", help="Output format"
    )
    scan_p.add_argument(
        "--output", default=None, help="Output file path (required for SARIF)"
    )
    scan_p.add_argument(
        "--fail-on", choices=["CRITICAL", "HIGH"], default=None, help="CI/CD gating flag"
    )

    # Subcommand: scan-binaries
    scan_bin_p = subparsers.add_parser(
        "scan-binaries",
        help="Scan binary assets and check for malware hashes",
    )
    scan_bin_p.add_argument(
        "target_dir",
        help="Directory containing binary assets to scan",
    )
    scan_bin_p.add_argument(
        "--blocklist",
        help="Custom hash blocklist file path",
    )
    scan_bin_p.add_argument(
        "--enable-vt",
        action="store_true",
        help="Enables VirusTotal queries (requires VIRUSTOTAL_API_KEY)",
    )
    scan_bin_p.add_argument(
        "--max-files",
        type=int,
        help="Caps number of binaries scanned",
    )
    scan_bin_p.add_argument(
        "--format",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format",
    )
    scan_bin_p.add_argument(
        "--fail-on-malware",
        action="store_true",
        help="Fail with exit code 1 if malware is detected",
    )

    # Serve API
    serve_p = subparsers.add_parser(
        "serve", help="Run Headless REST API Gateway & Microservice Daemon"
    )
    serve_p.add_argument(
        "--host", default="127.0.0.1", help="Host IP to bind to (overrides MCP_VULN_HOST)"
    )
    serve_p.add_argument(
        "--port", type=int, default=8080, help="Port to bind to (overrides MCP_VULN_PORT)"
    )
    serve_p.add_argument(
        "--cors-origins", default=None, help="CORS allowed origins"
    )

    # Lint
    lint_p = subparsers.add_parser(
        "lint", help="Audit MCP tool schemas and contracts for production readiness"
    )
    lint_p.add_argument(
        "--command",
        dest="server_command",
        help="Command to start stdio MCP server to lint",
    )
    lint_p.add_argument("--url", help="URL of SSE MCP server to lint")
    lint_p.add_argument("--file", help="Path to JSON schema file to lint")
    lint_p.add_argument(
        "--format", choices=["table", "json", "sarif"], default="table", help="Output format"
    )
    lint_p.add_argument(
        "--fail-under", type=int, default=0, help="Minimum acceptable readiness score (0-100)"
    )
    lint_p.add_argument(
        "--compliance", choices=["owasp-mcp-top-10", "owasp-llm-2025"], default=None, help="Evaluate against compliance frameworks"
    )
    lint_p.add_argument(
        "--fail-on-non-compliant", action="store_true", help="Fail with exit code 1 if compliance tier is NON_COMPLIANT"
    )

    # Sandbox
    sandbox_p = subparsers.add_parser(
        "sandbox", help="Safely execute and probe untrusted MCP packages in an isolated container"
    )
    sandbox_p.add_argument("ecosystem", choices=["pypi", "npm"], help="Ecosystem of the package")
    sandbox_p.add_argument("package", help="Name of the package to install and probe")
    sandbox_p.add_argument("--version", help="Specific version to install")
    sandbox_p.add_argument("--timeout", type=int, default=60, help="Container timeout in seconds")
    sandbox_p.add_argument(
        "--network", choices=["bridge", "none"], default="bridge", help="Network policy during execution"
    )
    sandbox_p.add_argument(
        "--passports", action="store_true", help="Automatically matches discovered tools against passport knowledge base"
    )
    sandbox_p.add_argument(
        "--threat-check", action="store_true", help="Automatically runs the YARA/RegEx threat engine against discovered tool descriptions"
    )

    # Timeline
    timeline_p = subparsers.add_parser(
        "timeline", help="Display per-version vulnerability timeline for a server"
    )
    timeline_p.add_argument("server", help="Server package name")
    timeline_p.add_argument(
        "--target-version", help="Filter timeline to a specific version"
    )
    timeline_p.add_argument(
        "--data-dir", default="data/vulnerabilities", help="Directory of OSV advisories"
    )
    timeline_p.add_argument(
        "--snapshot", default="vulnerabilities.json.gz", help="Path to consolidated snapshot file"
    )

    # Correlate
    correlate_p = subparsers.add_parser(
        "correlate", help="Correlate all server passports against vulnerability database"
    )
    correlate_p.add_argument(
        "--output", default=None, help="Optional output JSON file path"
    )
    correlate_p.add_argument(
        "--data-dir", default="data/vulnerabilities", help="Directory of OSV advisories"
    )
    correlate_p.add_argument(
        "--snapshot", default="vulnerabilities.json.gz", help="Path to consolidated snapshot file"
    )

    # Resolve Config
    resolve_p = subparsers.add_parser(
        "resolve-config", help="Automated conflict resolver and tool namespacing"
    )
    resolve_p.add_argument("config_file", help="Path to client config file")
    resolve_p.add_argument(
        "--strategy",
        choices=["prefix", "priority", "report"],
        default="prefix",
        help="Resolution strategy (prefix, priority, report)",
    )
    resolve_p.add_argument(
        "--output", help="Optional file path to output sanitized configuration"
    )
    resolve_p.add_argument(
        "--dir", default="data/fingerprints", help="Passport data directory"
    )
    resolve_p.add_argument(
        "--json", action="store_true", help="Output resolution result as JSON"
    )

    # Export Config
    export_cfg_p = subparsers.add_parser(
        "export-config", help="Export client configuration (Claude, Cursor, Cline, Zed, Windsurf, Docker)"
    )
    export_cfg_p.add_argument("package", help="Package name to export configuration for")
    export_cfg_p.add_argument(
        "--client",
        choices=["claude", "cursor", "cline", "zed", "windsurf", "docker"],
        default="claude",
        help="Target client environment",
    )
    export_cfg_p.add_argument(
        "--dir", default="data/fingerprints", help="Passport data directory"
    )
    export_cfg_p.add_argument(
        "--output", help="Optional output file path"
    )


    # Verify Feed
    verify_feed_p = subparsers.add_parser(
        "verify-feed", help="Verify cryptographic attestation for the vulnerability feed"
    )
    verify_feed_p.add_argument("--feed", required=True, help="Path or URL to the feed file")
    verify_feed_p.add_argument("--manifest", help="Path to manifest.json")
    verify_feed_p.add_argument("--bundle", help="Path to the sigstore bundle")
    verify_feed_p.add_argument("--expected-identity", default="https://github.com/JMartynov/mcp-vulnerabilities/.github/workflows/sign_release.yml@refs/heads/main", help="Expected OIDC identity")
    verify_feed_p.add_argument("--expected-issuer", default="https://token.actions.githubusercontent.com", help="Expected OIDC issuer")
    verify_feed_p.add_argument("--offline", action="store_true", help="Perform verification offline")
    verify_feed_p.add_argument("--json", action="store_true", help="Output JSON structured results")


    return parser
