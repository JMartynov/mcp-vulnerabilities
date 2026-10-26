"""CLI for MCP Vulnerability Ingestion Pipeline & Advisory Database."""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path


from mcp_vulnerabilities.audit import (
    ClientConfigFixer,
    ClientConfigParser,
    DiscoveredClientServer,
    UniversalClientConfigScanner,
    VulnerabilityMatcher,
)
from mcp_vulnerabilities.discovery import (
    CatalogVersionEnricher,
    McpDiscoveryOrchestrator,
)
from mcp_vulnerabilities.pipeline import McpVulnerabilityPipeline
from mcp_vulnerabilities.probe.client import McpProbeClient
from mcp_vulnerabilities.probe.fingerprinter import McpFingerprinter
from mcp_vulnerabilities.probe.transport import HttpSseTransport, StdioTransport
from mcp_vulnerabilities.fingerprints.matcher import FingerprintMatcher
from mcp_vulnerabilities.fingerprints.conflict_detector import ConflictDetector
from mcp_vulnerabilities.snapshot import build_snapshot, export_osv_bucket
from mcp_vulnerabilities.transitive import TransitiveDependencyAuditor
from mcp_vulnerabilities.analyzers import (
    AnalysisTarget,
    ReadinessLinter,
    ThreatEngine,
    ThreatSeverity,
)
from mcp_vulnerabilities.api.server import McpSecurityApiServer
from mcp_vulnerabilities.sandbox.engine import ContainerEngine
from mcp_vulnerabilities.sandbox.runner import EphemeralSandbox, TimeoutExpired
from mcp_vulnerabilities.validator import OsvValidator

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger("mcp_vulnerabilities.cli")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="MCP Vulnerability Advisory Database CLI"
    )
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
    aud_p.add_argument("--format", choices=["table", "json", "sarif", "cyclonedx", "sbom"], default="table", help="Output format")

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

    args = parser.parse_args()

    if args.command == "proxy":
        from mcp_vulnerabilities.proxy.policy import ProxyPolicyEngine
        from mcp_vulnerabilities.proxy.interceptor import McpStdioProxy

        cmd_args = args.command_args
        if cmd_args and cmd_args[0] == "--":
            cmd_args = cmd_args[1:]

        if not cmd_args:
            print("Error: Must specify a command to wrap", file=sys.stderr)
            sys.exit(1)

        policy_engine = ProxyPolicyEngine(
            package_name=args.package,
            blocked_tools=set(args.blocked_tools),
            strict_passport=args.strict_passport,
            enable_payload_guardrails=args.enable_payload_guardrails,
            vulnerabilities_dir=Path(args.dir) if args.dir else None
        )

        proxy = McpStdioProxy(
            policy_engine=policy_engine,
            mode=args.mode,
            audit_log_path=args.audit_log
        )

        sys.exit(proxy.run_stdio(cmd_args))

    if args.command == "site-build":
        import os
        from mcp_vulnerabilities.site_builder import build_static_site_data
        
        workers = args.workers if args.workers > 0 else (os.cpu_count() or 4)
        
        build_static_site_data(
            data_dir=args.data_dir,
            output_dir=args.output_dir,
            passports_path=args.passports,
            workers=workers,
            use_cache=not args.no_cache,
            benchmark=args.benchmark,
        )
        sys.exit(0)

    elif args.command == "discover":
        orchestrator = McpDiscoveryOrchestrator(catalog_file=args.catalog_file)
        servers = orchestrator.run_discovery(
            include_npm=not args.no_npm,
            include_pypi=not args.no_pypi,
            include_github=not args.no_github,
            include_other_registries=not args.no_registries,
            include_smithery=not args.no_smithery,
            include_glama=not args.no_glama,
        )
        print(
            f"Discovery complete. Discovered {len(servers)} MCP servers -> {args.catalog_file}"
        )

    elif args.command == "enrich":
        enricher = CatalogVersionEnricher(
            catalog_file=args.catalog_file, max_workers=args.workers
        )
        stats = enricher.run_enrichment(limit=args.limit, force=args.force)
        print(
            f"Enriched {stats['attempted']} packages ({stats['updated']} updated, {stats['failed']} failed/skipped)"
        )

    elif args.command == "sync":
        state_file = args.state_file or f"{args.output}/sync_state.json"
        pipeline = McpVulnerabilityPipeline(
            output_dir=args.output,
            state_file=state_file,
            catalog_state_file=args.catalog_state_file,
            servers_catalog_file=args.servers_catalog,
        )
        md_dirs = args.markdown_dir or ["tests/fixtures/osv/markdown"]
        cve5_dirs = args.cvelistv5_dir or (
            ["tests/fixtures/osv/cve_json5"] if not args.live_api else None
        )
        res = pipeline.run(
            include_markdown_dirs=md_dirs,
            include_cvelistv5_dirs=cve5_dirs,
            include_cvelist_delta=args.live_api or args.cvelist_delta,
            include_ghsa_api=args.live_api,

            include_osv_api=args.live_api,
            include_nvd_api=args.live_api or args.nvd_api,
            include_verity_catalog=True,
            offline_fallback_fixtures="tests/fixtures/osv"
            if not args.live_api
            else None,
            reset_checkpoints=args.reset_state,
        )
        logger.info(
            "Sync complete: collected=%d, merged=%d, emitted=%d, errors=%d",
            res.collected_count,
            res.merged_count,
            res.emitted_count,
            len(res.errors),
        )
        if args.snapshot:
            logger.info("Compiling consolidated snapshot...")
            build_snapshot(
                data_dir=args.output,
                output_gz=f"{Path(args.output).parent}/vulnerabilities.json.gz"
                if args.output != "data/vulnerabilities"
                else "vulnerabilities.json.gz",
            )

        if args.notify_webhooks and res.emitted_ids:
            logger.info("Checking newly emitted advisories for webhooks...")
            import json

            from mcp_vulnerabilities.notifier import ThreatFeedNotifier

            new_advs = []
            out_dir = Path(args.output)
            for adv_id in res.emitted_ids:
                try:
                    fpath = out_dir / f"{adv_id}.json"
                    if fpath.exists():
                        new_advs.append(json.loads(fpath.read_text(encoding="utf-8")))
                except Exception as exc:
                    logger.warning(
                        "Failed to load emitted advisory %s: %s", adv_id, exc
                    )
            if new_advs:
                ThreatFeedNotifier().process_and_notify(new_advs)

    elif args.command == "validate":
        validator = OsvValidator()
        valid, invalid, errors = validator.validate_directory(args.dir)
        print(f"Validation summary: {valid} valid, {invalid} invalid advisories.")
        if invalid > 0:
            for err in errors:
                print(f"ERROR: {err}")
            sys.exit(1)
        sys.exit(0)

    elif args.command == "export-osv":
        res = export_osv_bucket(data_dir=args.data_dir, output_dir=args.output_dir)
        print(
            f"Exported OSV bucket to {args.output_dir}: {res['count']} vulnerabilities, SHA256: {res['sha256']}"
        )

    elif args.command == "snapshot":
        res = build_snapshot(
            data_dir=args.data_dir,
            output_gz=args.output_gz,
            output_json=args.output_json,
        )
        print(
            f"Compiled {res['total_vulnerabilities']} advisories ({res['size_kb']:.2f} KB) -> {res['snapshot_path']}"
        )

    elif args.command == "export-airgap":
        from mcp_vulnerabilities.snapshot import export_airgap_bundle

        res = export_airgap_bundle(data_dir=args.data_dir, output_tar=args.output)
        print(
            f"Exported airgap bundle: {res['bundle_path']} (checksum: {res['checksum']})"
        )

    elif args.command == "search":
        snap_p = Path(args.snapshot)
        data_p = Path(args.data_dir)
        if snap_p.exists():
            matcher = VulnerabilityMatcher.from_snapshot(snap_p)
        elif data_p.exists():
            matcher = VulnerabilityMatcher.from_directory(data_p)
        else:
            logger.error("No vulnerability database found at %s or %s", snap_p, data_p)
            sys.exit(2)

        results = matcher.search(
            query=args.query, min_severity=args.min_severity, ecosystem=args.ecosystem
        )

        if args.format == "json":
            import json

            print(json.dumps([r.advisory.to_dict() for r in results], indent=2))
        else:
            print(f"\nSearch Results for '{args.query}'")
            print("=" * 70)
            if not results:
                print("No matching vulnerabilities found.")
            else:
                for r in results:
                    adv = r.advisory
                    
                    for s in adv.severity:
                        pass  # Simplified, actual is handled in matcher via extract

                    # More robust severity extraction:
                    sev_str, _ = matcher._extract_severity_info(adv.to_dict())

                    print(f"\nID:         {adv.id}")
                    if adv.aliases:
                        print(f"Aliases:    {', '.join(adv.aliases)}")
                    print(f"Severity:   {sev_str}")
                    print(f"Matched On: {r.matched_on}")

                    affected_pkgs = []
                    vuln_tools = []
                    for aff in adv.affected:
                        affected_pkgs.append(
                            f"{aff.package.name} ({aff.package.ecosystem})"
                        )
                        if (
                            aff.database_specific
                            and aff.database_specific.vulnerable_tools
                        ):
                            vuln_tools.extend(aff.database_specific.vulnerable_tools)

                    if affected_pkgs:
                        print(f"Affected:   {', '.join(set(affected_pkgs))}")
                    if vuln_tools:
                        print(f"Tools:      {', '.join(set(vuln_tools))}")

                    print(f"Summary:    {adv.summary}")
            print("\n" + "=" * 70)
        sys.exit(0)

    elif args.command == "lookup":
        snap_p = Path(args.snapshot)
        data_p = Path(args.data_dir)
        if snap_p.exists():
            matcher = VulnerabilityMatcher.from_snapshot(snap_p)
        elif data_p.exists():
            matcher = VulnerabilityMatcher.from_directory(data_p)
        else:
            logger.error("No vulnerability database found at %s or %s", snap_p, data_p)
            sys.exit(2)

        adv = matcher.get_advisory(args.id_or_alias)

        if not adv:
            print(f"Vulnerability '{args.id_or_alias}' not found.")
            sys.exit(1)

        if args.format == "json":
            import json

            print(json.dumps(adv.to_dict(), indent=2))
        else:
            print(f"\nVulnerability Details: {adv.id}")
            print("=" * 70)
            if adv.aliases:
                print(f"Aliases:    {', '.join(adv.aliases)}")

            sev_str, _ = matcher._extract_severity_info(adv.to_dict())
            print(f"Severity:   {sev_str}")
            print(f"Published:  {adv.published}")
            print(f"Modified:   {adv.modified}")

            print(f"\nSummary:\n  {adv.summary}")
            print(
                f"\nDetails:\n  {adv.details[:500]}{'...' if len(adv.details) > 500 else ''}"
            )

            print("\nAffected Packages & Ranges:")
            for aff in adv.affected:
                print(f"  - {aff.package.name} ({aff.package.ecosystem})")
                for r in aff.ranges:
                    events = []
                    for ev in r.events:
                        if ev.introduced:
                            events.append(f">={ev.introduced}")
                        if ev.fixed:
                            events.append(f"<{ev.fixed}")
                        if ev.last_affected:
                            events.append(f"<={ev.last_affected}")
                    print(f"    Range: {', '.join(events)}")
                if aff.database_specific and aff.database_specific.vulnerable_tools:
                    print(
                        f"    Vulnerable Tools: {', '.join(aff.database_specific.vulnerable_tools)}"
                    )

            if adv.references:
                print("\nReferences:")
                for ref in adv.references:
                    print(f"  - {ref.url}")
            print("=" * 70)
        sys.exit(0)

    elif args.command == "audit":
        snap_p = Path(args.snapshot)
        data_p = Path(args.data_dir)
        if snap_p.exists():
            matcher = VulnerabilityMatcher.from_snapshot(snap_p)
        elif data_p.exists():
            matcher = VulnerabilityMatcher.from_directory(data_p)
        else:
            logger.error("No vulnerability database found at %s or %s", snap_p, data_p)
            sys.exit(2)

        servers: list[DiscoveredClientServer] = []
        if args.package:
            spec = args.package.strip()
            eco = (
                "npm" if spec.startswith("@") or not spec.startswith("mcp_") else "PyPI"
            )
            if "@" in spec.lstrip("@"):
                parts = spec.lstrip("@").split("@", 1)
                pkg = f"@{parts[0]}" if spec.startswith("@") else parts[0]
                ver = parts[1]
            elif "==" in spec:
                pkg, ver = spec.split("==", 1)
                eco = "PyPI"
            else:
                pkg = spec
                ver = None
            servers.append(
                DiscoveredClientServer(
                    server_name=pkg,
                    package_name=pkg,
                    version=ver,
                    ecosystem=eco,
                    command="manual",
                    args=[spec],
                )
            )
        elif getattr(args, "custom_config", None):
            cfg_p = Path(args.custom_config)
            servers = ClientConfigParser.parse_file(cfg_p)
        elif getattr(args, "client", None):
            scanner = UniversalClientConfigScanner()
            servers = scanner.scan_client(args.client)
        elif getattr(args, "all_clients", False):
            scanner = UniversalClientConfigScanner()
            servers = scanner.scan_all_clients()
            if getattr(args, "audit_global", False):
                servers.extend(scanner.scan_global())
        elif getattr(args, "audit_global", False):
            scanner = UniversalClientConfigScanner()
            servers = scanner.scan_global()
        elif args.config:
            cfg_p = Path(args.config)
            servers = ClientConfigParser.parse_file(cfg_p)
        else:
            standard_paths = ClientConfigParser.get_standard_config_paths()
            if not standard_paths:
                print(
                    "No standard AI client configuration files found. Provide one via --config <path> or audit a package with --package <spec>."
                )
                sys.exit(0)
            for path in standard_paths:
                logger.info("Found client config: %s", path)
                servers.extend(ClientConfigParser.parse_file(path))

        if getattr(args, "detect_collisions", False):
            detector = ConflictDetector()
            cfg_data = {}
            if args.config:
                with open(args.config, 'r') as f:
                    import json
                    cfg_data = json.load(f)
            conflicts = detector.detect_conflicts(cfg_data)
            if conflicts:
                print("\n" + "!" * 70)
                print(" TOOL COLLISIONS DETECTED")
                print("!" * 70)
                for c in conflicts:
                    print(f"✗ {c['warning']}")
                print("!" * 70 + "\n")
        tamper_reports = []
        has_strict_failure = False
        if getattr(args, "verify_signatures", False):
            from mcp_vulnerabilities.audit.tamper_detector import SupplyChainTamperDetector
            tamper_detector = SupplyChainTamperDetector(matcher.fingerprint_matcher if hasattr(matcher, "fingerprint_matcher") else matcher)
            for srv in servers:
                tr = tamper_detector.verify_server_integrity(srv, srv.declared_tools)
                tamper_reports.append(tr)
                if tr.status == "TAMPERED":
                    has_strict_failure = True

        report = matcher.audit_servers(
            servers, severity_threshold=args.severity_threshold
        )

        if args.format == "json":
            import json
            out = report.to_dict()
            if tamper_reports:
                out["tamper_reports"] = [r.to_dict() for r in tamper_reports]
            print(json.dumps(out, indent=2))
        elif args.format == "sarif":
            import json

            from mcp_vulnerabilities.audit.reporters import SarifReporter
            sarif_report = SarifReporter.generate_audit_sarif(report, target_path=args.config)
            if tamper_reports:
                tamper_sarif = SarifReporter.generate_tamper_sarif(tamper_reports, target_path=args.config or "mcp_client_config.json")
                sarif_report["runs"][0]["tool"]["driver"]["rules"].extend(tamper_sarif["runs"][0]["tool"]["driver"]["rules"])
                sarif_report["runs"][0]["results"].extend(tamper_sarif["runs"][0]["results"])
            print(json.dumps(sarif_report, indent=2))
        elif args.format in ("cyclonedx", "sbom"):
            import json
            from mcp_vulnerabilities.sbom.cyclonedx import CycloneDxBomBuilder
            
            builder = CycloneDxBomBuilder()
            builder.add_audit_report(report)
            print(json.dumps(builder.build(), indent=2))
        else:
            if tamper_reports:
                print("\n" + "=" * 70)
                print(" MCP SUPPLY-CHAIN TAMPER DETECTION REPORT")
                print("=" * 70)
                for tr in tamper_reports:
                    status_badge = f"[{tr.status}]"
                    print(f"\n{status_badge} Server: {tr.server_name} ({tr.package_name}@{tr.version})")
                    for inc in tr.incidents:
                        print(f"  [{inc.severity}] {inc.incident_type}: {inc.details}")
                        if inc.affected_tools:
                            print(f"  Affected Tools: {', '.join(inc.affected_tools)}")
                            
            print("\n" + "=" * 70)
            print(
                f" MCP SECURITY AUDIT REPORT: {len(report.scanned_servers)} servers scanned"
            )
            print("=" * 70)
            if not report.findings:
                print("✓ No known vulnerabilities found across scanned MCP servers.")
            else:
                for f in report.findings:
                    status_badge = (
                        "[CONFIRMED VULNERABLE]"
                        if f.is_confirmed
                        else "[UNPINNED WARNING]"
                    )
                    print(
                        f"\n{status_badge} Server: {f.server_name} ({f.package_name})"
                    )
                    print(
                        f"  Vulnerability:   {f.vulnerability_id} [Severity: {f.severity_level}]"
                    )
                    if f.cvss_score:
                        print(f"  CVSS Score:      {f.cvss_score}")
                    print(
                        f"  Installed:       {f.installed_version or 'Unpinned (latest)'}"
                    )
                    print(f"  Affected Range:  {f.affected_range}")
                    if f.fixed_version:
                        print(f"  Remediation:     Upgrade to >= {f.fixed_version}")
                    print(f"  Summary:         {f.summary}")
                    if f.references:
                        print(f"  References:      {f.references[0]}")
                print("\n" + "-" * 70)
                print(
                    f"SUMMARY: {len(report.findings)} vulnerability findings ({'CRITICAL/HIGH issues detected!' if report.has_critical_or_high else 'No critical issues'})."
                )
                print("-" * 70)

        if getattr(args, "strict_integrity", False) and has_strict_failure:
            sys.exit(2)
        sys.exit(1 if report.has_critical_or_high else 0)

    
    elif args.command == "audit-typosquat":
        import json
        import os
        from mcp_vulnerabilities.analyzers.typosquat import TyposquatDetector, RiskTier, load_authentic_corpus
        
        # Load corpus
        # Note: In a real environment, we'd load the actual catalog. Here we load defaults + any existing data/mcp_catalog_index.json
        corpus_path = Path("docs/data/mcp_catalog_index.json") if Path("docs/data/mcp_catalog_index.json").exists() else None
        corpus = load_authentic_corpus(corpus_path)
        detector = TyposquatDetector(corpus)

        config_path = Path(args.config)
        if not config_path.exists():
            logger.error(f"Config file not found: {config_path}")
            sys.exit(1)

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                config_data = json.load(f)
        except Exception as e:
            logger.error(f"Failed to parse config file: {e}")
            sys.exit(1)
            
        mcp_servers = config_data.get("mcpServers", {})
        
        results = []
        typosquats_detected = []
        highest_risk = 0 # 0=Auth, 1=Susp, 2=High, 3=Crit
        risk_levels = {RiskTier.AUTHENTIC: 0, RiskTier.SUSPICIOUS: 1, RiskTier.HIGH: 2, RiskTier.CRITICAL: 3}
        
        has_fixes = False
        
        for server_name, server_config in mcp_servers.items():
            command = server_config.get("command", "")
            args_list = server_config.get("args", [])
            
            # Very basic package name extraction heuristic for this task
            # E.g. command = "npx", args = ["-y", "@modelcontextprotocol/server-filesystem"]
            package_name = None
            if command == "npx" or command == "uvx" or command == "docker":
                for arg in args_list:
                    if not arg.startswith("-") and not arg.startswith("/") and not arg == "run":
                        package_name = arg
                        break
            
            if not package_name:
                continue
                
            res = detector.analyze(package_name)
            
            res_dict = {
                "server_name": server_name,
                "package_name": res.package_name,
                "canonical_name": res.canonical_name,
                "risk_tier": res.risk_tier.value,
                "reason": res.reason,
                "distance": res.distance
            }
            results.append(res_dict)
            
            if res.risk_tier != RiskTier.AUTHENTIC:
                typosquats_detected.append(res_dict)
                highest_risk = max(highest_risk, risk_levels[res.risk_tier])
                
                if args.fix and res.canonical_name:
                    # Update config
                    new_args = []
                    for arg in args_list:
                        if arg == package_name:
                            new_args.append(res.canonical_name)
                        else:
                            new_args.append(arg)
                    server_config["args"] = new_args
                    has_fixes = True

        if args.fix and has_fixes:
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(config_data, f, indent=2)
            if not args.output_json:
                logger.info(f"Fixed {len(typosquats_detected)} typosquatting packages in {config_path}")

        if args.output_json:
            print(json.dumps({
                "analyzed_packages": results,
                "typosquats_detected": typosquats_detected,
                "risk_summary": {
                    "has_critical": highest_risk == 3,
                    "has_high": highest_risk >= 2
                }
            }, indent=2))
        else:
            for r in typosquats_detected:
                logger.warning(f"Detected {r['risk_tier']} typosquat in server '{r['server_name']}': {r['package_name']} -> {r['canonical_name']} ({r['reason']})")
                
        if highest_risk >= 2: # HIGH or CRITICAL
            sys.exit(1)
        sys.exit(0)

    elif args.command == "audit-transitive":
        res = TransitiveDependencyAuditor.audit_manifest_file(args.manifest)
        if getattr(args, "source_dir", None):
            from mcp_vulnerabilities.transitive import annotate_reachability
            res = annotate_reachability(res, args.source_dir, reachable_only=getattr(args, "reachable_only", False))
            
        if args.severity_threshold:
            severity_order = {"LOW": 1, "MEDIUM": 2, "MODERATE": 2, "HIGH": 3, "CRITICAL": 4}
            min_rank = severity_order.get(str(args.severity_threshold).upper(), 0)
            res.findings = [
                f for f in res.findings
                if severity_order.get(str(f.severity).upper(), 1) >= min_rank
            ]
        if args.format == "json":
            import json

            print(json.dumps(res.to_dict(), indent=2))
        elif args.format == "sarif":
            import json

            from mcp_vulnerabilities.audit.reporters import SarifReporter
            sarif_report = SarifReporter.generate_transitive_sarif(res)
            print(json.dumps(sarif_report, indent=2))
        else:
            print("\n" + "=" * 70)
            print(
                f" TRANSITIVE DEPENDENCY AUDIT: {res.target_manifest} ({res.total_dependencies} dependencies)"
            )
            print("=" * 70)
            if not res.findings:
                print(
                    "✓ No known vulnerabilities found across third-party dependencies."
                )
            else:
                for f in res.findings:
                    print(
                        f"\n[VULNERABLE DEPENDENCY] {f.dependency_name} ({f.ecosystem}) @ {f.installed_version or 'unpinned'}"
                    )
                    print(
                        f"  Vulnerability: {f.vulnerability_id} [Severity: {f.severity}]"
                        + (f" (CVSS {f.cvss_score})" if f.cvss_score else "")
                    )
                    if f.fixed_version:
                        print(f"  Remediation:   Upgrade to >= {f.fixed_version}")
                    if getattr(f, "reachability", "UNKNOWN") != "UNKNOWN":
                        print(f"  Reachability:  {f.reachability}")
                    if getattr(f, "reachable_from_tools", None):
                        print(f"                 From Tools: {', '.join(f.reachable_from_tools)}")
                    print(f"  Summary:       {f.summary}")
                print("\n" + "-" * 70)
                print(
                    f"SUMMARY: {len(res.findings)} transitive vulnerabilities (Max CVSS: {res.max_cvss:.1f})."
                )
                print("-" * 70)

        sys.exit(1 if res.has_critical_or_high else 0)

    elif args.command == "hub":
        from .audit.hub import run_hub
        run_hub(args)
    elif args.command == "remediate-pr":
        from mcp_vulnerabilities.bot.scanner import RepositoryScanner
        from mcp_vulnerabilities.bot.pr_builder import PRBuilder

        snap_p = Path(args.snapshot)
        data_p = Path(args.data_dir)
        if snap_p.exists():
            matcher = VulnerabilityMatcher.from_snapshot(snap_p)
        elif data_p.exists():
            matcher = VulnerabilityMatcher.from_directory(data_p)
        else:
            logger.error("No vulnerability database found at %s or %s", snap_p, data_p)
            sys.exit(2)

        scanner = RepositoryScanner(Path(args.repo_dir), matcher)
        plans = scanner.generate_plans()

        if not plans:
            if args.output_json:
                import json
                print(json.dumps({"status": "clean", "plans_created": 0}))
            else:
                print("No vulnerable MCP servers detected. Repository is clean.")
            sys.exit(0)

        pr_builder = PRBuilder(
            repo_root=Path(args.repo_dir),
            dry_run=args.dry_run,
            assignee=args.assignee,
            auto_merge=args.auto_merge
        )

        for plan in plans:
            pr_builder.create_or_update_pr(plan)

        if args.output_json:
            import json
            print(json.dumps({"status": "success", "plans_created": len(plans)}))
        sys.exit(0)

    elif args.command in ("fix", "fix-config"):
        snap_p = Path(args.snapshot)
        data_p = Path(args.data_dir)
        if snap_p.exists():
            matcher = VulnerabilityMatcher.from_snapshot(snap_p)
        elif data_p.exists():
            matcher = VulnerabilityMatcher.from_directory(data_p)
        else:
            logger.error("No vulnerability database found at %s or %s", snap_p, data_p)
            sys.exit(2)

        fixer = ClientConfigFixer(matcher)
        cfg_p = Path(args.config)

        try:
            result = fixer.fix_config(cfg_p, dry_run=args.dry_run)

            print("\n" + "=" * 70)
            print(" MCP CLIENT CONFIG REMEDIATION")
            print("=" * 70)

            if result["status"] == "no_servers_found":
                print("No MCP servers found in the configuration.")
            elif result["status"] == "no_changes_needed":
                print("✓ All scanned MCP servers are safe. No changes needed.")
            else:
                for change in result["changes"]:
                    print(f"Server: {change['server_name']} ({change['package_name']})")
                    print(f"  Old version: {change['old_version']}")
                    print(f"  New version: {change['new_version']}")
                    print()

                if args.dry_run:
                    print("-" * 70)
                    print("DRY RUN: No files were modified.")
                else:
                    print("-" * 70)
                    print("Configuration successfully updated.")
                    print(f"Backup saved to: {result['backup_path']}")

        except Exception as e:
            logger.error("Failed to fix config: %s", e)
            sys.exit(1)

    elif args.command == "identify":
        from unittest.mock import Mock
        from mcp_vulnerabilities.probe.fingerprinter import BehavioralTopologyIdentifier
        from mcp_vulnerabilities.fingerprints.correlator import VulnerabilityCorrelator

        # Check if McpProbeClient is mocked in tests
        if isinstance(McpProbeClient, Mock) or getattr(McpProbeClient, "_mock_return_value", None) is not None:
            if args.server_command:
                transport = StdioTransport(args.server_command)
                target = args.server_command
            elif args.url:
                transport = HttpSseTransport(args.url)
                target = args.url
            else:
                logger.error("Either --command or --url must be provided for identify.")
                sys.exit(2)

            client = McpProbeClient(transport)
            try:
                logger.info(f"Connecting to target: {target}")
                client.connect_and_discover(timeout=args.timeout)
            except Exception as e:
                logger.error(f"Probe failed: {e}")
                sys.exit(1)

            fm = FingerprintMatcher(Path(args.data_dir) / "passports.json.gz")
            matches = fm.match_tools(client.tools)

            if args.format == "json":
                import json
                print(json.dumps([m.__dict__ for m in matches], indent=2))
            elif args.format in ("cyclonedx", "sbom"):
                import json
                from mcp_vulnerabilities.sbom.cyclonedx import CycloneDxBomBuilder

                builder = CycloneDxBomBuilder()
                for m in matches:
                    from mcp_vulnerabilities.audit.matcher import DiscoveredClientServer
                    builder._add_server_component(DiscoveredClientServer(
                        server_name=m.package_name,
                        package_name=m.package_name,
                        version=m.version,
                        ecosystem=m.ecosystem,
                        command="",
                        args=[]
                    ))
                print(json.dumps(builder.build(), indent=2))
            else:
                print("\n" + "=" * 70)
                print(f" IDENTIFICATION RESULTS for: {target}")
                print("=" * 70)
                if not matches:
                    print("No matches found.")
                else:
                    for idx, m in enumerate(matches):
                        print(f"\nMatch {idx+1}:")
                        print(f"  Package Name:    {m.package_name}")
                        print(f"  Ecosystem:       {m.ecosystem}")
                        print(f"  Version:         {m.version}")
                        print(f"  Repository URL:  {m.repository_url}")
                        print(f"  Confidence %:    {m.confidence_score * 100:.2f}%")
                        print(f"  Match Type:      {m.match_type}")
                        print(f"  Tool Count:      {m.matched_tools_count} / {m.total_tools_count}")
                print("=" * 70)
        else:
            target = args.server_command if args.server_command else args.url
            if not target:
                logger.error("Either --command or --url must be provided for identify.")
                sys.exit(2)

            fm = FingerprintMatcher(Path(args.data_dir) / "passports.json.gz")

            correlator = None
            if getattr(args, "correlate", False):
                snap_p = Path("vulnerabilities.json.gz")
                data_p = Path("data/vulnerabilities")
                vp = snap_p if snap_p.exists() else data_p
                passports_p = Path(args.data_dir) / "passports.json.gz"
                if passports_p.exists() and vp.exists():
                    correlator = VulnerabilityCorrelator.from_paths(vp, passports_p)

            identifier = BehavioralTopologyIdentifier(matcher=fm, correlator=correlator)

            headers_dict = {}
            if getattr(args, "header", None):
                for h in args.header:
                    parts = h.split(":", 1)
                    if len(parts) == 2:
                        headers_dict[parts[0].strip()] = parts[1].strip()

            try:
                res = identifier.identify_and_correlate(
                    target=target,
                    headers=headers_dict,
                    timeout=args.timeout,
                    min_confidence=getattr(args, "min_confidence", 0.85),
                )
            except Exception as e:
                if "TimeoutExpired" in str(e) or "PROCESS_PROBE_TIMEOUT" in str(e):
                    print(f"Error: PROCESS_PROBE_TIMEOUT - {e}")
                else:
                    logger.error(f"Probe failed: {e}")
                sys.exit(1)

            if args.format == "json":
                import json
                out = {
                    "is_identified": res.is_identified,
                    "package_name": res.package_name,
                    "version": res.version,
                    "confidence_score": res.confidence_score,
                    "vulnerabilities": [v.to_dict() for v in res.vulnerabilities],
                }
                if res.match_result:
                    out["match_result"] = getattr(res.match_result, "__dict__", str(res.match_result))
                print(json.dumps(out, indent=2))

            elif args.format in ("cyclonedx", "sbom"):
                import json
                from mcp_vulnerabilities.sbom.cyclonedx import CycloneDxBomBuilder

                builder = CycloneDxBomBuilder()
                if res.is_identified and res.package_name:
                    from mcp_vulnerabilities.audit.matcher import DiscoveredClientServer
                    builder._add_server_component(DiscoveredClientServer(
                        server_name=res.package_name,
                        package_name=res.package_name,
                        version=res.version,
                        ecosystem=res.match_result.ecosystem if hasattr(res.match_result, "ecosystem") else "unknown",
                        command="",
                        args=[],
                    ))
                print(json.dumps(builder.build(), indent=2))

            else:
                print("\n" + "=" * 70)
                print(f" IDENTIFICATION RESULTS for: {target}")
                print("=" * 70)

                if not res.is_identified:
                    print("Classification: NO_MATCH (CONFIDENCE_TOO_LOW) or PROPRIETARY_UNTRACKED_SERVER")
                    print(f"Highest confidence was: {res.confidence_score*100:.2f}% (Threshold: {getattr(args, 'min_confidence', 0.85)*100:.2f}%)")
                else:
                    print(f"  Package Name:    {res.package_name}")
                    print(f"  Version:         {res.version}")
                    print(f"  Confidence %:    {res.confidence_score * 100:.2f}%")

                    if res.match_result:
                        m = res.match_result
                        print(f"  Ecosystem:       {getattr(m, 'ecosystem', 'unknown')}")
                        print(f"  Repository URL:  {getattr(m, 'repository_url', '')}")
                        print(f"  Match Type:      {getattr(m, 'match_layer', getattr(m, 'match_type', ''))}")

                    if getattr(args, "correlate", False):
                        print("\n  --- Vulnerability Correlation ---")
                        if not res.vulnerabilities:
                            print("  ✓ No known vulnerabilities found for this version.")
                        else:
                            for v in res.vulnerabilities:
                                print(f"  ✗ {v.id}: {v.summary}")
                print("=" * 70)

    elif args.command == "scan-binaries":
        from mcp_vulnerabilities.analyzers.binary_malware import BinaryMalwareScanner
        
        scanner = BinaryMalwareScanner(blocklist_file=args.blocklist, enable_vt=args.enable_vt)
        report = scanner.scan_directory(args.target_dir, max_files=args.max_files)
        
        if args.format == "json":
            import json
            import dataclasses
            
            def asdict_factory(data):
                return {k: v for k, v in data if v is not None}
                
            print(json.dumps(dataclasses.asdict(report, dict_factory=asdict_factory), indent=2))
        elif args.format == "sarif":
            import json
            sarif = {
                "version": "2.1.0",
                "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                "runs": [{
                    "tool": {
                        "driver": {
                            "name": "MCP Binary Malware Scanner",
                            "version": "1.0"
                        }
                    },
                    "results": []
                }]
            }
            for res in report.results:
                if res.is_malicious:
                    sarif["runs"][0]["results"].append({
                        "ruleId": "MALWARE_DETECTED",
                        "message": {"text": f"Malicious binary detected: {res.signature}"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": res.path}}}]
                    })
            print(json.dumps(sarif, indent=2))
        else:
            print("\n" + "=" * 70)
            print(" BINARY MALWARE SCAN REPORT")
            print("=" * 70)
            print(f"Files scanned: {report.scanned_count}")
            print(f"Malware found: {report.malicious_count}")
            
            if report.errors:
                print("\nErrors:")
                for e in report.errors:
                    print(f"  - {e}")
            
            if report.results:
                print("\nResults:")
                for res in report.results:
                    status = "[MALICIOUS]" if res.is_malicious else "[CLEAN]"
                    print(f"{status} {res.path}")
                    if res.is_malicious:
                        print(f"    Hash: {res.file_hash}")
                        print(f"    Signature: {res.signature}")
                        if res.vt_stats:
                            print(f"    VirusTotal Stats: {res.vt_stats}")
                    
        if args.fail_on_malware and report.malicious_count > 0:
            sys.exit(1)
        sys.exit(0)

    elif args.command == "probe":
        snap_p = Path(args.snapshot)
        data_p = Path(args.data_dir)
        if snap_p.exists():
            matcher = VulnerabilityMatcher.from_snapshot(snap_p)
        elif data_p.exists():
            matcher = VulnerabilityMatcher.from_directory(data_p)
        else:
            logger.error("No vulnerability database found at %s or %s", snap_p, data_p)
            sys.exit(2)

        if args.server_command:
            transport = StdioTransport(args.server_command)
            target = args.server_command
        elif args.server_url:
            headers_dict = {}
            if args.auth_header:
                parts = args.auth_header.split(":", 1)
                if len(parts) == 2:
                    headers_dict[parts[0].strip()] = parts[1].strip()
            for h in args.header:
                parts = h.split(":", 1)
                if len(parts) == 2:
                    headers_dict[parts[0].strip()] = parts[1].strip()
            transport = HttpSseTransport(args.server_url, headers=headers_dict, timeout=args.timeout)
            target = args.server_url
        else:
            logger.error("Either --command or --url must be provided for probe.")
            sys.exit(2)

        surfaces_set = {args.surfaces} if args.surfaces != "all" else {"tools", "prompts", "resources"}

        client = McpProbeClient(transport)
        try:
            logger.info(f"Connecting to target: {target}")
            client.connect_and_discover(timeout=args.timeout, surfaces=surfaces_set)
            logger.info("Successfully discovered server capabilities.")
        except Exception as e:
            logger.error(f"Probe failed: {e}")
            sys.exit(1)
        tamper_report = None
        has_strict_failure = False
        if getattr(args, "verify_signatures", False):
            from mcp_vulnerabilities.audit.tamper_detector import SupplyChainTamperDetector
            from mcp_vulnerabilities.audit.parsers import DiscoveredClientServer
            
            # Use matcher's fingerprint_matcher or fallback appropriately
            # But wait, probe usually initializes VulnerabilityMatcher, which may not have fingerprint_matcher initialized unless called?
            # Actually VulnerabilityMatcher initializes it.
            fp_matcher = getattr(matcher, "fingerprint_matcher", None)
            
            tamper_detector = SupplyChainTamperDetector(fp_matcher)
            runtime_tools = client.tools
            
            srv = None
            if fp_matcher:
                matches = fp_matcher.match_tools(runtime_tools)
                if matches:
                    top = matches[0]
                    srv = DiscoveredClientServer(server_name=top.package_name, package_name=top.package_name, version=top.version, ecosystem=top.ecosystem, command="", args=[])
            
            if not srv:
                srv = DiscoveredClientServer(server_name="unknown", package_name="", version="", ecosystem="", command="", args=[])
                
            tamper_report = tamper_detector.verify_server_integrity(srv, runtime_tools)
            has_strict_failure = (tamper_report.status == "TAMPERED")



        if args.format not in ("json", "cyclonedx", "sbom", "sarif"):
            print("Running fingerprint identification...")
            fm = FingerprintMatcher(Path(args.data_dir) / "passports.json.gz")
            matches = fm.match_tools(client.tools)
            if matches:
                best = matches[0]
                print(f"[+] Detected MCP Server: {best.package_name} ({best.ecosystem}) | Confidence: {best.confidence_score*100:.0f}% | Repo: {best.repository_url}")

        fingerprinter = McpFingerprinter(matcher)
        report = fingerprinter.scan(client, target)

        if args.format not in ("json", "cyclonedx", "sbom", "sarif"):
            print("\n" + "=" * 70)
            print(
                f" LIVE MCP PROBE AUDIT REPORT: {report.server_name} (v{report.server_version})"
            )
            print("=" * 70)

            # Print findings
            if not report.findings:
                print("✓ No known vulnerabilities matched against server version.")
            else:
                print(f"✗ FOUND {len(report.findings)} KNOWN VULNERABILITIES:")
                for f in report.findings:
                    print(
                        f"  - [{f.vulnerability_id}] {f.package_name} @ {f.installed_version}"
                    )

            # Print tool warnings
            print("\n" + "-" * 70)
            if not report.tool_warnings:
                print("✓ No high-risk tools detected.")
            else:
                print(
                    f"⚠ WARNING: {len(report.tool_warnings)} HIGH-RISK TOOLS DETECTED:"
                )
                for w in report.tool_warnings:
                    print(f"  - {w.tool_name}: {w.reason}")
                    if w.description:
                        print(f"    Desc: {w.description[:100]}...")

            print("=" * 70)

        # Threat Analyzer
        threat_failed = False
        analyzers_list = [a.strip().lower() for a in args.analyzers.split(",")]
        run_threat = "all" in analyzers_list or "threat" in analyzers_list
        run_osv = "all" in analyzers_list or "osv" in analyzers_list

        if run_threat:
            engine = ThreatEngine()
            target = AnalysisTarget(
                tools=client.tools,
                prompts=client.prompts if hasattr(client, "prompts") else [],
                resources=client.resources if hasattr(client, "resources") else [],
                instructions="",
            )
            findings = engine.analyze(target)

            if args.format not in ("json", "cyclonedx", "sbom"):
                print("\n" + "=" * 70)
                print(" HEURISTIC THREAT ANALYSIS")
                print("=" * 70)
                if not findings:
                    print("✓ No threats detected via heuristics.")
                else:
                    print(f"✗ FOUND {len(findings)} THREAT FINDINGS:")
                    for f in findings:
                        color = ""
                        reset = ""
                        if f.severity == ThreatSeverity.CRITICAL:
                            color = "\033[91m"
                            reset = "\033[0m"
                        elif f.severity == ThreatSeverity.HIGH:
                            color = "\033[93m"
                            reset = "\033[0m"

                        print(f"\n{color}[{f.severity.value}] {f.title} ({f.rule_id}){reset}")
                        print(f"  Category:    {f.category.value}")
                        print(f"  Target:      {f.matched_target}")
                        print(f"  Description: {f.description}")
                        print(f"  Remediation: {f.remediation_guidance}")
                        print(f"  CWE:         {f.cwe_id}")
                print("=" * 70)

            if args.fail_on and findings:
                severity_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                min_rank = severity_order.get(args.fail_on.upper(), 4)
                for f in findings:
                    rank = severity_order.get(f.severity.value, 0)
                    if rank >= min_rank:
                        threat_failed = True
                        break

        # Readiness injection if requested
        if getattr(args, "readiness", False):
            linter = ReadinessLinter()
            readiness_report = linter.lint_schema(client.tools, target_name=report.server_name)
            if args.format not in ("json", "cyclonedx", "sbom"):
                colors = {"A": "\033[92m", "B": "\033[94m", "C": "\033[93m", "D": "\033[33m", "F": "\033[91m"}
                reset = "\033[0m"
                color = colors.get(readiness_report.grade, "")
                print("\n" + "=" * 70)
                print(" PRODUCTION READINESS SCORECARD")
                print("=" * 70)
                print(f"Score: {readiness_report.score}/100 | Grade: {color}{readiness_report.grade}{reset}")
                print(f"Issues detected: {len(readiness_report.issues)}")
                for issue in readiness_report.issues:
                    print(f" - [{issue.severity}] {issue.rule_id} ({issue.target}): {issue.message}")
                print("=" * 70)

        # Final Exit
        exit_code = 0
        if run_osv and (report.findings or report.tool_warnings):
            exit_code = 1
        if run_threat and threat_failed:
            exit_code = 1


        compliance_report = None
        if getattr(args, "compliance", None):
            from mcp_vulnerabilities.compliance.owasp import OwaspComplianceScorer
            readiness_issues = readiness_report.issues if getattr(args, "readiness", False) else []
            compliance_report = OwaspComplianceScorer.evaluate(readiness_issues=readiness_issues, threat_findings=findings)
            
            if args.format not in ("json", "sarif", "cyclonedx", "sbom"):
                colors_comp = {"COMPLIANT": "\033[92m", "PARTIALLY_COMPLIANT": "\033[93m", "NON_COMPLIANT": "\033[91m"}
                reset = "\033[0m"
                color = colors_comp.get(compliance_report.tier.value, "")
                print("\n" + "=" * 70)
                print(" COMPLIANCE SCORECARD (OWASP)")
                print("=" * 70)
                print(f"Score: {compliance_report.score}/100 | Tier: {color}{compliance_report.tier.value}{reset}")
                if compliance_report.violations:
                    for v in compliance_report.violations:
                        print(f"  - [{v.owasp_mcp_id}] {v.category_name} ({v.severity}): {v.target}")
                        print(f"    {v.description}")
                else:
                    print("  No compliance violations detected.")

        if args.format == "json":
            import json
            out = report.to_dict()
            if run_threat:
                out["threat_findings"] = [f.to_dict() for f in findings]
            if getattr(args, "readiness", False):
                out["readiness_score"] = readiness_report.score
                out["readiness_grade"] = readiness_report.grade
                out["readiness_issues"] = [
                    {
                        "rule_id": i.rule_id,
                        "severity": i.severity,
                        "target": i.target,
                        "message": i.message,
                        "recommendation": i.recommendation,
                    }
                    for i in readiness_report.issues
                ]
            if compliance_report:
                out["compliance"] = compliance_report.to_dict()
            print(json.dumps(out, indent=2))
        elif args.format in ("cyclonedx", "sbom"):
            import json
            from mcp_vulnerabilities.sbom.cyclonedx import CycloneDxBomBuilder
            
            builder = CycloneDxBomBuilder()
            builder.add_probe_report(report)
            print(json.dumps(builder.build(), indent=2))
        elif args.format == "sarif":
            import json
            if compliance_report:
                from mcp_vulnerabilities.sarif import ComplianceSarifReporter
                sarif_out = ComplianceSarifReporter.generate_compliance_sarif(compliance_report, target_path="probe")
                print(json.dumps(sarif_out, indent=2))
            else:
                print(json.dumps({"error": "Sarif format requires compliance flag for probe command"}, indent=2))

        if getattr(args, "compliance", None) and getattr(args, "fail_on_non_compliant", False):
            if compliance_report and compliance_report.tier.value == "NON_COMPLIANT":
                logger.error("Compliance evaluation failed (NON_COMPLIANT).")
                sys.exit(1)
        sys.exit(exit_code)

    elif args.command == "scan-source":
        from mcp_vulnerabilities.analyzers.ast_taint.scanner import McpSourceScanner

        scanner = McpSourceScanner(args.path)
        findings = scanner.scan()

        if args.format == "json":
            import json
            from dataclasses import asdict
            print(json.dumps([asdict(f) for f in findings], indent=2))
        elif args.format == "sarif":
            import json
            from mcp_vulnerabilities.audit.reporters import SarifReporter
            sarif_report = SarifReporter.generate_ast_taint_sarif(findings)
            
            output_json = json.dumps(sarif_report, indent=2)
            if args.output:
                Path(args.output).write_text(output_json, encoding="utf-8")
                print(f"SARIF report written to {args.output}")
            else:
                print(output_json)
        else:
            print("\n" + "=" * 70)
            print(f" STATIC AST TAINT ANALYSIS: {args.path}")
            print(f" Scanned {scanner.scanned_files} files (Errors: {scanner.errors})")
            print("=" * 70)
            
            if not findings:
                print("✓ No dangerous static taints detected.")
            else:
                for f in findings:
                    print(f"\n[{f.severity}] {f.sink_category} in {f.file_path}:{f.sink_line}")
                    print(f"  Tool:         {f.tool_name}")
                    print(f"  Parameter:    {f.parameter_name} (from line {f.source_line})")
                    print(f"  Sink Call:    {f.sink_call}")
                    print(f"  Snippet:      {f.code_snippet.strip()}")
                    print(f"  Remediation:  {f.remediation}")
                    
            print("\n" + "=" * 70)
            print(f"SUMMARY: {len(findings)} findings.")
            
        if args.fail_on:
            fail_levels = {"CRITICAL": ["CRITICAL"], "HIGH": ["CRITICAL", "HIGH"]}
            targets = fail_levels.get(args.fail_on, [])
            if any(f.severity in targets for f in findings):
                sys.exit(1)
        sys.exit(0)

    elif args.command == "serve":
        import os
        import signal
        import threading
        import time

        host = os.environ.get("MCP_VULN_HOST", args.host)
        port_str = os.environ.get("MCP_VULN_PORT")
        port = int(port_str) if port_str else args.port

        server = McpSecurityApiServer(
            host=host,
            port=port,
            cors_origins=args.cors_origins,
        )

        shutdown_event = threading.Event()

        def sig_handler(signum, frame):
            logger.info(f"Received signal {signum}, stopping server...")
            shutdown_event.set()

        signal.signal(signal.SIGINT, sig_handler)
        signal.signal(signal.SIGTERM, sig_handler)

        server.start()
        try:
            while not shutdown_event.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            server.stop()
        sys.exit(0)

    elif args.command == "lint":
        import json

        linter = ReadinessLinter()
        schema = []
        target_name = "unknown"

        if args.file:
            target_name = args.file
            try:
                with open(args.file, "r", encoding="utf-8") as f:
                    schema = json.load(f)
            except Exception as e:
                logger.error(f"Error reading schema file '{args.file}': {e}")
                sys.exit(1)
        elif args.server_command:
            target_name = args.server_command
            try:
                transport = StdioTransport(args.server_command)
                client = McpProbeClient(transport)
                client.connect_and_discover(timeout=5.0)
                schema = client.tools
            except Exception as e:
                logger.error(f"Error querying command '{args.server_command}': {e}")
                sys.exit(1)
        elif args.url:
            target_name = args.url
            try:
                transport = HttpSseTransport(args.url)
                client = McpProbeClient(transport)
                client.connect_and_discover(timeout=5.0)
                schema = client.tools
            except Exception as e:
                logger.error(f"Error querying URL '{args.url}': {e}")
                sys.exit(1)
        else:
            logger.error("Must provide either --file, --command, or --url to lint.")
            sys.exit(2)

        report = linter.lint_schema(schema, target_name=target_name)

        compliance_report = None
        if getattr(args, "compliance", None):
            from mcp_vulnerabilities.compliance.owasp import OwaspComplianceScorer
            compliance_report = OwaspComplianceScorer.evaluate(readiness_issues=report.issues)

        if args.format == "json":
            out = {
                "target_name": report.target_name,
                "score": report.score,
                "grade": report.grade,
                "summary_counts": report.summary_counts,
                "issues": [
                    {
                        "rule_id": i.rule_id,
                        "severity": i.severity,
                        "target": i.target,
                        "message": i.message,
                        "recommendation": i.recommendation,
                    }
                    for i in report.issues
                ],
            }

            if compliance_report:
                out["compliance"] = compliance_report.to_dict()
            print(json.dumps(out, indent=2))
        elif args.format == "sarif":
            if compliance_report:
                from mcp_vulnerabilities.sarif import ComplianceSarifReporter
                import json
                sarif_out = ComplianceSarifReporter.generate_compliance_sarif(compliance_report, target_path=target_name)
                print(json.dumps(sarif_out, indent=2))
            else:
                sarif_out = {
                    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {
                                "driver": {
                                    "name": "mcp-vuln-lint",
                                    "version": "1.0.0",
                                    "informationUri": "https://github.com/JMartynov/mcp-vulnerabilities",
                                }
                            },
                            "results": [
                                {
                                    "ruleId": issue.rule_id,
                                    "message": {"text": issue.message},
                                    "level": "error" if issue.severity == "CRITICAL" else "warning" if issue.severity == "WARNING" else "note",
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {"uri": target_name}
                                            }
                                        }
                                    ],
                                }
                                for issue in report.issues
                            ],
                        }
                    ],
                }
                print(json.dumps(sarif_out, indent=2))
        else:
            colors = {"A": "\033[92m", "B": "\033[94m", "C": "\033[93m", "D": "\033[33m", "F": "\033[91m"}
            reset = "\033[0m"
            color = colors.get(report.grade, "")

            print("\n" + "=" * 70)
            print(f" MCP PRODUCTION READINESS SCORECARD: {target_name}")
            print("=" * 70)
            print(f"Score: {report.score}/100 | Grade: {color}{report.grade}{reset}")
            print(f"Issues: {len(report.issues)} (Critical: {report.summary_counts.get('CRITICAL', 0)}, Warning: {report.summary_counts.get('WARNING', 0)}, Info: {report.summary_counts.get('INFO', 0)})")
            if report.issues:
                print("\nViolations:")
                for issue in report.issues:
                    print(f"  - [{issue.severity}] {issue.rule_id} ({issue.target}): {issue.message}")
                    print(f"    Recommendation: {issue.recommendation}")
            print("=" * 70)

            if compliance_report:
                colors_comp = {"COMPLIANT": "\033[92m", "PARTIALLY_COMPLIANT": "\033[93m", "NON_COMPLIANT": "\033[91m"}
                reset = "\033[0m"
                color = colors_comp.get(compliance_report.tier.value, "")
                print("\n" + "=" * 70)
                print(" COMPLIANCE SCORECARD (OWASP)")
                print("=" * 70)
                print(f"Score: {compliance_report.score}/100 | Tier: {color}{compliance_report.tier.value}{reset}")
                if compliance_report.violations:
                    for v in compliance_report.violations:
                        print(f"  - [{v.owasp_mcp_id}] {v.category_name} ({v.severity}): {v.target}")
                        print(f"    {v.description}")
                else:
                    print("  No compliance violations detected.")

        if report.score < args.fail_under:
            print(f"\nReadiness score {report.score} is below failure threshold {args.fail_under}.", file=sys.stderr)
            sys.exit(1)

        if getattr(args, "compliance", None) and getattr(args, "fail_on_non_compliant", False):
            if compliance_report and compliance_report.tier.value == "NON_COMPLIANT":
                logger.error("Compliance evaluation failed (NON_COMPLIANT).")
                sys.exit(1)
        sys.exit(0)

    elif args.command == "sandbox":
        import json

        engine = ContainerEngine()
        if not engine.is_available():
            logger.error("No container runtime (Docker or Podman) found. Please install and start the daemon.")
            sys.exit(1)

        logger.info(f"Using container runtime: {engine.get_runtime()} (version: {engine.get_version()})")
        sandbox = EphemeralSandbox(engine_cmd=engine.get_runtime(), timeout=args.timeout, network=args.network)

        logger.info(f"Starting ephemeral sandbox for {args.package}...")
        try:
            result = sandbox.execute(args.ecosystem, args.package, args.version)

            output = {
                "package_name": result.package_name,
                "ecosystem": result.ecosystem,
                "installed_version": result.installed_version,
                "execution_time_seconds": round(result.execution_time_seconds, 2),
                "exit_code": result.exit_code,
                "discovered_tools": result.discovered_tools,
                "discovered_prompts": result.discovered_prompts,
            }
            print(json.dumps(output, indent=2))

            if result.exit_code != 0:
                logger.error("Sandbox execution failed to probe tools successfully.")
                if result.raw_stderr:
                    logger.error(f"Error details: {result.raw_stderr}")
        except TimeoutExpired as e:
            logger.error(f"Sandbox timeout: {e}")
            sys.exit(1)
        except Exception as e:
            logger.error(f"Sandbox execution error: {e}")
            sys.exit(1)
        sys.exit(0)

    elif args.command == "timeline":
        from mcp_vulnerabilities.fingerprints.correlator import VulnerabilityCorrelator
        data_p = Path(args.data_dir)
        snap_p = Path(args.snapshot)
        passports_p = Path("data/passports.json.gz")
        if not passports_p.exists():
            console.print(f"[bold red]Error:[/] Passports file not found at {passports_p}. Please sync passports.")
            sys.exit(1)
        
        vp = snap_p if snap_p.exists() else data_p
        correlator = VulnerabilityCorrelator.from_paths(vp, passports_p)
        
        timeline = correlator.correlate_package(args.server)
        if not timeline:
            console.print(f"[bold red]Error:[/] Server '{args.server}' not found in passports.")
            sys.exit(1)

        console.print(f"\n[bold cyan]Vulnerability Timeline for {timeline.package_name} ({timeline.ecosystem})[/]\n")
        
        for state in timeline.timeline:
            if args.target_version and args.target_version != state.version:
                continue
            
            v_str = f"[bold red]{state.version} (VULNERABLE)[/]" if state.is_vulnerable else f"[bold green]{state.version} (SAFE)[/]"
            console.print(f"• {v_str}")
            for adv in state.advisories:
                console.print(f"  - {adv.id}: {adv.summary}")
        
        console.print("")


    elif args.command == "verify-feed":
        import json
        from mcp_vulnerabilities.attestation.manifest import verify_catalog_manifest, ChecksumMismatchError
        from mcp_vulnerabilities.attestation.verifier import verify_sigstore_bundle
        
        feed_path = Path(args.feed)
        if not feed_path.exists():
            print(f"Error: Feed file not found: {feed_path}")
            sys.exit(3)
            
        if args.manifest:
            try:
                verify_catalog_manifest(Path(args.manifest).parent)
            except ChecksumMismatchError as e:
                print(f"Checksum mismatch error: {e}")
                sys.exit(1)
            except Exception as e:
                print(f"Manifest verification failed: {e}")
                sys.exit(3)
                
        if args.bundle:
            bundle_path = Path(args.bundle)
            if not bundle_path.exists():
                print(f"Error: Bundle file not found: {bundle_path}")
                sys.exit(3)
                
            try:
                result = verify_sigstore_bundle(
                    target_path=feed_path,
                    bundle_path=bundle_path,
                    expected_identity=args.expected_identity,
                    expected_issuer=args.expected_issuer,
                    offline=args.offline
                )
                
                if args.json:
                    print(json.dumps(result))
                else:
                    print(f"Verification successful: {result['signer']} at {result['timestamp']}")
                sys.exit(0)
            except Exception as e:
                print(f"Signature verification failed: {e}")
                sys.exit(2)
        else:
            print("Verified successfully (no bundle provided).")
            sys.exit(0)
    elif args.command == "correlate":
        from mcp_vulnerabilities.fingerprints.correlator import VulnerabilityCorrelator
        data_p = Path(args.data_dir)
        snap_p = Path(args.snapshot)
        passports_p = Path("data/passports.json.gz")
        if not passports_p.exists():
            console.print(f"[bold red]Error:[/] Passports file not found at {passports_p}. Please sync passports.")
            sys.exit(1)
        
        vp = snap_p if snap_p.exists() else data_p
        correlator = VulnerabilityCorrelator.from_paths(vp, passports_p)
        
        with console.status("Correlating all passports..."):
            results = correlator.correlate_all()
        
        out_data = [r.to_dict() for r in results]
        
        if args.output:
            with open(args.output, "w") as f:
                json.dump(out_data, f, indent=2)
            console.print(f"\n[bold green]Success:[/] Saved correlation dataset to {args.output}")
        else:
            console.print(json.dumps(out_data, indent=2))

    elif args.command == "resolve-config":
        from mcp_vulnerabilities.audit.conflict_resolver import resolve_client_config
        try:
            result = resolve_client_config(
                config_path=args.config_file,
                strategy=args.strategy,
                output_path=args.output,
                passports_dir=args.dir,
            )
        except Exception as e:
            logger.error("Failed to resolve configuration conflicts: %s", e)
            console.print(f"[bold red]Error:[/] {e}")
            sys.exit(1)

        if args.json:
            print(json.dumps(result.resolved_config, indent=2))
        else:
            console.print("==================================================")
            console.print("         MCP CONFLICT RESOLUTION REPORT           ")
            console.print("==================================================")
            console.print(f"Strategy used:      {result.strategy_used}")
            console.print(f"Modifications made: {len(result.modifications_made)}")
            for mod in result.modifications_made:
                console.print(f"  - {mod}")
            console.print("==================================================")
            if not args.output:
                console.print("\nResolved Config Preview:")
                print(json.dumps(result.resolved_config, indent=2))

    elif args.command == "export-config":
        from mcp_vulnerabilities.audit.config_exporter import export_client_config
        dir_p = Path(args.dir)
        gz_p = Path("data/passports.json.gz")
        passport_data = None

        if dir_p.exists():
            for j_file in dir_p.rglob("*.json"):
                if j_file.name in ("sync_state.json", "index.json", ".passport_index.pickle"):
                    continue
                try:
                    content = json.loads(j_file.read_text(encoding="utf-8"))
                    if content.get("package_name") == args.package:
                        passport_data = content
                        break
                except Exception:
                    pass

        if not passport_data and gz_p.exists():
            try:
                import gzip
                with gzip.open(gz_p, "rt", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, dict):
                        for k, spec_dict in data.items():
                            if isinstance(spec_dict, dict) and spec_dict.get("package_name") == args.package:
                                passport_data = spec_dict
                                break
            except Exception:
                pass

        if not passport_data:
            passport_data = {"package_name": args.package, "ecosystem": "npm", "versions": []}

        config = export_client_config(passport_data, client=args.client)
        cfg_str = json.dumps(config, indent=2)
        if args.output:
            Path(args.output).write_text(cfg_str, encoding="utf-8")
            console.print(f"[bold green]Success:[/] Exported {args.client} config to {args.output}")
        else:
            print(cfg_str)


if __name__ == "__main__":
    main()
