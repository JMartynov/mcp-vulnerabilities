import re

with open("src/mcp_vulnerabilities/cli.py", "r") as f:
    content = f.read()

# Replace in discover
discover_find = """    disc_p.add_argument(
        "--no-glama", action="store_true", help="Skip Glama.ai discovery"
    )"""
discover_repl = """    disc_p.add_argument(
        "--no-glama", action="store_true", help="Skip Glama.ai discovery"
    )
    disc_p.add_argument("--prune", action="store_true", help="Prune dead or tombstoned servers")
    disc_p.add_argument("--prune-archived", action="store_true", help="Prune archived repositories")
    disc_p.add_argument("--prune-deleted", action="store_true", help="Prune deleted repositories")
    disc_p.add_argument("--offline-backoff", action="store_true", help="Enable exponential backoff for offline endpoints")"""
content = content.replace(discover_find, discover_repl)

# Replace in sync
sync_find = """    sync_p.add_argument(
        "--notify-webhooks",
        action="store_true",
        help="Dispatch webhooks for new critical/high advisories",
    )"""
sync_repl = """    sync_p.add_argument(
        "--notify-webhooks",
        action="store_true",
        help="Dispatch webhooks for new critical/high advisories",
    )
    sync_p.add_argument("--prune", action="store_true", help="Prune dead or tombstoned servers")
    sync_p.add_argument("--prune-archived", action="store_true", help="Prune archived repositories")
    sync_p.add_argument("--prune-deleted", action="store_true", help="Prune deleted repositories")
    sync_p.add_argument("--offline-backoff", action="store_true", help="Enable exponential backoff for offline endpoints")"""
content = content.replace(sync_find, sync_repl)

discover_handler_find = """    elif args.command == "discover":
        orchestrator = McpDiscoveryOrchestrator(catalog_file=args.catalog_file)
        servers = orchestrator.run_discovery(
            include_npm=not args.no_npm,
            include_pypi=not args.no_pypi,
            include_github=not args.no_github,
            include_other_registries=not args.no_registries,
            include_smithery=not args.no_smithery,
            include_glama=not args.no_glama,
        )"""
discover_handler_repl = """    elif args.command == "discover":
        orchestrator = McpDiscoveryOrchestrator(catalog_file=args.catalog_file)
        servers = orchestrator.run_discovery(
            include_npm=not args.no_npm,
            include_pypi=not args.no_pypi,
            include_github=not args.no_github,
            include_other_registries=not args.no_registries,
            include_smithery=not args.no_smithery,
            include_glama=not args.no_glama,
            include_pruning=args.prune or args.prune_archived or args.prune_deleted,
            offline_backoff=args.offline_backoff
        )"""
content = content.replace(discover_handler_find, discover_handler_repl)

sync_handler_find = """            include_gitlab_sync=args.include_gitlab,
            include_cisa_kev=True,
            include_verity_catalog=True,
            offline_fallback_fixtures="tests/fixtures/osv"
            if not args.live_api
            else None,
            reset_checkpoints=args.reset_state,
        )"""
sync_handler_repl = """            include_gitlab_sync=args.include_gitlab,
            include_cisa_kev=True,
            include_verity_catalog=True,
            offline_fallback_fixtures="tests/fixtures/osv"
            if not args.live_api
            else None,
            reset_checkpoints=args.reset_state,
            include_pruning=args.prune or args.prune_archived or args.prune_deleted,
        )"""
content = content.replace(sync_handler_find, sync_handler_repl)

with open("src/mcp_vulnerabilities/cli.py", "w") as f:
    f.write(content)
