import sys
import re
import signal
from typing import Any

ANSI_ESCAPE_PATTERN = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')

def sanitize_ansi(text: str) -> str:
    """Strips terminal escape sequences from output to prevent injection."""
    return ANSI_ESCAPE_PATTERN.sub('', text)

def restore_terminal():
    # Restore standard terminal state
    sys.stdout.write("\033[?25h") # Cursor visible
    sys.stdout.write("\033[?1049l") # Exit alternate screen buffer
    sys.stdout.flush()

def handle_sigint(sig, frame):
    restore_terminal()
    print("\nInterrupted by user. Exiting.")
    sys.exit(0)

def do_fix_multi_client(args=None):
    from mcp_vulnerabilities.audit.fixer import ClientConfigFixer
    from mcp_vulnerabilities.audit.matcher import VulnerabilityMatcher
    from pathlib import Path
    
    # Simple setup
    try:
        matcher = VulnerabilityMatcher.from_directory(Path("data/vulnerabilities"))
    except Exception:
        # Dummy matcher if data is not available
        matcher = VulnerabilityMatcher()
    
    fixer = ClientConfigFixer(matcher)
    
    # Run fix_all_clients with dry_run=True first
    print("Scanning client configurations...")
    results = fixer.fix_all_clients(dry_run=True)
    
    if not results:
        print("No configurable clients found or no changes needed.")
        return
        
    changes_found = [res for res in results if res.get("status") in ("dry_run", "success") and res.get("changes")]
    
    if not changes_found:
        print("All client configurations are up-to-date and secure.")
        return
        
    print("\n--- Proposed Fixes ---")
    for idx, res in enumerate(changes_found):
        client = res.get("client", "unknown")
        path = res.get("path", "")
        print(f"[{idx}] Client: {client} | Config: {path}")
        if "diff" in res:
            print(res["diff"])
        for change in res.get("changes", []):
            print(f"  * {change.get('server_name')}: {change.get('old_version')} -> {change.get('new_version')}")
            
    print("\nEnter the indices of the configurations you want to fix (comma-separated, e.g. 0,2), or 'all':")
    try:
        selection = input("> ").strip().lower()
    except EOFError:
        return
        
    if not selection:
        print("No changes applied.")
        return
        
    selected_indices = set()
    if selection == 'all':
        selected_indices = set(range(len(changes_found)))
    else:
        for p in selection.split(','):
            if p.strip().isdigit():
                idx = int(p.strip())
                if 0 <= idx < len(changes_found):
                    selected_indices.add(idx)
                    
    if not selected_indices:
        print("No valid indices selected.")
        return
        
    # Apply selected
    for idx in selected_indices:
        res = changes_found[idx]
        client = res.get("client")
        print(f"Applying fixes for {client}...")
        fixer.fix_config(Path(res["path"]), dry_run=False, client_name=client)
        
    print("Fixes applied successfully.")

def run_hub(args=None):
    # Non-TTY handling
    is_non_interactive = False
    is_json = False
    if args and getattr(args, "json", False):
        is_json = True
        is_non_interactive = True
    if args and getattr(args, "batch", False):
        is_non_interactive = True
    if not sys.stdout.isatty():
        is_non_interactive = True
        
    if is_non_interactive:
        # Fall back to automated audit
        if is_json:
            sys.argv = ["mcp-vuln", "audit", "--format", "json"]
        else:
            sys.argv = ["mcp-vuln", "audit"]
        from mcp_vulnerabilities.cli import main as cli_main
        try:
            cli_main()
        except SystemExit as e:
            sys.exit(e.code)
        except Exception as e:
            sys.exit(1)
        return

    # Interactive Mode
    signal.signal(signal.SIGINT, handle_sigint)
    
    # Enter alternate screen buffer & hide cursor briefly
    sys.stdout.write("\033[?1049h\033[?25l")
    sys.stdout.flush()
    sys.stdout.write("\033[?25h") # Show cursor for input
    sys.stdout.flush()
    
    try:
        while True:
            # We sanitize the constant banner anyway just in case, though it's static
            banner = """=======================================================
           🛡️  MCP SECURITY COMMAND HUB  🛡️
=======================================================
[1] 🔍 Universal Audit (Scan all 9 AI Clients + Global)
[2] 🛡️  Supply-Chain Integrity Check (Verify Tool Signatures)
[3] 📊 View Interactive CVE Vulnerability Timelines
[4] ⚡ Unknown Server Fingerprint & Live Prober
[5] 🔧 Multi-Client One-Click Config Auto-Patcher
[6] 📦 Export Audited Configurations (SARIF / CycloneDX SBOM)
[0] 🚪 Exit
======================================================="""
            print(sanitize_ansi(banner))
            
            try:
                choice = input(sanitize_ansi("> ")).strip()
            except EOFError:
                break
                
            if choice == "0":
                break
            elif choice == "1":
                print("Launching Universal Audit...")
                from mcp_vulnerabilities.cli import main as cli_main
                sys.argv = ["mcp-vuln", "audit"]
                try:
                    cli_main()
                except SystemExit:
                    pass
            elif choice == "2":
                print("Launching Supply-Chain Integrity Check...")
                from mcp_vulnerabilities.cli import main as cli_main
                sys.argv = ["mcp-vuln", "audit", "--verify-signatures", "--strict-integrity"]
                try:
                    cli_main()
                except SystemExit:
                    pass
            elif choice == "3":
                print("Launching CVE Vulnerability Timelines...")
                from mcp_vulnerabilities.cli import main as cli_main
                sys.argv = ["mcp-vuln", "search"]
                try:
                    cli_main()
                except SystemExit:
                    pass
            elif choice == "4":
                print("Launching Unknown Server Fingerprint & Live Prober...")
                print("To use the prober, run 'mcp-vuln probe --stdio <command>' directly.")
            elif choice == "5":
                do_fix_multi_client(args)
            elif choice == "6":
                print("Launching Export Audited Configurations...")
                from mcp_vulnerabilities.cli import main as cli_main
                sys.argv = ["mcp-vuln", "audit", "--format", "sarif"]
                try:
                    cli_main()
                except SystemExit:
                    pass
            else:
                print("Invalid choice. Please enter a number between 0 and 6.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        restore_terminal()

if __name__ == "__main__":
    run_hub()
