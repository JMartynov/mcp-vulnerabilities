import sys

def run_hub(args=None):
    if not sys.stdout.isatty():
        print("Interactive hub requires an interactive TTY terminal. Use headless CLI commands in CI/CD.")
        sys.exit(1)
        
    while True:
        print("=======================================================")
        print("           🛡️  MCP SECURITY COMMAND HUB  🛡️")
        print("=======================================================")
        print("[1] 🔍 Universal Audit (Scan all 9 AI Clients + Global)")
        print("[2] 🛡️  Supply-Chain Integrity Check (Verify Tool Signatures)")
        print("[3] 📊 View Interactive CVE Vulnerability Timelines")
        print("[4] ⚡ Unknown Server Fingerprint & Live Prober")
        print("[5] 🔧 Multi-Client One-Click Config Auto-Patcher")
        print("[6] 📦 Export Audited Configurations (SARIF / CycloneDX SBOM)")
        print("[0] 🚪 Exit")
        print("=======================================================")
        try:
            choice = input("> ").strip()
        except EOFError:
            break
            
        if choice == "0":
            break
        elif choice == "1":
            print("Launching Universal Audit...")
            from .cli import main as cli_main
            sys.argv = ["mcp-vuln", "audit"]
            try:
                cli_main()
            except SystemExit:
                pass
        elif choice == "2":
            print("Launching Supply-Chain Integrity Check...")
            from .cli import main as cli_main
            sys.argv = ["mcp-vuln", "audit", "--verify-signatures", "--strict-integrity"]
            try:
                cli_main()
            except SystemExit:
                pass
        elif choice == "3":
            print("Launching CVE Vulnerability Timelines...")
            from .cli import main as cli_main
            sys.argv = ["mcp-vuln", "search"]
            try:
                cli_main()
            except SystemExit:
                pass
        elif choice == "4":
            print("Launching Unknown Server Fingerprint & Live Prober...")
            print("To use the prober, run 'mcp-vuln probe --stdio <command>' directly.")
        elif choice == "5":
            print("Launching Multi-Client One-Click Config Auto-Patcher...")
            from .cli import main as cli_main
            sys.argv = ["mcp-vuln", "fix", "--all-clients"]
            try:
                cli_main()
            except SystemExit:
                pass
        elif choice == "6":
            print("Launching Export Audited Configurations...")
            from .cli import main as cli_main
            sys.argv = ["mcp-vuln", "audit", "--format", "sarif"]
            try:
                cli_main()
            except SystemExit:
                pass
        else:
            print("Invalid choice. Please enter a number between 0 and 6.")
            
if __name__ == "__main__":
    run_hub()
