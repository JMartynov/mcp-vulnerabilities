import re

with open("src/mcp_vulnerabilities/audit/tui.py", "r") as f:
    content = f.read()

# Add imports
imports = """
import asyncio
import curses
import json
import logging
import subprocess
import time
import platform
from pathlib import Path
from typing import Any, List, Tuple
"""
content = re.sub(r"import curses.*?from typing import Any, List, Tuple", imports.strip(), content, flags=re.DOTALL)

# Update VulnerabilityMatcher initialization
matcher_init = """
        # Initialize network scanner with 0 concurrency in test mode to avoid actually running
        self.net_scanner = NetworkMCPScanner(max_concurrency=1 if self.is_test else 64)
        
        # We need a matcher, ideally loaded from state
        # In a real app we'd load the state/catalog properly
        def load_advisories():
            snap_path = Path("vulnerabilities.json.gz")
            if snap_path.exists():
                return VulnerabilityMatcher.from_snapshot(snap_path).advisories
            dir_path = Path("data/vulnerabilities")
            if dir_path.exists():
                return VulnerabilityMatcher.from_directory(dir_path).advisories
            return []
            
        self.matcher = VulnerabilityMatcher(load_advisories())
"""
content = re.sub(r"        # Initialize network scanner.*?self\.matcher = VulnerabilityMatcher\(\[\]\)", matcher_init.strip(), content, flags=re.DOTALL)

# Add ClientConfigParser import if missing
if "ClientConfigParser" not in content:
    content = content.replace("from mcp_vulnerabilities.audit.parsers import DiscoveredClientServer, UniversalClientConfigScanner", "from mcp_vulnerabilities.audit.parsers import DiscoveredClientServer, UniversalClientConfigScanner, ClientConfigParser")

# Update _load_data
load_data_new = """
    def _load_data(self):
        if getattr(self.args, "config", None):
            self.servers = ClientConfigParser.parse_file(Path(self.args.config))
        else:
            self.servers = self.scanner.scan_all_clients()
            
        # Network scan
        if not self.is_test:
            target = getattr(self.args, "target", "localhost")
            ports_arg = getattr(self.args, "ports", "*")
            ports = None
            if ports_arg != "*":
                ports = [int(p.strip()) for p in ports_arg.split(",")]
            
            try:
                loop = asyncio.get_event_loop()
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                
            net_results = loop.run_until_complete(self.net_scanner.scan_target(target, ports))
            for res in net_results:
                if res.get("mcp_handshake"):
                    self.servers.append(DiscoveredClientServer(
                        server_name=f"{res['host']}:{res['port']}{res['path']}",
                        package_name="network-endpoint",
                        version=None,
                        ecosystem="network",
                        command="network",
                        args=[],
                        client_name="network",
                        url=res['url'],
                        declared_tools=res.get("tools", [])
                    ))
            
        # For simplicity, not blocking UI on network scan, just doing clients
        self.filtered_servers = self.servers[:]
        self._audit_servers()
        self.selected_idx = 0
        self.scroll_offset = 0
"""
content = re.sub(r"    def _load_data\(self\):.*?self\.scroll_offset = 0", load_data_new.strip(), content, flags=re.DOTALL)

with open("src/mcp_vulnerabilities/audit/tui.py", "w") as f:
    f.write(content)
