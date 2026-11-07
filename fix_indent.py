with open("src/mcp_vulnerabilities/audit/tui.py", "r") as f:
    lines = f.readlines()
for i, line in enumerate(lines):
    if "def _audit_servers" in line:
        lines[i] = "    def _audit_servers(self):\n"
    if "def _get_server_badge" in line:
        lines[i] = "    def _get_server_badge(self, server: DiscoveredClientServer) -> Tuple[str, int]:\n"
with open("src/mcp_vulnerabilities/audit/tui.py", "w") as f:
    f.writelines(lines)
