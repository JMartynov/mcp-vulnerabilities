import re

with open("src/mcp_vulnerabilities/audit/tui.py", "r") as f:
    content = f.read()

draw_header_new = """
        drift_status = "Synced"
        
        posture = "SECURE"
        has_high = False
        for findings in self.findings.values():
            for f in findings:
                if f.severity.upper() == "CRITICAL":
                    posture = "CRITICAL"
                    break
                elif f.severity.upper() == "HIGH":
                    has_high = True
            if posture == "CRITICAL":
                break
        if posture != "CRITICAL" and has_high:
            posture = "HIGH"
        elif posture == "SECURE" and any(len(f) > 0 for f in self.findings.values()):
            posture = "WARNING"
            
        sub_text = f" OS: {platform.system()} | Discovered: {len(self.servers)} Servers | Posture: {posture} | Baseline: {drift_status} "
        self.stdscr.addstr(1, 0, " " * self.width)
"""

content = re.sub(r"        drift_status = \"Synced\".*?self\.stdscr\.addstr\(1, 0, \" \" \* self\.width\)", draw_header_new.strip(), content, flags=re.DOTALL)

with open("src/mcp_vulnerabilities/audit/tui.py", "w") as f:
    f.write(content)
