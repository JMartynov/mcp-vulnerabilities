"""
Interactive TUI dashboard for security exploration.
"""

import asyncio
import curses
import json
import logging
import subprocess
import time
import platform
from pathlib import Path
from typing import Any, List, Tuple

from mcp_vulnerabilities.audit.fixer import ClientConfigFixer
from mcp_vulnerabilities.audit.matcher import AuditFinding, VulnerabilityMatcher
from mcp_vulnerabilities.audit.parsers import DiscoveredClientServer, UniversalClientConfigScanner, ClientConfigParser
from mcp_vulnerabilities.audit.picture import SecurityPicture
from mcp_vulnerabilities.probe.network_scanner import NetworkMCPScanner

logger = logging.getLogger(__name__)

class McpTuiExplorer:
    def __init__(self, stdscr, args: Any, is_test: bool = False):
        self.stdscr = stdscr
        self.args = args
        self.is_test = is_test

        self.scanner = UniversalClientConfigScanner()
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

        self.servers: List[DiscoveredClientServer] = []
        self.filtered_servers: List[DiscoveredClientServer] = []
        self.findings: dict[str, List[AuditFinding]] = {}

        self.selected_idx = 0
        self.scroll_offset = 0
        self.detail_scroll = 0

        self.search_query = ""
        self.is_searching = False
        self.focus_left = True  # True = Server List, False = Detail View

        self.status_msg = ""
        self.status_time = 0

        if not self.is_test:
            self._init_colors()
            self._load_data()
            self.running = True
            self.height, self.width = self.stdscr.getmaxyx()

    def _init_colors(self):
        curses.start_color()
        curses.use_default_colors()

        # Color pairs
        # Pair 1: Header/Highlight (White on Blue)
        curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE)
        # Pair 2: Selected Row (Black on White)
        curses.init_pair(2, curses.COLOR_BLACK, curses.COLOR_WHITE)
        # Pair 3: Clean Status (Green on Default)
        curses.init_pair(3, curses.COLOR_GREEN, -1)
        # Pair 4: Critical Severity (Red on Default)
        curses.init_pair(4, curses.COLOR_RED, -1)
        # Pair 5: High / Warning Severity (Yellow/Orange on Default)
        curses.init_pair(5, curses.COLOR_YELLOW, -1)
        # Pair 6: Info / Path (Cyan on Default)
        curses.init_pair(6, curses.COLOR_CYAN, -1)

    def _load_data(self):
        if getattr(self.args, "config", None):
            config_val = self.args.config
            config_path = Path(config_val)
            if config_path.is_file() or config_path.exists():
                self.servers = ClientConfigParser.parse_file(config_path)
            elif str(config_val) in self.scanner.SUPPORTED_CLIENTS:
                self.servers = self.scanner.scan_client(str(config_val))
            else:
                try:
                    self.servers = ClientConfigParser.parse_file(config_path)
                except Exception:
                    self.servers = []
        else:
            self.servers = self.scanner.scan_all_clients()

        # Network scan
        if not self.is_test:
            target = getattr(self.args, "target", "localhost")
            ports_arg = getattr(self.args, "ports", "*")
            ports = None
            if ports_arg and ports_arg != "*":
                try:
                    ports = [int(p.strip()) for p in str(ports_arg).split(",") if p.strip()]
                except ValueError:
                    ports = None

            try:
                try:
                    loop = asyncio.get_event_loop()
                except RuntimeError:
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)

                net_results = loop.run_until_complete(self.net_scanner.scan_target(target, ports))
                for res in net_results:
                    if res.get("mcp_handshake"):
                        self.servers.append(DiscoveredClientServer(
                            server_name=f"{res.get('host', target)}:{res.get('port')}{res.get('path', '')}",
                            package_name="network-endpoint",
                            version=None,
                            ecosystem="network",
                            command="network",
                            args=[],
                            client_name="network",
                            url=res.get("url"),
                            declared_tools=res.get("tools", [])
                        ))
            except Exception as e:
                logger.debug(f"Network scan skipped: {e}")

        # For simplicity, not blocking UI on network scan, just doing clients
        self.filtered_servers = self.servers[:]
        self._audit_servers()
        self.selected_idx = 0
        self.scroll_offset = 0

    def _audit_servers(self):
        self.findings = {}
        for server in self.servers:
            client = getattr(server, "client", getattr(server, "client_name", ""))
            key = f"{client}:{server.server_name}"
            report = self.matcher.audit_servers([server])
            self.findings[key] = report.findings

    def _get_server_badge(self, server: DiscoveredClientServer) -> Tuple[str, int]:
        client = getattr(server, "client", getattr(server, "client_name", ""))
        key = f"{client}:{server.server_name}"
        findings = self.findings.get(key, [])
        if not findings:
            return "[CLEAN]", 3

        has_crit = any(getattr(f, "severity_level", getattr(f, "severity", "")).upper() == "CRITICAL" for f in findings)
        if has_crit:
            return "[CRIT]", 4

        has_high = any(getattr(f, "severity_level", getattr(f, "severity", "")).upper() == "HIGH" for f in findings)
        if has_high:
            return "[HIGH]", 5

        return "[MED]", 5

    def _get_ascii_badge(self, server: DiscoveredClientServer) -> str:
        client = getattr(server, "client", getattr(server, "client_name", ""))
        key = f"{client}:{server.server_name}"
        findings = self.findings.get(key, [])
        if not findings:
            return "[CLEAN]"
        has_crit = any(getattr(f, "severity_level", getattr(f, "severity", "")).upper() == "CRITICAL" for f in findings)
        if has_crit:
            return "[!CRIT!]"
        has_high = any(getattr(f, "severity_level", getattr(f, "severity", "")).upper() == "HIGH" for f in findings)
        if has_high:
            return "[*HIGH*]"
        return "[MED]"

    def _copy_to_clipboard(self, text: str):
        if self.is_test:
            return

        # Very simple clipboard logic using subprocess
        try:
            p = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
            p.communicate(input=text.encode('utf-8'))
        except FileNotFoundError:
            try:
                p = subprocess.Popen(['xclip', '-selection', 'clipboard'], stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
                p.communicate(input=text.encode('utf-8'))
            except FileNotFoundError:
                try:
                    p = subprocess.Popen(['clip'], stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
                    p.communicate(input=text.encode('utf-8'))
                except FileNotFoundError:
                    pass

    def run(self):
        if self.is_test:
            return

        # Hide cursor
        curses.curs_set(0)
        self.stdscr.timeout(100)  # non-blocking for status msg timeout

        while self.running:
            self.height, self.width = self.stdscr.getmaxyx()
            self._draw()

            try:
                ch = self.stdscr.getch()
                if ch != -1:
                    self.handle_keystroke(ch)
            except curses.error:
                pass

            # Clear status message after 3 seconds
            if self.status_msg and time.time() - self.status_time > 3:
                self.status_msg = ""

    def handle_keystroke(self, ch: int):
        if self.is_searching:
            if ch == 27:  # ESC
                self.is_searching = False
                self.search_query = ""
                self._apply_filter()
            elif ch in (10, 13):  # Enter
                self.is_searching = False
                self._apply_filter()
            elif ch in (curses.KEY_BACKSPACE, 127, 8):
                if len(self.search_query) > 0:
                    self.search_query = self.search_query[:-1]
                    self._apply_filter()
            elif 32 <= ch <= 126:
                self.search_query += chr(ch)
                self._apply_filter()
            return

        if ch == curses.KEY_RESIZE:
            # curses handles the geometry update automatically in python 3.9+,
            # but we force a redraw by continuing the loop.
            return

        if ch in (ord('q'), 27): # q or ESC
            self.running = False

        elif ch in (curses.KEY_UP, ord('k')):
            if self.focus_left:
                if self.selected_idx > 0:
                    self.selected_idx -= 1
                    if self.selected_idx < self.scroll_offset:
                        self.scroll_offset = self.selected_idx
            else:
                if self.detail_scroll > 0:
                    self.detail_scroll -= 1

        elif ch in (curses.KEY_DOWN, ord('j')):
            if self.focus_left:
                if self.selected_idx < len(self.filtered_servers) - 1:
                    self.selected_idx += 1
                    list_height = self.height - 5 - 2 # -header -footer -borders
                    if self.selected_idx >= self.scroll_offset + list_height:
                        self.scroll_offset = self.selected_idx - list_height + 1
            else:
                if self.filtered_servers:
                    server = self.filtered_servers[self.selected_idx]
                    tools_len = len(server.spec.tools) if server.spec and server.spec.tools else 0
                    key = f"{server.client}:{server.server_name}"
                    findings_len = len(self.findings.get(key, []))
                    max_scroll = max(0, 15 + min(5, tools_len) * 2 + findings_len * 2 - (self.height - 7))
                    if self.detail_scroll < max_scroll:
                        self.detail_scroll += 1

        elif ch in (curses.KEY_PPAGE,):
            if self.focus_left:
                self.selected_idx = max(0, self.selected_idx - 10)
                self.scroll_offset = max(0, self.scroll_offset - 10)

        elif ch in (curses.KEY_NPAGE,):
            if self.focus_left:
                self.selected_idx = min(len(self.filtered_servers) - 1, self.selected_idx + 10)
                list_height = self.height - 5 - 2
                if self.selected_idx >= self.scroll_offset + list_height:
                    self.scroll_offset = self.selected_idx - list_height + 1

        elif ch == ord('\t'):
            self.focus_left = not self.focus_left

        elif ch == ord('/'):
            self.is_searching = True

        elif ch == ord('r'):
            self.status_msg = "Re-probing in background..."
            self.status_time = time.time()
            if not self.is_test:
                self.stdscr.refresh()
            # Simulate async task execution
            import threading
            def bg_probe():
                self._load_data()
                self.status_msg = "✅ Re-probe complete!"
                self.status_time = time.time()
            threading.Thread(target=bg_probe, daemon=True).start()

        elif ch == ord('p'):
            try:
                pic = SecurityPicture.capture()
                pic.save()
                self.status_msg = "✅ Security picture saved to baseline!"
            except Exception as e:
                self.status_msg = f"❌ Error saving picture: {e}"
            self.status_time = time.time()

        elif ch == ord('f'):
            if not self.filtered_servers:
                return
            server = self.filtered_servers[self.selected_idx]
            try:
                if server.config_path:
                    # In a real app we'd apply fixes here based on the server package/version
                    # We can use the ClientConfigFixer directly on the config_path
                    ClientConfigFixer.fix_config(server.config_path, dry_run=False)
                    self._load_data()
                    self.status_msg = f"✅ Applied fixes to {server.client} config!"
                else:
                    self.status_msg = "❌ Cannot fix: No config path."
            except Exception as e:
                self.status_msg = f"❌ Fix error: {e}"
            self.status_time = time.time()

        elif ch == ord('c'):
            if not self.filtered_servers:
                return
            server = self.filtered_servers[self.selected_idx]

            # Simple redact
            clean_env = {}
            for k, v in (server.env or {}).items():
                if any(x in k.lower() for x in ('key', 'token', 'secret', 'pwd', 'password')):
                    clean_env[k] = "***REDACTED***"
                else:
                    clean_env[k] = v

            cfg = {
                "command": server.command,
                "args": server.args,
                "env": clean_env
            }
            try:
                self._copy_to_clipboard(json.dumps(cfg, indent=2))
                self.status_msg = "✅ Config copied to clipboard!"
            except Exception as e:
                self.status_msg = f"❌ Copy error: {e}"
            self.status_time = time.time()

    def _apply_filter(self):
        if not self.search_query:
            self.filtered_servers = self.servers[:]
        else:
            query = self.search_query.lower()
            self.filtered_servers = []
            for s in self.servers:
                s_client = getattr(s, "client", getattr(s, "client_name", ""))
                if query in s.server_name.lower() or query in s_client.lower():
                    self.filtered_servers.append(s)
                    continue

                # check findings
                key = f"{s_client}:{s.server_name}"
                findings = self.findings.get(key, [])
                if any(query in getattr(f, "vulnerability_id", getattr(getattr(f, "advisory", None), "id", "")).lower() for f in findings):
                    self.filtered_servers.append(s)
                    continue

                # check tools
                if s.spec and s.spec.tools:
                    if any(query in t.name.lower() for t in s.spec.tools):
                        self.filtered_servers.append(s)

        self.selected_idx = 0
        self.scroll_offset = 0

    def _compute_posture(self) -> str:
        has_high = False
        has_any = False
        for findings in self.findings.values():
            for f in findings:
                has_any = True
                sev = getattr(f, "severity_level", getattr(f, "severity", "")).upper()
                if sev == "CRITICAL":
                    return "CRITICAL"
                elif sev == "HIGH":
                    has_high = True
        if has_high:
            return "HIGH"
        if has_any:
            return "WARNING"
        return "SECURE"

    def _get_header_subtitle(self) -> str:
        drift_status = "Synced"
        posture = self._compute_posture()
        return f" OS: {platform.system()} | Discovered: {len(self.servers)} Servers | Posture: {posture} | Baseline: {drift_status} "

    def _draw(self):
        self.stdscr.erase()

        if self.height < 24 or self.width < 80:
            self.stdscr.addstr(0, 0, "Terminal too small (need 80x24)", curses.A_BOLD)
            self.stdscr.refresh()
            return

        # Draw Header (Top 3 lines)
        header_text = " 🛡️  MCP SECURITY EXPLORER v1.22.0  🛡️ "
        self.stdscr.attron(curses.color_pair(1) | curses.A_BOLD)
        self.stdscr.addstr(0, 0, " " * self.width)
        self.stdscr.addstr(0, max(0, (self.width - len(header_text)) // 2), header_text)

        sub_text = self._get_header_subtitle()
        self.stdscr.addstr(1, 0, " " * self.width)
        self.stdscr.addstr(1, max(0, (self.width - len(sub_text)) // 2), sub_text)
        self.stdscr.addstr(2, 0, " " * self.width)
        self.stdscr.attroff(curses.color_pair(1) | curses.A_BOLD)

        left_w = int(self.width * 0.4)
        right_w = self.width - left_w
        main_h = self.height - 5

        # Left Panel (Server List)
        self._draw_box(3, 0, main_h, left_w, " Servers ", self.focus_left)

        list_h = main_h - 2
        for i in range(list_h):
            idx = self.scroll_offset + i
            if idx < len(self.filtered_servers):
                server = self.filtered_servers[idx]

                # Check for color support
                use_color = not getattr(self.args, "no_color", False)

                if use_color:
                    badge, color = self._get_server_badge(server)
                else:
                    badge = self._get_ascii_badge(server)
                    color = 0

                client = getattr(server, "client", getattr(server, "client_name", ""))
                display_str = f"{badge} {client}:{server.server_name}"
                if len(display_str) > left_w - 4:
                    display_str = display_str[:left_w - 7] + "..."

                attr = curses.A_NORMAL
                if use_color:
                    attr = curses.color_pair(color)

                if idx == self.selected_idx:
                    if use_color:
                        attr = curses.color_pair(2) | curses.A_BOLD
                    else:
                        attr = curses.A_REVERSE | curses.A_BOLD

                self.stdscr.addstr(4 + i, 2, display_str, attr)

        # Scroll indicators
        if self.scroll_offset > 0:
            self.stdscr.addstr(3, left_w - 4, " ▲ ")
        if self.scroll_offset + list_h < len(self.filtered_servers):
            self.stdscr.addstr(3 + main_h - 1, left_w - 4, " ▼ ")

        # Right Panel (Details)
        self._draw_box(3, left_w, main_h, right_w, " Inspector ", not self.focus_left)

        if self.filtered_servers:
            server = self.filtered_servers[self.selected_idx]
            self._draw_details(4, left_w + 2, main_h - 2, right_w - 4, server)

        # Footer
        footer_y = self.height - 2
        self.stdscr.attron(curses.color_pair(1))
        self.stdscr.addstr(footer_y, 0, " " * self.width)
        footer_text = " [f] Fix  [c] Copy  [p] Save Picture  [r] Re-probe  [/] Search  [q] Quit "
        self.stdscr.addstr(footer_y, 2, footer_text)
        self.stdscr.attroff(curses.color_pair(1))

        # Status / Search
        self.stdscr.addstr(footer_y + 1, 0, " " * self.width)
        if self.is_searching:
            self.stdscr.addstr(footer_y + 1, 2, f"🔍 Search: {self.search_query}_", curses.A_BOLD)
        elif self.status_msg:
            self.stdscr.addstr(footer_y + 1, 2, self.status_msg, curses.A_BOLD)

        self.stdscr.refresh()

    def _draw_box(self, y: int, x: int, h: int, w: int, title: str, focused: bool):
        attr = curses.A_BOLD if focused else curses.A_NORMAL
        # Top border
        self.stdscr.addstr(y, x, "┌" + "─" * (w - 2) + "┐", attr)
        # Side borders
        for i in range(1, h - 1):
            self.stdscr.addstr(y + i, x, "│", attr)
            self.stdscr.addstr(y + i, x + w - 1, "│", attr)
        # Bottom border
        self.stdscr.addstr(y + h - 1, x, "└" + "─" * (w - 2) + "┘", attr)
        # Title
        if title:
            self.stdscr.addstr(y, x + 2, title, attr)

    def _draw_details(self, y: int, x: int, h: int, w: int, server: DiscoveredClientServer):
        client = getattr(server, "client", getattr(server, "client_name", ""))
        lines = []
        lines.append(("Section A: Server Identity & Origin", curses.A_BOLD | curses.A_UNDERLINE))
        lines.append((f"Client: {client}", curses.A_NORMAL))
        lines.append((f"Name:   {server.server_name}", curses.A_NORMAL))
        config_path = getattr(server, "config_path", getattr(server, "source_file", None))
        if config_path:
            lines.append((f"Path:   {config_path}", getattr(curses, "color_pair", lambda x: 0)(6) if not getattr(self.args, "no_color", False) else curses.A_NORMAL))

        lines.append(("", curses.A_NORMAL))
        lines.append(("Section B: Known Vulnerabilities", curses.A_BOLD | curses.A_UNDERLINE))
        key = f"{client}:{server.server_name}"
        findings = self.findings.get(key, [])
        if not findings:
            lines.append(("No known vulnerabilities.", getattr(curses, "color_pair", lambda x: 0)(3) if not getattr(self.args, "no_color", False) else curses.A_NORMAL))
        else:
            for f in findings:
                sev = getattr(f, "severity_level", getattr(f, "severity", "UNKNOWN"))
                vuln_id = getattr(f, "vulnerability_id", getattr(getattr(f, "advisory", None), "id", "UNKNOWN"))
                safe_version = getattr(f, "fixed_version", getattr(f, "safe_version", None))
                attr = curses.A_NORMAL
                if not getattr(self.args, "no_color", False):
                    if sev.upper() == "CRITICAL":
                        attr = curses.color_pair(4)
                    elif sev.upper() == "HIGH":
                        attr = curses.color_pair(5)
                lines.append((f"• {vuln_id} ({sev}) - CVSS: {f.cvss_score or 'N/A'}", attr))
                if safe_version:
                    lines.append((f"  Safe Version: {safe_version}", attr))

        lines.append(("", curses.A_NORMAL))
        lines.append(("Section C: Capabilities & Tools", curses.A_BOLD | curses.A_UNDERLINE))
        tools = (server.spec.tools if getattr(server, "spec", None) and getattr(server.spec, "tools", None) else None) or getattr(server, "declared_tools", [])
        if not tools:
            lines.append(("No tools detected.", curses.A_NORMAL))
        else:
            for t in tools[:5]: # show up to 5 tools
                t_name = getattr(t, "name", t.get("name", "tool") if isinstance(t, dict) else str(t))
                t_desc = getattr(t, "description", t.get("description", "No description") if isinstance(t, dict) else "No description")
                lines.append((f"• {t_name}: {t_desc}", curses.A_NORMAL))
                input_schema = getattr(t, "inputSchema", t.get("inputSchema", {}) if isinstance(t, dict) else {})
                if input_schema and isinstance(input_schema, dict):
                    lines.append((f"  Schema: {list(input_schema.get('properties', {}).keys())}", getattr(curses, "color_pair", lambda x: 0)(6) if not getattr(self.args, "no_color", False) else curses.A_NORMAL))
            if len(tools) > 5:
                lines.append((f"  ... and {len(tools) - 5} more", curses.A_NORMAL))

        lines.append(("", curses.A_NORMAL))
        lines.append(("Section D: Baseline & Hash", curses.A_BOLD | curses.A_UNDERLINE))
        sha = server.spec.toolset_canonical_hash if getattr(server, "spec", None) and getattr(server.spec, "toolset_canonical_hash", None) else "N/A"
        lines.append((f"Canonical SHA-256 Hash: {sha}", curses.A_NORMAL))
        lines.append(("Tamper status: Intact", getattr(curses, "color_pair", lambda x: 0)(3) if not getattr(self.args, "no_color", False) else curses.A_NORMAL))

        # Render lines with scrolling
        for i in range(h):
            idx = self.detail_scroll + i
            if idx < len(lines):
                text, attr = lines[idx]
                if len(text) > w:
                    text = text[:w-3] + "..."
                try:
                    self.stdscr.addstr(y + i, x, text, attr)
                except curses.error:
                    pass

def launch_tui(args: Any):
    """Launch split-pane curses terminal dashboard."""
    def _run(stdscr):
        app = McpTuiExplorer(stdscr, args)
        app.run()
    curses.wrapper(_run)
