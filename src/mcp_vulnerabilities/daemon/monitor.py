"""
Background monitoring daemon.
"""

from __future__ import annotations

import asyncio
import fcntl
import json
import logging
import os
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from mcp_vulnerabilities.audit.picture import SecurityPicture, SecurityServerRecord
from mcp_vulnerabilities.audit.picture_diff import SecurityDriftReport, SecurityPictureDiffer
from mcp_vulnerabilities.probe.network_scanner import NetworkMCPScanner
from mcp_vulnerabilities.audit.parsers import UniversalClientConfigScanner

logger = logging.getLogger("mcp_vulnerabilities.daemon.monitor")


@dataclass
class MonitorConfig:
    interval_seconds: int = 300
    targets: str = "localhost"
    ports_spec: str = "3000-8800"
    notify_os: bool = False
    webhook_url: str | None = None
    pid_file: Path = Path.home() / ".mcp-vuln" / "run" / "monitor.pid"
    log_file: Path = Path.home() / ".mcp-vuln" / "logs" / "monitor.log"
    baseline_path: Path = Path.home() / ".mcp-vuln" / "state" / "security_picture.json"
    debounce_window_sec: int = 86400  # 24 hours suppression for identical alerts
    alert_cache_file: Path = Path.home() / ".mcp-vuln" / "state" / "alert_cache.json"


class AlertDispatcher:
    def __init__(self, config: MonitorConfig):
        self.config = config
        self.alert_cache: Dict[str, float] = self._load_cache()

    def _load_cache(self) -> Dict[str, float]:
        if self.config.alert_cache_file.exists():
            try:
                return json.loads(self.config.alert_cache_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {}

    def _save_cache(self) -> None:
        self.config.alert_cache_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.config.alert_cache_file.write_text(json.dumps(self.alert_cache), encoding="utf-8")
        except Exception:
            pass

    def _is_debounced(self, alert_id: str) -> bool:
        now = time.time()
        if alert_id in self.alert_cache:
            last_time = self.alert_cache[alert_id]
            if now - last_time < self.config.debounce_window_sec:
                return True
        return False

    def _mark_alert(self, alert_id: str) -> None:
        self.alert_cache[alert_id] = time.time()
        self._save_cache()
        
    def dispatch(self, title: str, message: str, severity: str, alert_id: str, payload: Dict[str, Any]) -> None:
        if self._is_debounced(alert_id):
            logger.debug(f"Alert {alert_id} suppressed by debounce.")
            return

        self._mark_alert(alert_id)

        if self.config.notify_os:
            if sys.platform == "darwin":
                self._send_macos_notification(title, message, severity)
            elif sys.platform.startswith("linux"):
                self._send_linux_notification(title, message, severity)

        if self.config.webhook_url:
            self._send_webhook(title, message, severity, payload)

    def _send_macos_notification(self, title: str, message: str, severity: str) -> None:
        sound = "Basso" if severity in ("CRITICAL", "HIGH") else "Submarine"
        script = f'display notification "{message}" with title "{title}" sound name "{sound}"'
        try:
            subprocess.run(["osascript", "-e", script], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.warning(f"Failed to send macOS notification: {e}")

    def _send_linux_notification(self, title: str, message: str, severity: str) -> None:
        urgency = "critical" if severity in ("CRITICAL", "HIGH") else "normal"
        try:
            subprocess.run(["notify-send", title, message, f"--urgency={urgency}"], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            logger.warning(f"Failed to send Linux notification: {e}")

    def _send_webhook(self, title: str, message: str, severity: str, payload: Dict[str, Any]) -> None:
        url = self.config.webhook_url
        if not url:
            return


        if "slack.com" in url:
            data = {
                "text": f"{title}\n{message}",
                "blocks": [
                    {
                        "type": "header",
                        "text": {
                            "type": "plain_text",
                            "text": f"🚨 {title}"
                        }
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": message
                        }
                    }
                ]
            }
        elif "discord.com" in url:
            data = {
                "content": f"**{title}**\n{message}",
                "embeds": [
                    {
                        "title": title,
                        "description": message,
                        "color": 14753578 if severity in ("CRITICAL", "HIGH") else 15512110
                    }
                ]
            }
        else:
            data = payload

        req = urllib.request.Request(
            url, 
            data=json.dumps(data).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        try:
            with urllib.request.urlopen(req, timeout=10):
                pass
        except Exception as e:
            logger.warning(f"Failed to send webhook: {e}")


def parse_ports_spec(ports_spec: str) -> List[int]:
    ports = set()
    for part in ports_spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                start, end = part.split("-", 1)
                for p in range(int(start), int(end) + 1):
                    ports.add(p)
            except ValueError:
                pass
        else:
            try:
                ports.add(int(part))
            except ValueError:
                pass
    return sorted(list(ports))


class McpMonitorDaemon:
    def __init__(self, config: MonitorConfig):
        self.config = config
        self.running = False
        self.network_scanner = NetworkMCPScanner()
        self.client_scanner = UniversalClientConfigScanner()
        self.dispatcher = AlertDispatcher(self.config)
        
        self.config.pid_file.parent.mkdir(parents=True, exist_ok=True)
        self.config.log_file.parent.mkdir(parents=True, exist_ok=True)
        self.config.baseline_path.parent.mkdir(parents=True, exist_ok=True)

    def _daemonize(self) -> None:
        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            logger.error(f"Fork 1 failed: {e}")
            sys.exit(1)

        os.chdir("/")
        os.setsid()
        os.umask(0)

        try:
            pid = os.fork()
            if pid > 0:
                sys.exit(0)
        except OSError as e:
            logger.error(f"Fork 2 failed: {e}")
            sys.exit(1)

        sys.stdout.flush()
        sys.stderr.flush()

        with open(os.devnull, 'r') as devnull:
            os.dup2(devnull.fileno(), sys.stdin.fileno())
            
        with open(self.config.log_file, 'a') as log_file:
            os.dup2(log_file.fileno(), sys.stdout.fileno())
            os.dup2(log_file.fileno(), sys.stderr.fileno())

    def _write_pid(self) -> None:
        self.pid_fd = open(self.config.pid_file, 'w')
        try:
            fcntl.flock(self.pid_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            logger.error(f"Another instance is already running (locked PID file {self.config.pid_file})")
            sys.exit(1)
            
        self.pid_fd.write(f"{os.getpid()}\n")
        self.pid_fd.flush()

    def _remove_pid(self) -> None:
        if hasattr(self, 'pid_fd'):
            try:
                fcntl.flock(self.pid_fd, fcntl.LOCK_UN)
                self.pid_fd.close()
                if self.config.pid_file.exists():
                    self.config.pid_file.unlink()
            except Exception:
                pass

    def start(self, daemon: bool = False) -> None:
        if daemon:
            self._daemonize()
            
        self._write_pid()
        self._register_signals()
        
        logging.basicConfig(
            level=logging.INFO,
            format="%(asctime)s [%(levelname)s] %(message)s",
            force=True
        )
        logger.info(f"Monitor started with interval {self.config.interval_seconds}s")
        
        self.running = True
        try:
            asyncio.run(self._loop())
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        self.running = False
        self._remove_pid()
        logger.info("Monitor stopped.")

    def _register_signals(self) -> None:
        def handler(signum, frame):
            if signum == signal.SIGHUP:
                logger.info("SIGHUP received, reloading config/baseline.")
                self.dispatcher.alert_cache = self.dispatcher._load_cache()
            else:
                logger.info(f"Received signal {signum}, stopping.")
                self.running = False

        signal.signal(signal.SIGTERM, handler)
        signal.signal(signal.SIGINT, handler)
        signal.signal(signal.SIGHUP, handler)

    async def _loop(self) -> None:
        while self.running:
            try:
                diff = await self.run_monitoring_cycle()
                if diff and diff.is_drift_detected:
                    self._handle_drift(diff)
            except Exception as e:
                logger.error(f"Error in monitoring cycle: {e}")
                
            if not self.running:
                break
                
            await asyncio.sleep(self.config.interval_seconds)

    async def run_monitoring_cycle(self) -> SecurityDriftReport | None:
        ports = parse_ports_spec(self.config.ports_spec)
        endpoints = await self.network_scanner.scan_target(self.config.targets, ports)
        client_servers = self.client_scanner.scan_all_clients()
        
        # Build SecurityPicture from scans
        servers_records = []
        for srv in client_servers:
            servers_records.append(SecurityServerRecord(
                server_name=srv.server_name,
                package_name=srv.package_name or srv.server_name,
                version=srv.version,
                ecosystem=srv.ecosystem,
                canonical_tool_hash=None,
                passport_id=None,
            ))
            
        for ep in endpoints:
            if ep.get("mcp_handshake"):
                name = f"network_{ep['host']}:{ep['port']}{ep['path']}"
                servers_records.append(SecurityServerRecord(
                    server_name=name,
                    package_name=name,
                    version=None,
                    ecosystem="network",
                    canonical_tool_hash=None,
                    passport_id=None,
                ))

        live_picture = SecurityPicture(
            timestamp=datetime.now(timezone.utc).isoformat(),
            scan_target=self.config.targets,
            total_servers=len(servers_records),
            vulnerable_servers=0,
            tampered_servers=0,
            servers=servers_records,
        )
        
        baseline = SecurityPicture.load(self.config.baseline_path)
        if baseline is None:
            logger.info("No baseline found. Saving current as initial baseline.")
            live_picture.save(self.config.baseline_path)
            return None
            
        diff = SecurityPictureDiffer.compare(baseline=baseline, current=live_picture)
        
        # Optionally update baseline if it's drifting (or leave it to manual accept)
        # We don't automatically overwrite baseline unless told to. 
        # But we do need to return the diff.
        return diff

    def _handle_drift(self, diff: SecurityDriftReport) -> None:
        if not diff.is_drift_detected:
            return
            
        payload = {
            "new_vulnerabilities": diff.newly_introduced_vulnerabilities,
            "resolved_vulnerabilities": diff.resolved_vulnerabilities,
            "tamper_incidents": diff.tamper_incidents,
            "added_servers": diff.added_servers,
            "removed_servers": diff.removed_servers,
            "tool_schema_changes": diff.tool_schema_changes,
        }
        
        # Aggregate alert text
        messages = []
        severity = "MEDIUM"
        
        if diff.tamper_incidents:
            severity = "CRITICAL"
            for t in diff.tamper_incidents:
                messages.append(f"Tamper Detected: {t.get('package_name')} - {t.get('reason', t.get('incident', ''))}")
                
        if diff.newly_introduced_vulnerabilities:
            if severity != "CRITICAL":
                severity = "HIGH"
            for v in diff.newly_introduced_vulnerabilities:
                messages.append(f"New Vulnerability: {v.get('package_name')} - {v.get('cve')}")
                
        if diff.added_servers:
            for s in diff.added_servers:
                messages.append(f"Rogue/New Server: {s.get('package_name')}@{s.get('version')}")
                
        if diff.tool_schema_changes:
            for c in diff.tool_schema_changes:
                messages.append(f"Tool Schema Changed: {c.get('package_name')}")

        if not messages:
            return
            
        alert_id = str(hash(json.dumps(payload, sort_keys=True)))
        title = "MCP Security Alert: Posture Drift Detected"
        msg = "\n".join(messages)
        
        self.dispatcher.dispatch(title, msg, severity, alert_id, payload)


def check_status(pid_file: Path) -> bool:
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, 0)
        return True
    except (ValueError, OSError):
        return False


def stop_monitor(pid_file: Path) -> bool:
    if not pid_file.exists():
        return False
    try:
        pid = int(pid_file.read_text().strip())
        os.kill(pid, signal.SIGTERM)
        for _ in range(10):
            try:
                os.kill(pid, 0)
                time.sleep(0.5)
            except OSError:
                if pid_file.exists():
                    pid_file.unlink()
                return True
        return False
    except (ValueError, OSError):
        return False


def install_service(system: str) -> None:
    executable = sys.executable
    script_path = os.path.abspath(sys.argv[0])
    
    if system == "launchd":
        plist_path = Path.home() / "Library/LaunchAgents/com.mcp-vuln.monitor.plist"
        plist_path.parent.mkdir(parents=True, exist_ok=True)
        plist_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.mcp-vuln.monitor</string>
    <key>ProgramArguments</key>
    <array>
        <string>{executable}</string>
        <string>{script_path}</string>
        <string>monitor</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
"""
        plist_path.write_text(plist_content)
        print(f"Service installed to {plist_path}")
        print(f"Load with: launchctl load {plist_path}")
        
    elif system == "systemd":
        service_path = Path.home() / ".config/systemd/user/mcp-vuln-monitor.service"
        service_path.parent.mkdir(parents=True, exist_ok=True)
        service_content = f"""[Unit]
Description=MCP Vulnerability Monitor Daemon
After=network.target

[Service]
ExecStart={executable} {script_path} monitor
Restart=always
RestartSec=10

[Install]
WantedBy=default.target
"""
        service_path.write_text(service_content)
        print(f"Service installed to {service_path}")
        print("Enable and start with: systemctl --user enable --now mcp-vuln-monitor.service")
    else:
        print("Unknown system type.")


def start_monitor(args):
    """Run background monitoring daemon."""
    if hasattr(args, "status") and getattr(args, "status"):
        pid_file = Path(getattr(args, "pid_file", "~/.mcp-vuln/monitor.pid")).expanduser()
        if check_status(pid_file):
            print("Monitor daemon is running.")
            sys.exit(0)
        else:
            print("Monitor daemon is not running.")
            sys.exit(1)
            
    if hasattr(args, "stop") and getattr(args, "stop"):
        pid_file = Path(getattr(args, "pid_file", "~/.mcp-vuln/monitor.pid")).expanduser()
        if stop_monitor(pid_file):
            print("Monitor daemon stopped.")
            sys.exit(0)
        else:
            print("Monitor daemon is not running or failed to stop.")
            sys.exit(1)
            
    if hasattr(args, "install_service") and getattr(args, "install_service"):
        if sys.platform == "darwin":
            install_service("launchd")
        else:
            install_service("systemd")
        sys.exit(0)

    config = MonitorConfig()
    
    if hasattr(args, "interval") and args.interval is not None:
        config.interval_seconds = args.interval
    if hasattr(args, "targets") and args.targets is not None:
        config.targets = args.targets
    if hasattr(args, "ports") and args.ports is not None:
        config.ports_spec = args.ports
    if hasattr(args, "notify") and args.notify:
        config.notify_os = True
    elif hasattr(args, "desktop_notify") and args.desktop_notify:
        config.notify_os = True
        
    if hasattr(args, "webhook") and args.webhook:
        config.webhook_url = args.webhook
    elif hasattr(args, "alert_webhook") and args.alert_webhook:
        config.webhook_url = args.alert_webhook
        
    if hasattr(args, "pid_file") and args.pid_file:
        config.pid_file = Path(args.pid_file).expanduser()
    if hasattr(args, "log_file") and getattr(args, "log_file", None):
        config.log_file = Path(args.log_file).expanduser()

    daemon = McpMonitorDaemon(config)
    daemon.start(daemon=getattr(args, "daemon", False))

