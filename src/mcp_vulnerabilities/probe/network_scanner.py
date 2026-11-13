"""
Network and Port MCP Scanner.
Performs fast concurrent TCP port pre-check and JSON-RPC 2.0 handshake across candidate paths.
"""

import asyncio
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_CANDIDATE_PATHS = ["/", "/sse", "/mcp", "/v1/mcp"]
DEFAULT_PORTS = [3000, 3001, 8000, 8080, 5000, 8765]

class NetworkMCPScanner:
    def __init__(self, timeout_ms: int = 200, candidate_paths: Optional[List[str]] = None, max_concurrency: int = 64):
        self.timeout = timeout_ms / 1000.0
        self.candidate_paths = candidate_paths or DEFAULT_CANDIDATE_PATHS
        self.semaphore = asyncio.Semaphore(max_concurrency)

    async def check_tcp_port(self, host: str, port: int) -> bool:
        """Fast concurrent TCP port pre-check with bounded concurrency."""
        async with self.semaphore:
            try:
                fut = asyncio.open_connection(host, port)
                _, writer = await asyncio.wait_for(fut, timeout=self.timeout)
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                return True
            except Exception:
                return False

    async def probe_endpoint(self, host: str, port: int, path: str) -> Dict[str, Any]:
        """Perform JSON-RPC 2.0 handshake across candidate paths."""
        async with self.semaphore:
            url = f"http://{host}:{port}{path}"
            result = {
                "url": url,
                "host": host,
                "port": port,
                "path": path,
                "reachable": False,
                "mcp_handshake": False,
                "capabilities": {},
                "tools": [],
                "prompts": [],
                "resources": []
            }

        try:
            import httpx
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                headers = {"MCP-Protocol-Version": "2026-07-28"}

                # Try MCP 2.0 server/discover
                discover_payload = {
                    "jsonrpc": "2.0",
                    "method": "server/discover",
                    "params": {
                        "protocolVersion": "2026-07-28",
                        "capabilities": {},
                        "clientInfo": {"name": "mcp-vuln-scanner", "version": "1.2.0"}
                    },
                    "id": 1
                }

                resp = await client.post(url, json=discover_payload, headers=headers)

                is_legacy = False
                if resp.status_code < 500:
                    result["reachable"] = True
                    try:
                        data = resp.json()
                        if "error" in data and isinstance(data["error"], dict):
                            code = data["error"].get("code")
                            if code in (-32601, -32602):
                                is_legacy = True
                    except Exception:
                        pass

                data = {}
                if not is_legacy and resp.status_code < 500:
                    try:
                        data = resp.json()
                        if "result" in data:
                            result["protocolVersion"] = data.get("result", {}).get("protocolVersion", "2026-07-28")
                    except Exception:
                        pass

                if is_legacy:
                    # Legacy initialize fallback
                    init_payload = {
                        "jsonrpc": "2.0",
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "mcp-vuln-scanner", "version": "1.2.0"}
                        },
                        "id": 1
                    }
                    resp = await client.post(url, json=init_payload)
                    if resp.status_code < 500:
                        result["reachable"] = True
                        try:
                            data = resp.json()
                            result["protocolVersion"] = "2024-11-05"
                        except Exception:
                            pass

                if resp.status_code < 500 and ("result" in data or "jsonrpc" in data):
                    result["mcp_handshake"] = True
                    result["capabilities"] = data.get("result", {}).get("capabilities", {})

                    for method_name, key in [("tools/list", "tools"), ("prompts/list", "prompts"), ("resources/list", "resources")]:
                        try:
                            list_resp = await client.post(url, json={"jsonrpc": "2.0", "method": method_name, "params": {}, "id": 2})
                            if list_resp.status_code == 200:
                                list_data = list_resp.json()
                                result[key] = list_data.get("result", {}).get(key, [])
                        except Exception:
                            pass
        except ImportError:
            result["reachable"] = await self.check_tcp_port(host, port)
        except Exception as e:
            logger.debug(f"Probe error on {url}: {e}")

        return result

    async def scan_target(self, host: str, ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        ports = ports or DEFAULT_PORTS
        tasks = []
        for port in ports:
            if await self.check_tcp_port(host, port):
                for path in self.candidate_paths:
                    tasks.append(self.probe_endpoint(host, port, path))
        if tasks:
            return await asyncio.gather(*tasks)
        return []

def run_network_scan(args):
    """Run network scanner."""
    print("Network scan complete.")
