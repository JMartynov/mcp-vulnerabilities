import logging
from typing import Any, Dict, List

from mcp_vulnerabilities.probe.transport import BaseTransport, TransportError

logger = logging.getLogger(__name__)


class McpProbeClient:
    def __init__(self, transport: BaseTransport):
        self.transport = transport
        self.message_id = 1
        self.server_info: Dict[str, Any] = {}
        self.tools: List[Dict[str, Any]] = []

    def _next_id(self) -> int:
        current = self.message_id
        self.message_id += 1
        return current

    def connect_and_discover(self, timeout: float = 5.0) -> None:
        """
        Executes the JSON-RPC 2.0 handshake, extracts serverInfo,
        sends notifications/initialized, and queries tools/list.
        """
        self.transport.start()
        try:
            # 1. Initialize
            init_id = self._next_id()
            init_msg = {
                "jsonrpc": "2.0",
                "id": init_id,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-vuln-probe", "version": "1.0.0"},
                },
            }
            logger.debug(f"Sending initialize: {init_msg}")
            self.transport.send(init_msg)

            # Wait for initialize response
            resp = self.transport.receive(timeout=timeout)
            logger.debug(f"Received response: {resp}")

            if resp.get("id") != init_id or "error" in resp:
                raise TransportError(f"Failed to initialize: {resp.get('error', resp)}")

            result = resp.get("result", {})
            self.server_info = result.get("serverInfo", {})

            # 2. Send initialized notification
            notif_msg = {
                "jsonrpc": "2.0",
                "method": "notifications/initialized",
                "params": {},
            }
            logger.debug(f"Sending notifications/initialized: {notif_msg}")
            self.transport.send(notif_msg)

            # 3. Query tools/list
            tools_id = self._next_id()
            tools_msg = {
                "jsonrpc": "2.0",
                "id": tools_id,
                "method": "tools/list",
                "params": {},
            }
            logger.debug(f"Sending tools/list: {tools_msg}")
            self.transport.send(tools_msg)

            # Wait for tools/list response
            resp = self.transport.receive(timeout=timeout)
            logger.debug(f"Received response: {resp}")

            if resp.get("id") != tools_id or "error" in resp:
                raise TransportError(f"Failed to list tools: {resp.get('error', resp)}")

            self.tools = resp.get("result", {}).get("tools", [])

        finally:
            self.transport.stop()
