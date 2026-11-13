import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Set, Optional

from mcp_vulnerabilities.probe.transport import BaseTransport, TransportError

logger = logging.getLogger(__name__)

SUPPORTED_PROTOCOL_VERSIONS = ("2026-07-28", "2025-11-25", "2025-06-18", "2024-11-05")
LATEST_PROTOCOL_VERSION = "2026-07-28"
LEGACY_PROTOCOL_VERSION = "2024-11-05"

def is_discover_unsupported_error(resp: Dict[str, Any]) -> bool:
    if "error" in resp and isinstance(resp["error"], dict):
        code = resp["error"].get("code")
        return code in (-32601, -32602)
    return False



@dataclass
class DiscoveredMcpSurface:
    protocol_version: str = "2024-11-05"
    server_info: Dict[str, Any] = field(default_factory=dict)
    capabilities: Dict[str, Any] = field(default_factory=dict)
    instructions: Optional[str] = None
    tools: List[Dict[str, Any]] = field(default_factory=list)
    prompts: List[Dict[str, Any]] = field(default_factory=list)
    resources: List[Dict[str, Any]] = field(default_factory=list)


class McpProbeClient:
    def __init__(self, transport: BaseTransport):
        self.transport = transport
        self.message_id = 1
        self.surface = DiscoveredMcpSurface()

    @property
    def server_info(self) -> Dict[str, Any]:
        return self.surface.server_info

    @property
    def tools(self) -> List[Dict[str, Any]]:
        return self.surface.tools

    @property
    def prompts(self) -> List[Dict[str, Any]]:
        return self.surface.prompts

    @property
    def resources(self) -> List[Dict[str, Any]]:
        return self.surface.resources

    def get_server_info(self) -> Dict[str, Any]:
        return self.surface.server_info

    def list_tools(self) -> List[Dict[str, Any]]:
        return self.surface.tools

    def list_prompts(self) -> List[Dict[str, Any]]:
        return self.surface.prompts

    def list_resources(self) -> List[Dict[str, Any]]:
        return self.surface.resources

    def __enter__(self) -> "McpProbeClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def close(self) -> None:
        try:
            self.transport.stop()
        except Exception:
            pass

    def _next_id(self) -> int:
        current = self.message_id
        self.message_id += 1
        return current

    def connect(self, timeout: float = 5.0) -> None:
        """Alias for connect_and_discover."""
        self.connect_and_discover(timeout=timeout)

    def connect_and_discover(
        self, timeout: float = 5.0, surfaces: Optional[Set[str]] = None
    ) -> None:
        """
        Executes the JSON-RPC 2.0 handshake, extracts serverInfo,
        sends notifications/initialized, and queries available surfaces.
        """
        if surfaces is None:
            surfaces = {"tools", "prompts", "resources"}
        if "all" in surfaces:
            surfaces = {"tools", "prompts", "resources"}

        self.transport.start()
        try:
            # 1. Try MCP 2.0 server/discover
            discover_id = self._next_id()
            discover_msg = {
                "jsonrpc": "2.0",
                "id": discover_id,
                "method": "server/discover",
                "params": {
                    "protocolVersion": LATEST_PROTOCOL_VERSION,
                    "capabilities": {"roots": {"listChanged": True}, "sampling": {}},
                    "clientInfo": {"name": "mcp-vuln-probe", "version": "1.0.0"},
                },
            }
            logger.debug(f"Sending server/discover: {discover_msg}")
            self.transport.send(discover_msg)

            resp = self.transport.receive(timeout=timeout)
            logger.debug(f"Received response: {resp}")

            is_legacy = False
            if resp.get("id") == discover_id and "error" in resp:
                if is_discover_unsupported_error(resp):
                    logger.debug("server/discover unsupported, falling back to legacy initialize")
                    is_legacy = True
                else:
                    raise TransportError(f"Failed server/discover: {resp.get('error')}")

            if not is_legacy and resp.get("id") == discover_id and "result" in resp:
                # MCP 2.0 success
                result = resp.get("result", {})
                self.surface.server_info = result.get("serverInfo", {})
                self.surface.capabilities = result.get("capabilities", {})
                self.surface.instructions = result.get("instructions")
                self.surface.protocol_version = result.get("protocolVersion", LATEST_PROTOCOL_VERSION)
            else:
                # 2. Legacy Initialize
                init_id = self._next_id()
                init_msg = {
                    "jsonrpc": "2.0",
                    "id": init_id,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": LEGACY_PROTOCOL_VERSION,
                        "capabilities": {"roots": {"listChanged": True}, "sampling": {}},
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
                self.surface.server_info = result.get("serverInfo", {})
                self.surface.capabilities = result.get("capabilities", {})
                self.surface.instructions = result.get("instructions")
                self.surface.protocol_version = LEGACY_PROTOCOL_VERSION

                # Send initialized notification
                notif_msg = {
                    "jsonrpc": "2.0",
                    "method": "notifications/initialized",
                    "params": {},
                }
                logger.debug(f"Sending notifications/initialized: {notif_msg}")
                self.transport.send(notif_msg)

            # 3. Query surfaces based on capabilities
            server_caps = self.surface.capabilities

            if "tools" in surfaces and ("tools" in server_caps or not server_caps):
                # Always try tools if no capabilities specified (some simple servers omit it)
                tools_id = self._next_id()
                tools_msg = {
                    "jsonrpc": "2.0",
                    "id": tools_id,
                    "method": "tools/list",
                    "params": {},
                }
                logger.debug(f"Sending tools/list: {tools_msg}")
                self.transport.send(tools_msg)

                resp = self.transport.receive(timeout=timeout)
                logger.debug(f"Received response: {resp}")

                if resp.get("id") == tools_id and "error" not in resp:
                    self.surface.tools = resp.get("result", {}).get("tools", [])
                elif "error" in resp:
                    logger.warning(f"Error querying tools/list: {resp['error']}")

            if "prompts" in surfaces and "prompts" in server_caps:
                prompts_id = self._next_id()
                prompts_msg = {
                    "jsonrpc": "2.0",
                    "id": prompts_id,
                    "method": "prompts/list",
                    "params": {},
                }
                logger.debug(f"Sending prompts/list: {prompts_msg}")
                self.transport.send(prompts_msg)

                resp = self.transport.receive(timeout=timeout)
                logger.debug(f"Received response: {resp}")

                if resp.get("id") == prompts_id and "error" not in resp:
                    self.surface.prompts = resp.get("result", {}).get("prompts", [])
                elif "error" in resp:
                    logger.warning(f"Error querying prompts/list: {resp['error']}")

            if "resources" in surfaces and "resources" in server_caps:
                resources_id = self._next_id()
                resources_msg = {
                    "jsonrpc": "2.0",
                    "id": resources_id,
                    "method": "resources/list",
                    "params": {},
                }
                logger.debug(f"Sending resources/list: {resources_msg}")
                self.transport.send(resources_msg)

                resp = self.transport.receive(timeout=timeout)
                logger.debug(f"Received response: {resp}")

                if resp.get("id") == resources_id and "error" not in resp:
                    self.surface.resources = resp.get("result", {}).get("resources", [])
                elif "error" in resp:
                    logger.warning(f"Error querying resources/list: {resp['error']}")

        finally:
            self.transport.stop()
