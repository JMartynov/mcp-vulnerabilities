from typing import Any, Dict, List, Set
import logging
from mcp_vulnerabilities.audit.parsers import DiscoveredClientServer
from mcp_vulnerabilities.fingerprints.matcher import FingerprintMatcher

logger = logging.getLogger(__name__)

class ConflictDetector:
    """Detects multi-server tool shadowing/collisions in client configurations."""
    
    def __init__(self, matcher: FingerprintMatcher | None = None):
        self.matcher = matcher or FingerprintMatcher()
    
    def detect_conflicts(self, config_data: Dict[str, Any] | None = None, servers: List[DiscoveredClientServer] | None = None) -> List[Dict[str, Any]]:
        """
        Parses server entries in client configs and checks tool names exposed by each server
        (or known from passport specs if package name is identified).
        Flags collisions: when two different servers expose tools with the same name.
        """
        conflicts = []
        server_tools: Dict[str, Set[str]] = {}
        
        if servers is None:
            if config_data is None:
                return []
            from mcp_vulnerabilities.audit.parsers import ClientConfigParser
            servers = ClientConfigParser.parse_dict(config_data)
        
        for srv in servers:
            if not srv.package_name:
                continue
                
            tool_names = set()
            
            # Lookup in passport matcher
            spec = self.matcher.packages.get(srv.package_name)
            if spec and spec.versions:
                ver = spec.versions[0]
                for t in ver.tool_signatures:
                    tool_names.add(t.name)
            
            # Fallback for config enriched with tools in the dictionary
            if not tool_names and config_data:
                raw_servers = config_data.get("mcpServers") or config_data.get("mcp_servers") or config_data.get("servers", {})
                if not isinstance(raw_servers, dict):
                    if all(isinstance(v, dict) for v in config_data.values()):
                        raw_servers = config_data
                    else:
                        raw_servers = {}
                        
                srv_conf = raw_servers.get(srv.server_name, {})
                if isinstance(srv_conf, dict):
                    tools = srv_conf.get("tools", [])
                    if isinstance(tools, list):
                        for t in tools:
                            if isinstance(t, str):
                                tool_names.add(t)
                            elif isinstance(t, dict) and "name" in t:
                                tool_names.add(t["name"])
                    elif isinstance(tools, dict):
                        tool_names.update(tools.keys())
            
            if tool_names:
                server_tools[srv.server_name] = tool_names
            
        tool_to_servers: Dict[str, List[str]] = {}
        for srv_name, tools in server_tools.items():
            for t in tools:
                if t not in tool_to_servers:
                    tool_to_servers[t] = []
                tool_to_servers[t].append(srv_name)
                
        for tool, srv_list in tool_to_servers.items():
            if len(srv_list) > 1:
                conflicts.append({
                    "tool_name": tool,
                    "servers": srv_list,
                    "warning": f"Collision detected: Tool '{tool}' is exposed by multiple servers ({', '.join(srv_list)})."
                })
                
        return conflicts
