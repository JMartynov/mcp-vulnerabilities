import json
import time
import urllib.parse

from mcp_vulnerabilities.api.middleware import format_error
from mcp_vulnerabilities.api.openapi import generate_openapi_schema
from mcp_vulnerabilities.audit.parsers import ClientConfigParser
from mcp_vulnerabilities.fingerprints.conflict_detector import ConflictDetector
from mcp_vulnerabilities.probe.client import McpProbeClient
from mcp_vulnerabilities.probe.fingerprinter import McpFingerprinter
from mcp_vulnerabilities.probe.transport import HttpSseTransport, StdioTransport


def parse_body(handler) -> dict | None:
    content_length = int(handler.headers.get('Content-Length', 0))
    if content_length > 0:
        post_data = handler.rfile.read(content_length)
        try:
            return json.loads(post_data.decode('utf-8'))
        except json.JSONDecodeError:
            return None
    return None

def parse_query(path: str) -> dict:
    parsed_url = urllib.parse.urlparse(path)
    return urllib.parse.parse_qs(parsed_url.query)

def handle_health(handler, server):
    uptime = time.time() - server.start_time
    passports_loaded = 0
    if server.fingerprint_matcher:
        passports_loaded = len(server.fingerprint_matcher.packages)
    vulnerabilities_indexed = 0
    if server.vulnerability_matcher:
        vulnerabilities_indexed = len(server.vulnerability_matcher.advisories)

    return 200, {"Content-Type": "application/json"}, {
        "status": "ok",
        "version": "1.0.0",
        "vulnerabilities_indexed": vulnerabilities_indexed,
        "passports_loaded": passports_loaded,
        "uptime_seconds": uptime
    }

def handle_openapi(handler, server):
    return 200, {"Content-Type": "application/json"}, generate_openapi_schema()

def handle_scan_probe(handler, server):
    body = parse_body(handler)
    if body is None:
        return 400, {"Content-Type": "application/json"}, format_error("BAD_REQUEST", "Invalid JSON body")
    
    command = body.get("command")
    url = body.get("url")
    timeout = body.get("timeout", 30.0)
    
    if command:
        cmd_parts = command.split()
        transport = StdioTransport(command=cmd_parts[0], args=cmd_parts[1:])
    elif url:
        transport = HttpSseTransport(url=url)
    else:
        return 400, {"Content-Type": "application/json"}, format_error("BAD_REQUEST", "Either command or url must be provided")

    # Connect to MCP server
    with McpProbeClient(transport) as client:
        try:
            client.connect(timeout=timeout)
        except Exception as e:
            return 500, {"Content-Type": "application/json"}, format_error("PROBE_FAILED", "Failed to connect to MCP server", str(e))
        
        try:
            info = client.get_server_info()
            tools = client.list_tools()
            prompts = client.list_prompts()
            resources = client.list_resources()
        except Exception as e:
            return 500, {"Content-Type": "application/json"}, format_error("PROBE_FAILED", "Failed to get MCP server capabilities", str(e))
        
    fingerprinter = McpFingerprinter()
    fingerprint = fingerprinter.generate(info, tools, prompts, resources)

    identity = None
    if server.fingerprint_matcher:
        matches = server.fingerprint_matcher.match_tools(tools)
        if matches:
            match = matches[0] # Best match
            identity = {
                "package": f"pkg:{match.ecosystem}/{match.package_name}@{match.version}",
                "confidence": match.confidence_score,
                "version": match.version,
                "repository": match.repository_url
            }
            
    vulnerabilities = []
    if server.vulnerability_matcher and identity:
        # we can search the vulnerability matcher for this package
        results = server.vulnerability_matcher.search(query=identity["package"])
        for res in results:
            vulnerabilities.append({
                "id": res.advisory.id,
                "reason": res.matched_on,
                "severity": res.advisory.database_specific.get("severity", "UNKNOWN") if res.advisory.database_specific else "UNKNOWN"
            })
            
    return 200, {"Content-Type": "application/json"}, {
        "fingerprint": fingerprint,
        "identity": identity,
        "vulnerabilities": vulnerabilities
    }

def handle_identify(handler, server):
    body = parse_body(handler)
    if body is None:
        return 400, {"Content-Type": "application/json"}, format_error("BAD_REQUEST", "Invalid JSON body")

    if not server.fingerprint_matcher:
        return 500, {"Content-Type": "application/json"}, format_error("INTERNAL_ERROR", "Fingerprint matcher not initialized")

    tools = []
    if "tools" in body:
        tools = body["tools"]
    elif "command" in body:
        cmd_parts = body["command"].split()
        transport = StdioTransport(command=cmd_parts[0], args=cmd_parts[1:])
        with McpProbeClient(transport) as client:
            try:
                client.connect(timeout=30.0)
                tools = client.list_tools()
            except Exception as e:
                return 500, {"Content-Type": "application/json"}, format_error("PROBE_FAILED", "Failed to probe server", str(e))
    elif "url" in body:
        transport = HttpSseTransport(url=body["url"])
        with McpProbeClient(transport) as client:
            try:
                client.connect(timeout=30.0)
                tools = client.list_tools()
            except Exception as e:
                return 500, {"Content-Type": "application/json"}, format_error("PROBE_FAILED", "Failed to probe server", str(e))
    else:
        # maybe tools are provided correctly
        if isinstance(body, dict) and "tools" in body:
            tools = body["tools"]
        elif isinstance(body, list):
            tools = body
        else:
            return 400, {"Content-Type": "application/json"}, format_error("BAD_REQUEST", "Invalid input format")
        
    matches = server.fingerprint_matcher.match_tools(tools)
    if matches:
        match = matches[0]
        return 200, {"Content-Type": "application/json"}, {
            "package": f"pkg:{match.ecosystem}/{match.package_name}@{match.version}",
            "confidence": match.confidence_score,
            "version": match.version,
            "repository": match.repository_url
        }
    return 404, {"Content-Type": "application/json"}, format_error("NOT_FOUND", "No identity match found")

def handle_scan_config(handler, server):
    body = parse_body(handler)
    if body is None:
        return 400, {"Content-Type": "application/json"}, format_error("BAD_REQUEST", "Invalid JSON body")
        
    config = body.get("config")
    if not config:
        return 400, {"Content-Type": "application/json"}, format_error("BAD_REQUEST", "Missing config object")
        
    detect_collisions = body.get("detect_collisions", True)
    
    servers = ClientConfigParser.parse_dict(config)
    
    results = {
        "servers_audited": len(servers),
        "vulnerabilities": [],
        "collisions": []
    }
    
    if server.vulnerability_matcher:
        report = server.vulnerability_matcher.audit_servers(servers, server.fingerprint_matcher)
        for f in report.findings:
            results["vulnerabilities"].append({
                "server": f.server_name,
                "vulnerability_id": f.vulnerability_id,
                "reason": f.summary
            })
                
    if detect_collisions and server.fingerprint_matcher:
        detector = ConflictDetector(server.fingerprint_matcher)
        collisions = detector.detect_conflicts(config_data=config, servers=servers)
        for c in collisions:
            results["collisions"].append({
                "tool": c.get("tool_name"),
                "servers": c.get("servers", [])
            })
            
    return 200, {"Content-Type": "application/json"}, results

def handle_vulnerabilities(handler, server):
    query = parse_query(handler.path)
    limit = int(query.get("limit", ["10"])[0])
    offset = int(query.get("offset", ["0"])[0])
    cve = query.get("cve", [None])[0]
    tool = query.get("tool", [None])[0]
    ecosystem = query.get("ecosystem", [None])[0]

    if not server.vulnerability_matcher:
        return 500, {"Content-Type": "application/json"}, format_error("INTERNAL_ERROR", "Vulnerability matcher not initialized")

    vulns = server.vulnerability_matcher.advisories
    filtered = []
    for v_dict in vulns:
        # It's actually a dict, let's treat it as such or instantiate OsvVulnerability?
        # matcher.advisories is a list of dicts.
        aliases = v_dict.get("aliases", [])
        if cve and cve.lower() not in [a.lower() for a in aliases]:
            continue
            
        if tool:
            tool_found = False
            db_specific = v_dict.get("database_specific", {})
            for ext in db_specific.get("mcp_security_extensions", []):
                if tool in ext.get("vulnerable_tools", []):
                    tool_found = True
                    break
            if not tool_found:
                continue
                
        if ecosystem:
            eco_found = False
            for affected in v_dict.get("affected", []):
                pkg = affected.get("package", {})
                if pkg.get("ecosystem", "").lower() == ecosystem.lower():
                    eco_found = True
                    break
            if not eco_found:
                continue
                
        filtered.append(v_dict)
        
    paginated = filtered[offset:offset+limit]
    
    return 200, {"Content-Type": "application/json"}, {
        "total": len(filtered),
        "offset": offset,
        "limit": limit,
        "items": paginated
    }

def router(handler, server):
    path = handler.path.split("?")[0]
    method = handler.command

    if method == "GET":
        if path in ("/health", "/api/v1/health"):
            return handle_health(handler, server)
        elif path == "/openapi.json":
            return handle_openapi(handler, server)
        elif path == "/docs":
            html = """<!DOCTYPE html>
<html>
  <head>
    <title>MCP Security API Docs</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>body { margin: 0; padding: 0; }</style>
  </head>
  <body>
    <script id="api-reference" data-url="/openapi.json"></script>
    <script src="https://cdn.jsdelivr.net/npm/@scalar/api-reference"></script>
  </body>
</html>"""
            return 200, {"Content-Type": "text/html"}, html
        elif path == "/api/v1/vulnerabilities":
            return handle_vulnerabilities(handler, server)
            
    elif method == "POST":
        if path == "/api/v1/scan/probe":
            return handle_scan_probe(handler, server)
        elif path == "/api/v1/identify":
            return handle_identify(handler, server)
        elif path == "/api/v1/scan/config":
            return handle_scan_config(handler, server)
            
    return 404, {"Content-Type": "application/json"}, format_error("NOT_FOUND", "Endpoint not found")
