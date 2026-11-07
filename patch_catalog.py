import re

with open("src/mcp_vulnerabilities/catalog.py", "r") as f:
    content = f.read()

func = """
def prune_catalog(catalog_data: dict, catalog_state: 'McpCatalogState') -> dict:
    \"\"\"Removes tombstoned and archived servers from the catalog dictionary.\"\"\"
    if not catalog_data or "servers" not in catalog_data:
        return catalog_data
    
    servers = catalog_data["servers"]
    pruned_servers = {}
    
    for key, server in servers.items():
        eco = server.get("ecosystem")
        name = server.get("name")
        if not eco or not name:
            pruned_servers[key] = server
            continue
            
        canonical_key = catalog_state.package_key(eco, name)
        
        # Check tombstones
        if canonical_key in catalog_state.tombstones:
            tombstone = catalog_state.tombstones[canonical_key]
            # Log pruning for info
            logger.info("Pruning %s from catalog: %s", key, tombstone.reason)
            continue
            
        pruned_servers[key] = server
        
    pruned_data = catalog_data.copy()
    pruned_data["servers"] = pruned_servers
    pruned_data["total_servers"] = len(pruned_servers)
    return pruned_data
"""

if "def prune_catalog" not in content:
    content += "\n" + func + "\n"

with open("src/mcp_vulnerabilities/catalog.py", "w") as f:
    f.write(content)
