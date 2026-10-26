import json
from pathlib import Path
from typing import Set

def get_default_corpus() -> Set[str]:
    """Returns a curated list of authentic MCP package namespaces and names."""
    return {
        "@modelcontextprotocol/server-filesystem",
        "@modelcontextprotocol/server-postgres",
        "@modelcontextprotocol/server-sqlite",
        "@modelcontextprotocol/server-github",
        "@modelcontextprotocol/server-slack",
        "@modelcontextprotocol/server-google-drive",
        "@modelcontextprotocol/server-notion",
        "mcp-server-sqlite",
        "mcp-server-github",
        "mcp-server-postgres",
        "@smithery/cli",
        "mcp-server-fetch",
        "mcp-server-brave-search",
        "mcp-server-sequential-thinking",
        "mcp-server-memory",
        "mcp-server-puppeteer",
        "@modelcontextprotocol/server-memory",
        "@modelcontextprotocol/server-puppeteer",
        "@modelcontextprotocol/server-brave-search",
        "@modelcontextprotocol/server-fetch",
        "@modelcontextprotocol/server-sequential-thinking",
    }

def load_authentic_corpus(catalog_path: str | Path | None = None) -> Set[str]:
    """Loads authentic packages from a catalog index and merges with defaults."""
    corpus = get_default_corpus()
    if not catalog_path:
        return corpus
        
    catalog_path = Path(catalog_path)
    if catalog_path.exists():
        try:
            with open(catalog_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "package" in item:
                            corpus.add(item["package"])
                elif isinstance(data, dict):
                    # Check if it's the expected catalog format
                    if "packages" in data:
                        for pkg in data["packages"]:
                             if "name" in pkg:
                                 corpus.add(pkg["name"])
        except Exception:
            pass
    return corpus
