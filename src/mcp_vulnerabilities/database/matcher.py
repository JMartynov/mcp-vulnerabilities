import json
from pathlib import Path
from typing import Any

class VulnerabilityMatcher:
    def __init__(self, vulnerabilities_dir: Path):
        self.vulnerabilities_dir = vulnerabilities_dir

    def get_vulnerable_tools(self, package_name: str) -> set[str]:
        vulnerable_tools = set()
        if not self.vulnerabilities_dir or not self.vulnerabilities_dir.exists():
            return vulnerable_tools

        for filepath in self.vulnerabilities_dir.rglob("*.json"):
            try:
                data = json.loads(filepath.read_text(encoding="utf-8"))
                for affected in data.get("affected", []):
                    pkg = affected.get("package", {})
                    if pkg.get("name") == package_name:
                        db_specific = affected.get("database_specific", {})
                        tools = db_specific.get("vulnerable_tools", [])
                        vulnerable_tools.update(tools)
            except Exception:
                continue

        return vulnerable_tools
