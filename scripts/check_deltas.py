#!/usr/bin/env python3
import json
from pathlib import Path
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from mcp_vulnerabilities.delta_detector import DeltaDetector
from mcp_vulnerabilities.models import OsvVulnerability

def load_vulns(directory: Path):
    vulns = []
    if not directory.exists():
        return vulns
    for f in directory.rglob("*.json"):
        if f.name in ("sync_state.json", "index.json"):
            continue
        try:
            with open(f, "r") as fp:
                data = json.load(fp)
                if "id" in data:
                    vulns.append(OsvVulnerability.parse_obj(data))
        except Exception as e:
            pass # ignore parse errors for now
    return vulns

def main():
    old_dir = Path("data/vulnerabilities_backup")
    new_dir = Path("data/vulnerabilities")
    
    old_vulns = load_vulns(old_dir)
    new_vulns = load_vulns(new_dir)
    
    detector = DeltaDetector()
    has_delta = detector.evaluate_deltas(old_vulns, new_vulns)
    
    print(f"delta_detected={str(has_delta).lower()}")

if __name__ == "__main__":
    main()
