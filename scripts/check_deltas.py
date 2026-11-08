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
                    vulns.append(OsvVulnerability.from_dict(data))
        except Exception as e:
            pass # ignore parse errors for now
    return vulns

def check_passports_delta() -> bool:
    old_passport = Path("data/passports_backup.json.gz")
    new_passport = Path("data/passports.json.gz")
    
    if not new_passport.exists():
        return False
        
    if not old_passport.exists():
        return True
        
    import gzip
    
    try:
        old_data = gzip.open(old_passport, "rb").read()
        new_data = gzip.open(new_passport, "rb").read()
            
        old_json = json.loads(old_data)
        new_json = json.loads(new_data)
        
        old_count = old_json.get("total_passports", 0)
        new_count = new_json.get("total_passports", 0)
        
        if new_count > old_count:
            return True
            
        if old_json.get("passports") != new_json.get("passports"):
            return True
            
    except Exception:
        pass
        
    return False

def main():
    old_dir = Path("data/vulnerabilities_backup")
    new_dir = Path("data/vulnerabilities")
    
    old_vulns = load_vulns(old_dir)
    new_vulns = load_vulns(new_dir)
    
    detector = DeltaDetector()
    has_delta = detector.evaluate_deltas(old_vulns, new_vulns)
    
    if not has_delta:
        has_delta = check_passports_delta()
    
    print(f"delta_detected={str(has_delta).lower()}")

if __name__ == "__main__":
    main()
