#!/usr/bin/env python3
import gzip
import json
from pathlib import Path

def main():
    passports_path = Path("data/passports.json.gz")
    print(f"[*] Reading original database from {passports_path}...")
    with gzip.open(passports_path, "rt", encoding="utf-8") as f:
        data = json.load(f)

    passports_dict = data.get("passports", {})
    print(f"[*] Loaded {len(passports_dict)} records from master database.")

    # Aggregate dual-axis assessments from all 62 chunk files
    results_dir = Path("results")
    result_files = sorted(results_dir.glob("*/*.json"))
    print(f"[*] Aggregating from {len(result_files)} chunk result files...")

    updated_count = 0
    missing_matches = 0

    for rf in result_files:
        try:
            with open(rf, "r", encoding="utf-8") as f:
                chunk_data = json.load(f)
            items = chunk_data.get("items", [])
            for entry in items:
                pkg_name = entry.get("package_name")
                assessment = entry.get("assessment")
                if pkg_name in passports_dict:
                    passports_dict[pkg_name]["dual_axis_assessment"] = assessment
                    updated_count += 1
                else:
                    missing_matches += 1
        except Exception as e:
            print(f"[!] Error reading {rf}: {e}")

    print(f"[+] Total assessments mapped: {updated_count} (unmatched: {missing_matches})")

    # Serialize back to data/passports.json.gz
    print(f"[*] Re-serializing master database to {passports_path}...")
    with gzip.open(passports_path, "wt", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    print(f"[+] Successfully updated {passports_path} with Dual-Axis security assessments!")

if __name__ == "__main__":
    main()
