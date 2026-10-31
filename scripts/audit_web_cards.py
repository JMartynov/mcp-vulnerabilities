import argparse
import json
import logging
import os
import sys
import glob
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def parse_args():
    parser = argparse.ArgumentParser(description="Automated Daily Web Card & Advisory Parity Auditor")
    parser.add_argument("--catalog", default="docs/data/mcp_catalog_index.json")
    parser.add_argument("--shards-dir", default="docs/data/shards")
    parser.add_argument("--vulnerabilities", default="data/vulnerabilities")
    parser.add_argument("--report-dir", default="docs/reports/daily_audits")
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser.parse_args()

def is_valid_url(url):
    if not url:
        return True
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def compute_composite_risk(static_risk_tier, highest_cve_severity, is_vulnerable):
    rank_map = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "MODERATE": 2,
        "LOW": 1,
        "NONE": 0,
        "UNKNOWN": 0,
    }
    tier_map = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "LOW"}

    base_tier = (static_risk_tier or "LOW").upper()
    if base_tier == "MODERATE":
        base_tier = "MEDIUM"
    if base_tier not in rank_map:
        base_tier = "LOW"
    base_rank = rank_map[base_tier]
    
    if not is_vulnerable:
        return tier_map[base_rank]

    highest_cve_rank = rank_map.get((highest_cve_severity or "UNKNOWN").upper(), 0)
    if highest_cve_rank == 0:
        highest_cve_rank = 3  # Default to HIGH for unknown but vulnerable
        
    return tier_map[max(base_rank, highest_cve_rank)]

def load_osv_data(vuln_dir):
    osv_data = {}
    if not os.path.exists(vuln_dir):
        return osv_data
    
    for f in glob.glob(f"{vuln_dir}/*.json"):
        try:
            with open(f, 'r') as fp:
                adv = json.load(fp)
                for affected in adv.get("affected", []):
                    pkg = affected.get("package", {})
                    pkg_name = pkg.get("name")
                    if pkg_name:
                        if pkg_name not in osv_data:
                            osv_data[pkg_name] = []
                        osv_data[pkg_name].append(adv)
        except Exception as e:
            logging.warning(f"Failed to load OSV {f}: {e}")
    return osv_data

def get_highest_cve_severity(advisories):
    rank_map = {
        "CRITICAL": 4,
        "HIGH": 3,
        "MEDIUM": 2,
        "MODERATE": 2,
        "LOW": 1,
        "NONE": 0,
        "UNKNOWN": 0,
    }
    tier_map = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "LOW"}
    
    max_rank = 0
    for adv in advisories:
        sev = "UNKNOWN"
        db_spec = adv.get("database_specific", {})
        if "severity" in db_spec:
            sev = db_spec["severity"]
        rank = rank_map.get(sev.upper(), 0)
        if rank > max_rank:
            max_rank = rank
            
    if max_rank == 0 and len(advisories) > 0:
        return "HIGH"
    return tier_map[max_rank]

def audit():
    args = parse_args()
    
    if not os.path.exists(args.catalog):
        logging.error(f"Catalog file not found: {args.catalog}")
        if args.strict:
            sys.exit(1)
        return

    with open(args.catalog, 'r') as f:
        catalog = json.load(f)
        
    osv_data = load_osv_data(args.vulnerabilities)
    
    discrepancies = []
    processed_shards = set()
    all_shards_in_dir = set(glob.glob(f"{args.shards_dir}/*.json"))
    
    for item in catalog:
        pkg_name = item.get("package_name")
        shard_file = item.get("shard_file")
        
        # Data Sanity
        if not pkg_name:
            discrepancies.append(f"Item {item.get('id')} has empty package_name")
            
        for count_field in ["tools_count", "prompts_count", "resources_count", "vulnerable_versions_count", "total_versions_count"]:
            if item.get(count_field, 0) < 0:
                discrepancies.append(f"Item {pkg_name} has negative {count_field}")
                
        for url_field in ["repository_url", "homepage_url"]:
            if not is_valid_url(item.get(url_field)):
                discrepancies.append(f"Item {pkg_name} has invalid {url_field}: {item.get(url_field)}")

        # Shard File Existence & Ingestion
        if not shard_file:
            discrepancies.append(f"Item {pkg_name} is missing shard_file reference")
        else:
            shard_path = os.path.join(args.shards_dir, shard_file)
            processed_shards.add(os.path.abspath(shard_path))
            
            if not os.path.exists(shard_path):
                discrepancies.append(f"Shard file missing for {pkg_name}: {shard_file}")
            else:
                try:
                    with open(shard_path, 'r') as sf:
                        shard_data = json.load(sf)
                        if pkg_name not in shard_data:
                            discrepancies.append(f"Package {pkg_name} not found in its referenced shard {shard_file}")
                except Exception as e:
                    discrepancies.append(f"Failed to read shard {shard_file}: {e}")
                    
        # Advisory & CVE Posture Parity
        osv_advs = osv_data.get(pkg_name, [])
        expected_vulnerable = len(osv_advs) > 0
        if item.get("is_vulnerable", False) != expected_vulnerable:
            # We don't necessarily have all OSV data, so this might not be 100% strict depending on environment.
            # But the requirement says "Validate against OSV data".
            # For simplicity, we just log a discrepancy if we have OSV data that contradicts.
            if expected_vulnerable:
                discrepancies.append(f"Item {pkg_name} should be vulnerable according to OSV data")
            elif item.get("is_vulnerable", False) and os.path.exists(args.vulnerabilities) and list(glob.glob(f"{args.vulnerabilities}/*.json")):
                discrepancies.append(f"Item {pkg_name} is marked vulnerable but has no matching OSV data")
                
        if expected_vulnerable:
            expected_sev = get_highest_cve_severity(osv_advs)
            actual_sev = item.get("highest_cve_severity")
            if actual_sev != expected_sev:
                discrepancies.append(f"Item {pkg_name} highest_cve_severity mismatch: expected {expected_sev}, got {actual_sev}")
                
        # Composite Risk Tier Verification
        expected_composite = compute_composite_risk(
            item.get("static_risk_tier"), 
            item.get("highest_cve_severity"),
            item.get("is_vulnerable", False)
        )
        if item.get("composite_risk_tier") != expected_composite:
            discrepancies.append(f"Item {pkg_name} composite_risk_tier mismatch: expected {expected_composite}, got {item.get('composite_risk_tier')}")

    # Check for orphaned shards
    for sf in all_shards_in_dir:
        if os.path.abspath(sf) not in processed_shards:
            discrepancies.append(f"Orphaned shard file detected: {os.path.basename(sf)}")

    # Report Generation
    os.makedirs(args.report_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    summary = {
        "total_packages": len(catalog),
        "discrepancies_count": len(discrepancies),
        "discrepancies": discrepancies,
        "timestamp": timestamp
    }
    
    json_path = os.path.join(args.report_dir, "audit_latest.json")
    with open(json_path, 'w') as f:
        json.dump(summary, f, indent=2)
        
    md_path = os.path.join(args.report_dir, f"audit_{timestamp}.md")
    with open(md_path, 'w') as f:
        f.write(f"# Daily Web Card & Advisory Parity Audit Report\n\n")
        f.write(f"**Date:** {timestamp}\n")
        f.write(f"**Total Packages Audited:** {len(catalog)}\n")
        f.write(f"**Discrepancies Found:** {len(discrepancies)}\n\n")
        if discrepancies:
            f.write("## Discrepancies\n")
            for d in discrepancies:
                f.write(f"- {d}\n")
        else:
            f.write("## Status\nAll checks passed successfully.\n")

    if discrepancies:
        for d in discrepancies:
            logging.warning(d)
        if args.strict:
            logging.error("Strict mode enabled and discrepancies found. Exiting with 1.")
            sys.exit(1)
    else:
        logging.info("Audit passed with 0 discrepancies.")
        
if __name__ == "__main__":
    audit()
