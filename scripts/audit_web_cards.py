import argparse
import json
import logging
import os
import sys
import glob
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

from mcp_vulnerabilities.site_builder import _extract_advisory_severity, _compute_composite_risk

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
    url = str(url).strip()
    match = re.search(r'https?://[^\s]+', url)
    if match:
        url = match.group(0)
    elif not url.startswith(('http://', 'https://')) and '.' in url and ' ' not in url:
        url = 'https://' + url
    try:
        r = urlparse(url)
        return bool(r.scheme and r.netloc)
    except Exception:
        return False

def load_osv_data(vuln_dir):
    osv_data = {}
    if not os.path.exists(vuln_dir):
        return osv_data
    
    for f in (os.path.join(vuln_dir, x) for x in os.listdir(vuln_dir) if x.endswith(".json")):
        try:
            with open(f, 'r') as fp:
                adv = json.load(fp)
                for affected in adv.get("affected", []):
                    pkg = affected.get("package", {})
                    pkg_name = pkg.get("name")
                    if pkg_name:
                        ecosystem = pkg.get("ecosystem")
                        if pkg_name and ecosystem:
                            key = f"{ecosystem}:{pkg_name}"
                            if key not in osv_data:
                                osv_data[key] = []
                            osv_data[key].append(adv)
        except Exception as e:
            logging.warning(f"Failed to load OSV {f}: {e}")
    return osv_data

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
    all_shards_in_dir = set(os.path.abspath(os.path.join(args.shards_dir, f)) for f in os.listdir(args.shards_dir) if f.endswith(".json")) if os.path.exists(args.shards_dir) else set()
    has_vuln_files = bool(osv_data)
    
    shard_cache = {}
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

        shard_data = {}
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
                    if shard_path not in shard_cache:
                        with open(shard_path, 'r') as sf:
                            shard_cache[shard_path] = json.load(sf)
                    shard_data = shard_cache[shard_path]
                    if pkg_name not in shard_data:
                        discrepancies.append(f"Package {pkg_name} not found in its referenced shard {shard_file}")
                except Exception as e:
                    discrepancies.append(f"Failed to read shard {shard_file}: {e}")
                    
        # Advisory & CVE Posture Parity
        ecosystem = item.get("ecosystem")
        key = f"{ecosystem}:{pkg_name}"
        osv_advs = osv_data.get(key, [])
        expected_vulnerable = len(osv_advs) > 0
        is_vulnerable = item.get("is_vulnerable", False)
        if is_vulnerable != expected_vulnerable:
            if expected_vulnerable:
                discrepancies.append(f"Item {pkg_name} should be vulnerable according to OSV data")
            elif is_vulnerable and has_vuln_files and list(glob.glob(f"{args.vulnerabilities}/*{pkg_name}*.json")):
                discrepancies.append(f"Item {pkg_name} is marked vulnerable but has no matching OSV data")
                
        # Composite Risk Tier Verification
        pkg_entry = shard_data.get(pkg_name, {})
        versions = pkg_entry.get("versions", [])
        expected_sev, expected_composite = _compute_composite_risk(
            item.get("static_risk_tier"),
            item.get("is_vulnerable", False),
            versions,
        )
        if item.get("highest_cve_severity") != expected_sev:
            discrepancies.append(f"Item {pkg_name} highest_cve_severity mismatch: expected {expected_sev}, got {item.get('highest_cve_severity')}")
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
