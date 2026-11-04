#!/usr/bin/env python3
import sys
import os
import json
import tempfile
import subprocess
import argparse
from pathlib import Path

# Add src to pythonpath
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))
from mcp_vulnerabilities.scanners.trivy_engine import TrivyScanner

def scan_batch(batch_file: str, output_file: str):
    with open(batch_file, "r") as f:
        data = json.load(f)

    batch_id = data.get("batch_id")
    cohort = data.get("cohort")
    items = data.get("items", [])
    print(f"[*] Processing Batch {batch_id} ({cohort}) with {len(items)} items...")

    scanner = TrivyScanner()
    results = []

    for idx, item in enumerate(items, 1):
        name = item.get("name")
        eco = item.get("ecosystem", "generic")
        deps = item.get("dependencies", {})
        repo = item.get("repository_url")

        findings_count = 0
        findings_summary = []

        with tempfile.TemporaryDirectory() as tmpdir:
            if deps and eco == "npm":
                manifest = os.path.join(tmpdir, "package.json")
                with open(manifest, "w") as mf:
                    json.dump({"name": name or "test-pkg", "dependencies": deps}, mf)
                
                try:
                    subprocess.run(
                        ["npm", "install", "--package-lock-only", "--ignore-scripts"],
                        cwd=tmpdir,
                        check=True,
                        capture_output=True
                    )
                except subprocess.CalledProcessError:
                    try:
                        subprocess.run(
                            ["npm", "install", "--ignore-scripts"],
                            cwd=tmpdir,
                            check=True,
                            capture_output=True
                        )
                    except subprocess.CalledProcessError:
                        pass

                res = scanner.scan_fs(tmpdir)
                findings_count = len(res.findings)
                findings_summary = [f.cve_id for f in res.findings[:5]]
            elif deps and eco in ["pypi", "PyPI"]:
                manifest = os.path.join(tmpdir, "requirements.txt")
                with open(manifest, "w") as mf:
                    for k, v in deps.items():
                        v_clean = v.replace("^", "").replace("~=", "").replace("==", "")
                        mf.write(f"{k}=={v_clean}\n")
                res = scanner.scan_fs(tmpdir)
                findings_count = len(res.findings)
                findings_summary = [f.cve_id for f in res.findings[:5]]
            else:
                findings_count = 0
                findings_summary = []

        results.append({
            "name": name,
            "ecosystem": eco,
            "repository_url": repo,
            "declared_dependencies_count": len(deps),
            "trivy_findings_count": findings_count,
            "sample_cves": findings_summary
        })

    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    summary = {
        "batch_id": batch_id,
        "cohort": cohort,
        "total_scanned": len(results),
        "servers_with_vulnerabilities": sum(1 for r in results if r["trivy_findings_count"] > 0),
        "total_vulnerabilities_found": sum(r["trivy_findings_count"] for r in results),
        "results": results
    }

    with open(output_file, "w") as out:
        json.dump(summary, out, indent=2)

    print(f"[+] Batch {batch_id} completed: {summary['servers_with_vulnerabilities']}/{len(results)} servers have library vulnerabilities. Total CVEs: {summary['total_vulnerabilities_found']}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch", required=True, help="Path to batch JSON")
    parser.add_argument("--output", required=True, help="Path to output JSON")
    args = parser.parse_args()
    scan_batch(args.batch, args.output)
