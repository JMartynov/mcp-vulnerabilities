"""Snapshot builder compiling individual OSV vulnerability JSONs into a consolidated compressed archive."""

from __future__ import annotations

import gzip
import json
import logging
import hashlib
import tarfile
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.feed import AdvisoryFeedBuilder

logger = logging.getLogger("mcp_vulnerabilities.snapshot")

QUERY_SCRIPT_CONTENT = r"""import argparse
import gzip
import json
import re
import sys
from pathlib import Path

def parse_version(v_str):
    clean = v_str.lstrip("v=").strip()
    m = re.match(r"^(\d+(\.\d+)*)", clean)
    if not m:
        return (0, 0, 0)
    parts = [int(p) for p in m.group(1).split(".")]
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts)

def is_vulnerable(ver, ranges, versions):
    if versions and ver in versions:
        return True

    target = parse_version(ver)
    for r in ranges:
        events = r.get("events", [])
        intro = None
        fix = None
        last = None
        
        for ev in events:
            if "introduced" in ev:
                intro = parse_version(ev["introduced"])
            if "fixed" in ev:
                fix = parse_version(ev["fixed"])
            if "last_affected" in ev:
                last = parse_version(ev["last_affected"])
                
        in_range = True
        if intro is not None and target < intro:
            in_range = False
        if fix is not None and target >= fix:
            in_range = False
        if last is not None and target > last:
            in_range = False
            
        if in_range and (intro is not None or fix is not None or last is not None):
            return True
    return False

def check_package(pkg, ver, advisories):
    findings = []
    norm_pkg = pkg.lower()
    for adv in advisories:
        for aff in adv.get("affected", []):
            if aff.get("package", {}).get("name", "").lower() == norm_pkg:
                if ver:
                    if is_vulnerable(ver, aff.get("ranges", []), aff.get("versions", [])):
                        findings.append(adv)
                else:
                    findings.append(adv)
    return findings

def main():
    parser = argparse.ArgumentParser(description="Query airgapped vulnerability database.")
    parser.add_argument("--package", required=True, help="Package specifier, e.g. pkgname@1.2.3")
    args = parser.parse_args()
    
    if "@" in args.package:
        parts = args.package.rsplit("@", 1)
        if len(parts) == 2 and parts[0]:
            pkg = parts[0]
            ver = parts[1]
        else:
            parts = args.package.lstrip("@").rsplit("@", 1)
            pkg = "@" + parts[0]
            ver = parts[1]
    else:
        pkg = args.package
        ver = None

    gz_path = Path("vulnerabilities.json.gz")
    if not gz_path.exists():
        print("Error: vulnerabilities.json.gz not found in current directory.", file=sys.stderr)
        sys.exit(1)
        
    with gzip.open(gz_path, "rt", encoding="utf-8") as f:
        data = json.load(f)
        
    vulns = data.get("vulnerabilities", {})
    if isinstance(vulns, dict):
        advisories = list(vulns.values())
    else:
        advisories = vulns
        
    findings = check_package(pkg, ver, advisories)
    if findings:
        print(f"VULNERABILITIES FOUND FOR {args.package}:")
        for f in findings:
            print(f" - {f.get('id')}: {f.get('summary', 'No summary')}")
        sys.exit(1)
    else:
        print(f"No vulnerabilities found for {args.package}.")
        sys.exit(0)

if __name__ == "__main__":
    main()
"""


def build_snapshot(
    data_dir: str | Path = "data/vulnerabilities",
    output_gz: str | Path = "vulnerabilities.json.gz",
    output_json: str | Path | None = None,
    generate_feeds: bool = True,
) -> dict[str, Any]:
    """Compile all OSV vulnerability JSON files in data_dir into a single consolidated JSON/GZ snapshot."""
    dir_path = Path(data_dir)
    vulnerabilities: dict[str, Any] = {}

    for j_file in sorted(dir_path.rglob("*.json")):
        if j_file.name in ("sync_state.json", "index.json", ".vuln_index.pickle"):
            continue
        try:
            content = json.loads(j_file.read_text(encoding="utf-8"))
            if isinstance(content, dict) and "id" in content:
                vulnerabilities[content["id"]] = content
        except Exception as exc:
            logger.warning("Error reading %s: %s", j_file, exc)

    payload = {
        "version": "1.0.0",
        "schema_version": "1.6.0",
        "total_vulnerabilities": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }
    encoded = json.dumps(payload, ensure_ascii=False, indent=None).encode("utf-8")

    gz_path = Path(output_gz)
    with gzip.open(gz_path, "wb", compresslevel=9) as f:
        f.write(encoded)

    if output_json:
        Path(output_json).write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    gz_size_kb = gz_path.stat().st_size / 1024.0
    logger.info(
        "Successfully compiled snapshot with %d vulnerabilities into %s (%.2f KB)",
        len(vulnerabilities),
        gz_path,
        gz_size_kb,
    )
    if generate_feeds and vulnerabilities:
        feed_dir = dir_path.parent if dir_path.name == "vulnerabilities" else dir_path
        atom_path = feed_dir / "feed.atom"
        json_feed_path = feed_dir / "feed.json"
        try:
            AdvisoryFeedBuilder.generate_atom_feed(list(vulnerabilities.values()), atom_path)
            AdvisoryFeedBuilder.generate_json_feed(list(vulnerabilities.values()), json_feed_path)
        except Exception as exc:
            logger.warning("Error generating threat feeds: %s", exc)

    return {
        "total_vulnerabilities": len(vulnerabilities),
        "snapshot_path": str(gz_path),
        "size_kb": gz_size_kb,
    }


def export_airgap_bundle(
    data_dir: str | Path = "data/vulnerabilities",
    output_tar: str | Path = "dist/mcp-vulnerabilities-offline.tar.gz",
) -> dict[str, Any]:
    """Package the OSV advisory database and an embedded search script into an offline air-gapped bundle."""
    out_path = Path(output_tar)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    
    dir_path = Path(data_dir)
    gz_path = out_path.parent / "vulnerabilities.json.gz"
    
    # Generate snapshot first
    snapshot_res = build_snapshot(data_dir=dir_path, output_gz=gz_path, generate_feeds=False)
    
    query_py_path = out_path.parent / "query.py"
    query_py_path.write_text(QUERY_SCRIPT_CONTENT, encoding="utf-8")
    
    # Create tarball
    with tarfile.open(out_path, "w:gz") as tar:
        # Add generated vulnerabilities.json.gz
        tar.add(gz_path, arcname="vulnerabilities.json.gz")
        # Add query.py
        tar.add(query_py_path, arcname="query.py")
        
        # Add all json files in data_dir (including index.json, excluding sync_state.json)
        for j_file in sorted(dir_path.rglob("*.json")):
            if j_file.name == "sync_state.json":
                continue
            arc_name = Path("data/vulnerabilities") / j_file.relative_to(dir_path)
            tar.add(j_file, arcname=str(arc_name))
            
    # Compute sha256 checksum
    sha256_hash = hashlib.sha256()
    with open(out_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
            
    checksum = sha256_hash.hexdigest()
    checksum_path = out_path.with_suffix(".tar.gz.sha256")
    if out_path.suffix == ".gz" and out_path.stem.endswith(".tar"):
        checksum_path = out_path.parent / (out_path.name + ".sha256")
    elif out_path.suffix == ".gz":
        checksum_path = out_path.with_suffix(".gz.sha256")
        
    checksum_path.write_text(f"{checksum}  {out_path.name}\n", encoding="utf-8")
    
    # Cleanup intermediate files
    if gz_path.exists():
        gz_path.unlink()
    if query_py_path.exists():
        query_py_path.unlink()
        
    logger.info("Created airgap bundle %s (checksum: %s)", out_path, checksum)
    return {
        "bundle_path": str(out_path),
        "checksum": checksum,
        "checksum_path": str(checksum_path),
        "snapshot_info": snapshot_res,
    }


import datetime
import zipfile

from mcp_vulnerabilities.validator import OsvValidator


def export_osv_bucket(data_dir: Path, output_dir: Path) -> dict[str, Any]:
    """Export OSV vulnerabilities to a compliant ecosystem bucket format."""
    data_path = Path(data_dir)
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)
    
    zip_path = out_path / "all.zip"
    manifest_path = out_path / "manifest.json"
    
    vulnerabilities = []
    
    # OSV format requires deterministic zip, meaning stable timestamps and order
    # Using 1980-01-01 00:00:00 as epoch for zip files
    zip_time = (1980, 1, 1, 0, 0, 0)
    
    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
        for j_file in sorted(data_path.rglob("*.json")):
            if j_file.name in ("sync_state.json", "index.json", ".vuln_index.pickle"):
                continue
            try:
                # Read content and rewrite to ensure formatting
                content_dict = json.loads(j_file.read_text(encoding="utf-8"))
                
                # Check for required fields based on OSV 1.6 using OsvValidator
                errors = OsvValidator.validate(content_dict)
                if errors:
                    logger.warning("Validation errors for %s: %s", j_file.name, errors)
                    continue
                # The prompt explicitly asked to ensure modified and published are there as well
                if "modified" not in content_dict or "published" not in content_dict:
                    logger.warning("Missing modified or published for %s", j_file.name)
                    continue
                    
                json_str = json.dumps(content_dict, ensure_ascii=False, indent=2)
                
                # Write to zip deterministically
                zinfo = zipfile.ZipInfo(j_file.name, zip_time)
                # zipfile.ZIP_DEFLATED is already used at the file level but set permissions
                zinfo.external_attr = 0o644 << 16  # standard rw-r--r--
                zinfo.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(zinfo, json_str.encode("utf-8"))
                
                vulnerabilities.append(content_dict)
            except Exception as exc:
                logger.warning("Error reading %s during export: %s", j_file, exc)
                
    # Calculate SHA256 of the zip file
    hasher = hashlib.sha256()
    with open(zip_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hasher.update(chunk)
    zip_sha256 = hasher.hexdigest()
    
    # Create manifest.json
    manifest = {
        "count": len(vulnerabilities),
        "updated": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "sha256": zip_sha256
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    
    logger.info(
        "Successfully exported OSV bucket with %d vulnerabilities to %s (SHA256: %s)",
        len(vulnerabilities),
        output_dir,
        zip_sha256,
    )
    
    return manifest


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    data_dir = sys.argv[1] if len(sys.argv) > 1 else "data/vulnerabilities"
    out_gz = sys.argv[2] if len(sys.argv) > 2 else "vulnerabilities.json.gz"
    res = build_snapshot(data_dir=data_dir, output_gz=out_gz)
    print(f"Compiled {res['total_vulnerabilities']} vulnerabilities ({res['size_kb']:.2f} KB) -> {res['snapshot_path']}")
