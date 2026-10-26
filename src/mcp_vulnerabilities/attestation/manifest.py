import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path

class ChecksumMismatchError(Exception):
    pass

def hash_file(filepath: Path) -> str:
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def generate_catalog_manifest(data_dir: str | Path) -> str:
    data_dir = Path(data_dir)
    manifest = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": {}
    }

    targets = ["vulnerabilities.json.gz", "mcp_catalog_index.json", "analytics.json"]
    for target in targets:
        filepath = data_dir / target
        if filepath.exists():
            manifest["files"][target] = {
                "sha256": hash_file(filepath),
                "size": filepath.stat().st_size
            }

    # Sort files deterministically
    manifest["files"] = dict(sorted(manifest["files"].items()))
    
    manifest_path = data_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")

    return str(manifest_path)

def verify_catalog_manifest(data_dir: str | Path) -> None:
    data_dir = Path(data_dir)
    manifest_path = data_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    with open(manifest_path, "r") as f:
        manifest = json.load(f)

    for filename, info in manifest.get("files", {}).items():
        filepath = data_dir / filename
        if not filepath.exists():
            raise FileNotFoundError(f"Tracked file missing: {filepath}")
        
        current_hash = hash_file(filepath)
        if current_hash != info["sha256"]:
            raise ChecksumMismatchError(f"Hash mismatch for {filename}. Expected {info['sha256']}, got {current_hash}")
