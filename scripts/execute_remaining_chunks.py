#!/usr/bin/env python3
import subprocess
import os
import sys
from pathlib import Path

MISSING = [
    ("track_a", "chunk_06", "data/chunks/track_a/chunk_06.json", "results/track_a/result_chunk_06.json"),
    ("track_a", "chunk_07", "data/chunks/track_a/chunk_07.json", "results/track_a/result_chunk_07.json"),
    ("track_a", "chunk_08", "data/chunks/track_a/chunk_08.json", "results/track_a/result_chunk_08.json"),
    ("track_a", "chunk_09", "data/chunks/track_a/chunk_09.json", "results/track_a/result_chunk_09.json"),
    ("track_a", "chunk_10", "data/chunks/track_a/chunk_10.json", "results/track_a/result_chunk_10.json"),
    ("track_b", "chunk_01", "data/chunks/track_b/chunk_01.json", "results/track_b/result_chunk_01.json"),
    ("track_b", "chunk_02", "data/chunks/track_b/chunk_02.json", "results/track_b/result_chunk_02.json"),
]

def main():
    print(f"[*] Executing remaining {len(MISSING)} chunks to reach 100% database completion...")
    for idx, (tr, stem, cpath, rpath) in enumerate(MISSING, 1):
        print(f"[{idx}/{len(MISSING)}] Processing {tr} {stem} -> {rpath}...")
        os.makedirs(os.path.dirname(rpath), exist_ok=True)
        cmd = [sys.executable, "scripts/run_chunk_audit.py", "--chunk", cpath, "--output", rpath]
        try:
            res = subprocess.run(cmd, check=True)
            print(f"[+] Completed {tr} {stem}")
        except subprocess.CalledProcessError as e:
            print(f"[!] Error on {tr} {stem}: {e}")

    print("[*] All 7 remaining chunks executed.")

if __name__ == "__main__":
    main()
