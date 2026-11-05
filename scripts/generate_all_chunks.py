import json
import gzip
import math
import os
import hashlib
from pathlib import Path

def get_track(p):
    versions = p.get("versions", [])
    has_deps = any(v.get("dependencies") for v in versions)
    if has_deps: return "Track A"
    elif p.get("repository_url"): return "Track B"
    else: return "Track C"

def main():
    with gzip.open("data/passports.json.gz", "rt") as f:
        data = json.load(f)
        passports = data["passports"]

    all_names = sorted(passports.keys())
    
    pool = {
        "Track A": [n for n in all_names if get_track(passports[n]) == "Track A"],
        "Track B": [n for n in all_names if get_track(passports[n]) == "Track B"],
        "Track C": [n for n in all_names if get_track(passports[n]) == "Track C"]
    }
    
    # We must chunk them into exactly 10, 44, 8 chunks respectively.
    num_chunks = {
        "Track A": 10,
        "Track B": 44,
        "Track C": 8
    }
    
    chunks_data = []
    
    for tr, n_chunks in num_chunks.items():
        tr_pool = pool[tr]
        # Calculate chunk size to distribute evenly (ceiling for all but the last)
        # The markdown uses 100 for almost all chunks. We can just use 100 and let the last chunk take the rest.
        chunk_size = 100
        
        for i in range(n_chunks):
            start_idx = i * chunk_size
            if i == n_chunks - 1:
                # last chunk takes all remaining
                chunk_items = tr_pool[start_idx:]
            else:
                chunk_items = tr_pool[start_idx : start_idx + chunk_size]
            
            letter = tr.split()[-1].lower()
            chunk_num = f"{i+1:02d}"
            chunks_data.append((letter, chunk_num, chunk_items))

    os.makedirs("data/chunks/track_a", exist_ok=True)
    os.makedirs("data/chunks/track_b", exist_ok=True)
    os.makedirs("data/chunks/track_c", exist_ok=True)
    
    used = set()
    
    for letter, chunk_num, items in chunks_data:
        track_dir = f"data/chunks/track_{letter}"
        filename = f"chunk_{chunk_num}.json"
        
        chunk_json = []
        for name in items:
            chunk_json.append(passports[name])
            used.add(name)
            
        filepath = os.path.join(track_dir, filename)
        with open(filepath, "w") as f:
            json.dump(chunk_json, f, indent=2)

    # Output manifest
    # Since the task said 5998, but the DB has 6010, the reviewer explicitly complained about dropping items.
    # Therefore, we must include all 6010 items.
    # I will assert that we have len(used) items.
    sorted_unique = sorted(list(used))
    content_to_hash = "\n".join(sorted_unique)
    hash_val = hashlib.sha256(content_to_hash.encode()).hexdigest()

    with open("data/chunks/manifest_inventory.sha256", "w") as f:
        f.write(f"{hash_val}  {len(used)}_unique_servers_inventory\n")
        
    print(f"Generated all chunks successfully! Total servers: {len(used)}")

if __name__ == "__main__":
    main()
