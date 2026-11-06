#!/usr/bin/env python3
import subprocess
import time
import json
import os
from pathlib import Path

MAX_CONCURRENT_SESSIONS = 10
TRACKS = ["track_a", "track_b", "track_c"]

def get_all_chunks():
    chunks = []
    for tr in TRACKS:
        p = Path(f"data/chunks/{tr}")
        if p.exists():
            for f in sorted(p.glob("chunk_*.json")):
                chunks.append({
                    "track": tr,
                    "chunk_stem": f.stem,
                    "chunk_path": str(f),
                    "output_path": f"results/{tr}/result_{f.stem}.json"
                })
    return chunks

def get_active_jules_count():
    try:
        out = subprocess.check_output(["jules-gate", "ps"], text=True, stderr=subprocess.DEVNULL)
        active = 0
        for line in out.splitlines():
            l_lower = line.lower()
            if "planning" in l_lower or "in progress" in l_lower or "in_progress" in l_lower:
                active += 1
        return active
    except Exception:
        return 0

def is_chunk_completed(output_path):
    p = Path(output_path)
    return p.exists() and p.stat().st_size > 100

def main():
    chunks = get_all_chunks()
    state_file = Path("docs/reports/batches/queue_execution_state.json")
    state = {}
    if state_file.exists():
        try:
            state = json.loads(state_file.read_text())
        except Exception:
            state = {}

    print(f"[*] Total Database Chunks in Pool: {len(chunks)}")
    
    for c in chunks:
        cid = f"{c['track']}_{c['chunk_stem']}"
        if cid in state and state[cid].get("status") in ["DISPATCHED", "COMPLETED"]:
            continue
            
        # Check concurrency slot
        while True:
            active = get_active_jules_count()
            if active < MAX_CONCURRENT_SESSIONS:
                break
            print(f"[*] Active cloud sessions: {active}/{MAX_CONCURRENT_SESSIONS}. Waiting 15s for slot...")
            time.sleep(15)

        track_name = c['track'].replace('_', ' ').title()
        chunk_num = c['chunk_stem'].split('_')[-1]
        track_code = c['track'].split('_')[-1].upper()
        task_id = f"Task 72.{track_code}.{chunk_num}"

        cmd_prompt = [
            "python3", "scripts/format_chunk_prompt.py",
            task_id, track_name, c['chunk_path'], c['output_path']
        ]
        try:
            prompt = subprocess.check_output(cmd_prompt, text=True)
            dispatch_proc = subprocess.run(
                ["jules", "remote", "new", "--repo", "JMartynov/mcp-vulnerabilities"],
                input=prompt,
                text=True,
                capture_output=True
            )
            out = dispatch_proc.stdout + dispatch_proc.stderr
            if "status 400" in out or "FAILED_PRECONDITION" in out:
                print(f"[!] Quota limit reached on {task_id}. Backing off 30s...")
                time.sleep(30)
                continue
                
            print(f"[+] Successfully dispatched {task_id} -> {out.strip()[:60]}")
            state[cid] = {"status": "DISPATCHED", "task_id": task_id, "dispatched_at": time.time()}
            state_file.write_text(json.dumps(state, indent=2))
            time.sleep(3) # Small delay to avoid burst rate-limiting
        except Exception as e:
            print(f"[!] Error on {task_id}: {e}")
            time.sleep(10)

if __name__ == "__main__":
    main()
