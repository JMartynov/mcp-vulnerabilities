import subprocess
import sys
import json
from pathlib import Path

# Load all 62 chunks
all_chunks = []
for track in ['track_a', 'track_b', 'track_c']:
    p = Path(f'data/chunks/{track}')
    if p.exists():
        for f in sorted(p.glob('chunk_*.json')):
            all_chunks.append({
                'track': track,
                'chunk_stem': f.stem,
                'chunk_path': str(f),
                'output_path': f"results/{track}/result_{f.stem}.json"
            })

# We want chunks from index 5 to 55 (50 chunks)
target_chunks = all_chunks[5:55]
print(f"Targeting {len(target_chunks)} chunks for parallel dispatch...")

dispatched = []

for idx, c in enumerate(target_chunks, 1):
    track_name = c['track'].replace('_', ' ').title()
    chunk_num = c['chunk_stem'].split('_')[-1]
    track_code = c['track'].split('_')[-1].upper()
    chunk_id = f"Task 72.{track_code}.{chunk_num}"
    
    cmd_prompt = [
        "python3", "scripts/format_chunk_prompt.py",
        chunk_id, track_name, c['chunk_path'], c['output_path']
    ]
    prompt = subprocess.check_output(cmd_prompt, text=True)
    
    # Dispatch remote session
    cmd_dispatch = [
        "jules", "remote", "new",
        "--repo", "JMartynov/mcp-vulnerabilities",
        "--session", prompt
    ]
    
    try:
        out = subprocess.check_output(cmd_dispatch, text=True).strip()
        # Extract session ID from output
        session_id = None
        for line in out.splitlines():
            if "session" in line.lower() or "id" in line.lower() or line.isdigit():
                words = line.replace('/', ' ').replace(':', ' ').split()
                for w in words:
                    if w.isdigit() and len(w) >= 15:
                        session_id = w
                        break
            if session_id:
                break
        if not session_id and out.strip().isdigit():
            session_id = out.strip()
            
        print(f"[{idx}/50] Dispatched {chunk_id}: Session {session_id or out}")
        dispatched.append({
            'chunk_id': chunk_id,
            'session_id': session_id or out,
            'chunk_path': c['chunk_path'],
            'output_path': c['output_path']
        })
    except subprocess.CalledProcessError as e:
        print(f"[!] Error dispatching {chunk_id}: {e}")

with open("docs/reports/batches/dispatched_wave2_50_sessions.json", "w") as f:
    json.dump(dispatched, f, indent=2)

print(f"Successfully recorded {len(dispatched)} dispatched sessions to docs/reports/batches/dispatched_wave2_50_sessions.json")
