#!/usr/bin/env python3
import json
import subprocess
import os
import sys
from pathlib import Path

def main():
    state_file = Path("docs/reports/batches/queue_execution_state.json")
    if not state_file.exists():
        print("No execution state file found.")
        return

    state = json.loads(state_file.read_text())
    print(f"Checking {len(state)} dispatched sessions...")

    # Fetch ps status
    ps_proc = subprocess.run(["jules-gate", "ps"], text=True, capture_output=True)
    ps_lines = ps_proc.stdout.splitlines()

    completed_session_ids = set()
    for line in ps_lines:
        if "Completed" in line:
            parts = line.split()
            if parts:
                completed_session_ids.add(parts[0])

    print(f"Total sessions reporting 'Completed' status: {len(completed_session_ids)}")

    pulled_count = 0
    for chunk_key, info in state.items():
        sess_id = info.get("session_id")
        if not sess_id and "task_id" in info:
            # Need to match session ID if recorded
            pass

    # Inspect all session outputs and pull patches
    for sid in sorted(list(completed_session_ids)):
        try:
            diff_proc = subprocess.run(["jules", "remote", "pull", "--session", sid], text=True, capture_output=True)
            diff_text = diff_proc.stdout
            if "results/" in diff_text and "result_chunk_" in diff_text:
                apply_proc = subprocess.run(["git", "apply", "--reject", "-"], input=diff_text, text=True, capture_output=True)
                if apply_proc.returncode == 0:
                    print(f"[+] Successfully pulled and applied patch from session {sid}")
                    pulled_count += 1
                else:
                    if "already exists" in apply_proc.stderr:
                        pass # already merged
                    else:
                        print(f"[!] Warning on applying patch from session {sid}: {apply_proc.stderr[:100]}")
        except Exception as e:
            pass

    print(f"[*] Pulled and merged {pulled_count} new result files into working directory.")

if __name__ == "__main__":
    main()
