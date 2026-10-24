#!/usr/bin/env python3
"""
Trigger upstream cross-repo repository dispatch event to mcp-vulnerabilities.
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error

def trigger_dispatch(token: str, version: str, count: int, repo: str = "jmartynov/mcp-vulnerabilities"):
    url = f"https://api.github.com/repos/{repo}/dispatches"
    
    payload = {
        "event_type": "upstream_fingerprints_updated",
        "client_payload": {
            "upstream_version": version,
            "passports_count": count
        }
    }
    
    data = json.dumps(payload).encode("utf-8")
    
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("Content-Type", "application/json")
    
    try:
        with urllib.request.urlopen(req) as response:
            if response.status == 204:
                print(f"Successfully triggered repository_dispatch on {repo}")
                return True
            else:
                print(f"Unexpected status code: {response.status}")
                return False
    except urllib.error.HTTPError as e:
        print(f"HTTP Error: {e.code} {e.reason}")
        print(e.read().decode())
        return False
    except Exception as e:
        print(f"Error: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(description="Trigger cross-repo dispatch event.")
    parser.add_argument("--version", required=True, help="Upstream release version")
    parser.add_argument("--count", type=int, required=True, help="Passports count")
    parser.add_argument("--repo", default="jmartynov/mcp-vulnerabilities", help="Target repository")
    
    args = parser.parse_args()
    
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("Error: GITHUB_TOKEN environment variable not set.")
        sys.exit(1)
        
    success = trigger_dispatch(token, args.version, args.count, args.repo)
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()
