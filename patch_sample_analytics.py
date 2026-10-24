import json

with open("docs/data/analytics.json") as f:
    data = json.load(f)
    
data["patched_remediable_count"] = 100
data["zero_day_unpatched_count"] = 200
data["capabilities"] = {
    "fs_read_write": 500,
    "shell_exec": 300,
    "network_egress": 400,
    "mutating": 800,
    "read_only": 1500
}
data["top_secrets"] = [{"name": "OPENAI_API_KEY", "count": 100}]
data["transports"] = {"stdio": 500, "sse": 50}
data["tool_shadowing"] = [{"tool": "search", "entropy": 50}]

with open("docs/data/analytics.json", "w") as f:
    json.dump(data, f, indent=2)
