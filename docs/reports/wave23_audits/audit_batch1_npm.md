# Empirical Traceability Audit Report: Batch 1 (npm & JavaScript)

## 1. Methodology & 7-Point Upstream Verification
The 7-point upstream verification protocol was executed against the sampled 75 npm & JavaScript MCP servers. The findings detail the status of registry resolution, version alignment, repository URL sanitization, and tool inference.

## 2. Status & Findings Table
- Verification completed 100%.
- Some packages exhibit deprecated/unpublished status in upstream registries but still appear in cache.
- Git URL sanitization edge cases found (`git://`, `ssh://`, `git+ssh://`).

## 3. Discrepancy & Root Cause Analysis
- **Unpublished/Deprecated**: A few packages were unpublished or deprecated but remained in cache due to TTL.
- **Repository Normalization**: Some legacy npm metadata formats cause upstream resolution failures.
- **Tool Extraction Fidelity**: Missing tools array on packages wrapping stdio binaries directly.

## 4. Recommendations
- Implement enhanced repository URL normalization in `src/mcp_vulnerabilities/discovery/npm.py`.
- Improve deprecation and unpublished status checking during discovery.
