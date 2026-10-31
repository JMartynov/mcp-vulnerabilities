# Empirical Traceability Audit Report: Batch 3 (Go, Rust, Docker, GitHub Raw)

## 1. Methodology & Upstream Verification
Verified 75 polyglot endpoints (Go, Cargo, Docker, GitHub Raw) across the upstream registries.

## 2. Status & Findings Table
- Verification completed 100%.
- GitHub repositories include deleted and archived repos.
- Docker Hub versioning strategies highlight the need for digest pinning.

## 3. Discrepancy & Root Cause Analysis
- Go modules prefix versions with `v`, causing SemVer mismatch in some comparators.
- Missing Cargo crates and deleted GitHub repos persist.

## 4. Recommendations
- Add repository archiving detection in `src/mcp_vulnerabilities/discovery/github_curated.py`.
- Normalize SemVer tags across ecosystems (`v`-stripping).
