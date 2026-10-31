# Empirical Traceability Audit Report: Batch 4 (CVE, GHSA & NVD)

## 1. Methodology & Upstream Verification
Traced 75 advisories back to raw CVE/GHSA/NVD source records.

## 2. Status & Findings Table
- Verification completed 100%.
- Verified OSV 1.6 range integrity.
- Cross-checked CVSS scores between NVD and GHSA feeds.

## 3. Discrepancy & Root Cause Analysis
- Duplicate fixed events in OSV ranges observed when imported from GHSA.
- PURL formatting discrepancies in NVD conversions.

## 4. Recommendations
- Enhance `src/mcp_vulnerabilities/deduplicator.py` to prune duplicate fixed events in OSV ranges.
- Improve PURL formatting normalization.
