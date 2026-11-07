# Task 157A: CVSS Vector Scoring and Severity Extraction Engine

## Objective
Enhance `_extract_severity_info` in `src/mcp_vulnerabilities/audit/matcher.py` and `AdvisoryFusionEngine` in `src/mcp_vulnerabilities/dedup/fusion.py` to parse CVSS v3.1 and v3.0 vector strings into accurate numeric base scores and categorical severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`) when a direct numeric score float is not explicitly provided.

## Requirements
1. In `src/mcp_vulnerabilities/audit/matcher.py`:
   - In `_extract_severity_info(adv, affected)`:
     If `cvss_score` is not numeric, check if `score` matches CVSS vector patterns (`CVSS:3.1/...`, `CVSS:3.0/...`, `CVSS:4.0/...`).
     Parse CVSS 3.x vector metrics (AV, AC, PR, UI, S, C, I, A) to calculate the standard CVSS v3.1 base score, or extract base score metrics.
     Map the computed base score to standard CVSS v3.x qualitative ratings:
       - None: 0.0
       - LOW: 0.1 - 3.9
       - MEDIUM: 4.0 - 6.9
       - HIGH: 7.0 - 8.9
       - CRITICAL: 9.0 - 10.0
2. In `src/mcp_vulnerabilities/dedup/fusion.py`:
   - Use the computed score in `get_severity_score` to prioritize authoritative scores accurately.
3. Unit Tests:
   - Add unit tests in `tests/test_cvss_vector_scoring.py` verifying:
     - Vector `CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N` correctly calculates base score (e.g. 6.8 - 7.5) and maps to HIGH or MEDIUM appropriately.
     - Vectors with CRITICAL metrics (e.g. `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` -> 9.8 CRITICAL).
     - Advisory `CVE-2025-10193` is parsed with a non-UNKNOWN severity.
4. Verify all tests pass (`pytest`).
