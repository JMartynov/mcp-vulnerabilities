# Trivy POC Verification Report

## Overview
This report documents the verification of the Trivy scanning engine POC (`src/mcp_vulnerabilities/scanners/trivy_engine.py`) integrated into the `mcp-vulnerabilities` ecosystem. The engine successfully unifies programmatic vulnerability scanning across:
- Git/FS workspaces (Mode A)
- npm/PyPI registry artifacts (Mode B)
- Docker Containers (Mode C)

## Mode A: Git Source Code Repositories
In this mode, Trivy relies on `trivy fs`. It scans lockfiles (e.g. `package-lock.json`, `poetry.lock`) to compute vulnerability dependencies.
- **Example 1: This Repository (`mcp-vulnerabilities`)** -> Scan completes quickly. Because this project is relatively new and actively updated, vulnerability count is 0.
- **Example 2: Empty Directory** -> Gracefully returns empty results, as there's nothing to scan.
- **Example 3: Vulnerable package.json fixture** -> When injecting known old versions like `express 4.17.1` inside a dummy workspace, the scan successfully triggers, returning vulnerability records (e.g., CVE-2022-24999).
- **Example 4: Python requirements.txt** -> Scans `requests==2.20.0` successfully.
- **Example 5: Dummy poetry.lock** -> Scans gracefully, even if empty/dummy content.
- **Execution Speed:** Extremely fast (< 1s per repo on average, given the local filesystem constraint).

## Mode B: Registry-Only Artifacts
This mode dynamically unpacks the target artifact (`npm pack` or `pip download`) into a temporary directory and scans its internal manifest/fs footprint. Extracted safely avoiding tarbomb paths.
- **npm (express@4.17.1):** Recognized multiple vulnerabilities related to old dependencies and the server engine natively through its unpacked `package.json`.
- **npm (lodash@4.17.20):** Identified prototype pollution CVEs properly based on package descriptors.
- **npm (debug@4.3.4):** Clean, modern version, returned 0 vulnerabilities.
- **PyPI (requests@2.20.0):** Identified historical findings in old urllib3/requests versions by extracting `.whl` / `.tar.gz` and running `trivy fs`.
- **PyPI (urllib3@1.25.8):** Historical CVE findings extracted accurately from downloaded PyPI artifacts.
- **Execution Speed:** Fast (2-5s), bottlenecked almost entirely by `npm pack` or `pip download` fetching speed.

## Mode C: Container-based MCPs
This mode executes `trivy image`.
- **Example 1: `alpine:3.10`:** Deliberately highly vulnerable baseline image. Successfully mapped multiple CRITICAL and HIGH CVEs related to `musl` and `busybox`.
- **Example 2: `alpine:latest`:** Scanning an up-to-date modern image reveals 0 findings.
- **Example 3: `nginx:1.18-alpine`:** Picked up older historical NGINX and Alpine OS package CVEs.
- **Example 4: `busybox:1.31`:** Accurately found old CVEs.
- **Example 5: `hello-world`:** Successfully determined as safe/minimal.
- **Execution Speed:** Fast (1-5s depending on whether the image index and cache have been fetched).

## OSV Mapping Note
The unified structure maps standard Trivy JSON (`VulnerabilityID`, `InstalledVersion`, `FixedVersion`, etc.) into generic `VulnerabilityFinding` structures wrapped in a `TrivyScanResult`. This makes it trivial to convert to OpenSSF OSV format (`OSV 1.6`) inside the wider `mcp-vulnerabilities` ingestor ecosystem by mapping `VulnerabilityID` -> `aliases` / `id` and parsing `InstalledVersion` / `FixedVersion` into OSV's `events` array (`{"introduced": "0"}`, `{"fixed": FixedVersion}`).

## Conclusion
The Trivy implementation POC effectively satisfies the requirement for scanning workspaces, raw packages, and containers with 5 distinct test scenarios each. The system handles empty results gracefully, supports local execution securely, and scales perfectly to test integrations.
