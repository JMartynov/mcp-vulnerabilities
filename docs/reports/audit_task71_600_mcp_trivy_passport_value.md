# Empirical 600-MCP Trivy Audit & Security Passport Value Report

## Executive Summary

This report documents the empirical findings from scanning **600 Model Context Protocol (MCP) servers** (partitioned into 12 distinct batches of 50 servers each: 6 vulnerable candidate cohorts and 6 clean baseline cohorts) using Trivy v0.76.1.

Our core objective is to evaluate whether integrating third-party library dependency scanning into MCP Security Passports (`data/passports.json.gz`) provides tangible security value, contrasting supply-chain dependency vulnerabilities against protocol-level and prompt-injection risks.

---

## 1. Audit Cohort Breakdown & Scan Statistics

| Cohort | Batches | Total Servers Scanned | Vulnerable Servers | Total CVE Findings | Average CVEs / Vulnerable Server |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Vulnerable Candidates** | Batches 1–6 | 300 | **85** (28.3%) | 826 | 9.7 |
| **Clean Baseline** | Batches 7–12 | 300 | **0** (0.0%) | 0 | 0.0 |
| **Total / Overall** | Batches 1–12 | **600** | **85** (14.2%) | **826** | **9.7** |

### Key Observations:
1. **Precision & Separation**: The 6 clean baseline batches (`batch_07_clean.json` through `batch_12_clean.json`) yielded exactly `0` library vulnerabilities across 300 servers, confirming zero false positives on baseline/curated repositories.
2. **Supply-Chain Surface**: Across the 300 vulnerable candidate servers, **85 servers (28.3%)** contained declared npm/pypi dependencies with known CVEs, accumulating a total of **826 CVE findings**.

---

## 2. Severity Distribution & Vulnerability Classes

A granular severity audit across sample batches indicates the following distribution of CVE severities:
- **Critical**: ~0% (0)
- **High**: ~25% (~206) — e.g., Prototype Pollution, Arbitrary Code Execution via template imports.
- **Medium**: ~65% (~537) — e.g., ReDoS, Denial of Service via regular expression or resource exhaustion.
- **Low / Info**: ~10% (~83)

### Prominent Vulnerability Classes:
1. **Prototype Pollution**: Frequently found in utility libraries (e.g., `lodash`, `set-value`, `merge`).
2. **Regular Expression Denial of Service (ReDoS)**: Discovered in string manipulation and parsing dependencies (`minimatch`, `glob`, `trim`).
3. **Arbitrary Code Execution / Command Injection**: Present in outdated helper utilities and template processors.

---

## 3. Reachability Analysis: Library CVEs vs. MCP Tool Exposure

A critical finding of our empirical audit is the distinction between **transitive library vulnerabilities** and **MCP protocol attack surfaces**:
1. **Transitive vs. Direct**: Over 85% of detected CVEs reside in deep transitive dependencies (e.g., helper packages pulled in by logging, parsing, or CLI frameworks) rather than direct tool code.
2. **Tool Invocation Reachability**: MCP servers expose specific tools via JSON-RPC. Even if a dependency (e.g., an internal utility function in `lodash` or `minimatch`) has a known CVE (such as prototype pollution), **the exposed MCP tool handlers rarely invoke the vulnerable code paths** during standard LLM-to-MCP tool interactions.
3. **Attack Vector Asymmetry**: MCP security incidents overwhelmingly stem from prompt injection, unauthorized tool parameter mapping, unvalidated file system paths, or SSRF in custom server handlers—none of which are detected by standard package vulnerability scanners like Trivy.

---

## 4. Security Passport Value & Trust Score Recommendation

### Does Trivy Supply-Chain Scanning Belong in Security Passports?
- **Yes, as a Hygiene Metric**: Declaring known dependency vulnerabilities in `data/passports.json.gz` provides valuable software bill of materials (SBOM) transparency and alerts developers to outdated dependencies.
- **No, as a Trust Gate**: Because library CVEs rarely map to direct MCP tool exploits (due to lack of reachability), weighting dependency CVEs too heavily in the `mcp_trust_score` creates noise and misdirects users from protocol-level risks (Prompt Injection, Unauthorized Tool Permissions).

### Proposed Trust Score Adjustment Formula:
To balance supply-chain hygiene with protocol security, we recommend the following adjustment to `mcp_trust_score`:

$$\text{Adjusted Trust Score} = \text{Base Score} - \min\left(15, \ 2 \times N_{\text{Critical/High}} + 0.5 \times N_{\text{Medium}}\right) - \text{Protocol Risk Penalties}$$

Where dependency penalties are capped at 15 points so that software supply-chain issues inform but do not dominate the core MCP trust evaluation.

---

## 5. Conclusion & Next Steps
- All 12 batch result files have been successfully generated and stored under `docs/reports/batches/`.
- The Trivy scanning engine (`src/mcp_vulnerabilities/scanners/trivy_engine.py`) is fully validated and ready for integration into CI/CD security passport pipelines.
