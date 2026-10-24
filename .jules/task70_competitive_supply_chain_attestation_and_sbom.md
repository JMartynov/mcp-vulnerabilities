# Task 70: Competitive Analysis — Supply Chain Attestation, Sigstore & CycloneDX AIBOM Standards (P1)

## 1. Architectural Context & Technical Objective

Modern enterprise supply chain security requires verifiable attestations and cryptographic provenance. Frameworks such as **Sigstore (Cosign / Rekor)**, **in-toto**, **CycloneDX AI BOM (v1.5/v1.6)**, and **OpenSSF Scorecards** provide cryptographic guarantees that code, models, and vulnerability feeds have not been tampered with in transit:
1. **Sigstore/Cosign**: Keyless OIDC signing, transparency log inclusion (Rekor), and verifiable identity certificates (Fulcio).
2. **in-toto & SLSA**: Cryptographic proof of build environment integrity (SLSA Build Level 3) guaranteeing reproducible artifacts.
3. **CycloneDX AI/ML BOM**: Standardized machine-readable bills of materials representing AI models, training datasets, MCP server capabilities, and tool execution boundaries.
4. **OpenSSF Scorecards**: Automated security metric scoring for upstream repositories (branch protection, vulnerability disclosure policies, binary artifacts, code review enforcement).

This task conducts an in-depth technical analysis comparing `mcp-vulnerabilities` SBOM exporter (`compliance/cyclonedx.py`) and release pipeline against modern supply chain attestation standards, identifying missing capabilities, grading gaps by **HIGH**, **MEDIUM**, and **LOW** priority, and publishing a comprehensive report to `docs/audit/competitive_supply_chain_sbom.md`.

---

## 2. Competitive Scope & Comparison Matrix Areas
- **Target Standards & Tools**: Sigstore Cosign, Rekor Transparency Log, in-toto attestation framework, CycloneDX v1.6 AIBOM specification, OpenSSF Scorecard CLI.
- **Key Dimensions**:
  - Cryptographic Feed Attestation: Are `vulnerabilities.json.gz` and PyPI releases signed with verifiable keyless Sigstore signatures?
  - SLSA Build Provenance: Are GitHub Release artifacts generated with signed SLSA Level 3 provenance predicates?
  - CycloneDX AIBOM Completeness: Does the exporter populate tool parameter schemas, execution permission flags, and ML model dependencies?
  - Upstream MCP Repository Posture: Can `mcp-vulnerabilities` query OpenSSF Scorecard API to score upstream server maintenance health?
- **Deliverable**: `docs/audit/competitive_supply_chain_sbom.md`

---

## 3. Detailed Benchmark Analysis Requirements

### Section 1: Standards Alignment & Feature Matrix
- Document a detailed comparison table between `mcp-vulnerabilities` v1.1.0 and Sigstore / in-toto / CycloneDX / OpenSSF standards.
- Evaluate the schema completeness of `src/mcp_vulnerabilities/compliance/cyclonedx.py`.

### Section 2: Grading of Missed Capabilities
- **HIGH Severity Gaps**:
  - Lack of Cryptographic Attestation for Vulnerability Feeds: Feeds distributed to clients or web portals lack Sigstore / Rekor cryptographic verification, leaving them vulnerable to MITM cache poisoning.
  - Absence of OpenSSF Scorecard Integration: Upstream GitHub repos of MCP servers are not scored for risky maintenance practices (e.g. unreviewed PR merges, unpinned actions).
- **MEDIUM Severity Gaps**:
  - Incomplete CycloneDX v1.6 AI Extension Mapping (missing explicit machine learning component types and hardware execution requirements).
  - Absence of SLSA Build Level 3 provenance in the PyPI release workflow.
- **LOW Severity Gaps**:
  - Missing SPDX 3.0 export format alongside CycloneDX.

### Section 3: Concrete Architectural Proposals & Implementation Specifications
- Provide GitHub Actions workflow definitions for keyless Sigstore signing of PyPI wheels and daily snapshot bundles.
- Design Python schema extensions for OpenSSF Scorecard metrics in `mcp_fingerprints.models.ServerPassport`.

---

## 4. Implementation Steps

1. Review CycloneDX v1.6 spec, Sigstore Python SDK (`sigstore-python`), and OpenSSF Scorecard REST API.
2. Draft comprehensive technical report in `docs/audit/competitive_supply_chain_sbom.md` adhering strictly to HIGH/MEDIUM/LOW severity grading.
3. Include GitHub Actions workflow YAML designs and Pydantic schema extensions.

## Non-Interactive Completion Directive
Execute this task end-to-end without asking interactive questions. Formulate the in-depth technical benchmark report in `docs/audit/competitive_supply_chain_sbom.md` with full technical depth and severity classifications, and conclude directly with a complete patch so the remote environment cleanly transitions to `Completed`.
