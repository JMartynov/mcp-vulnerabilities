# Competitive Analysis — Supply Chain Attestation, Sigstore & CycloneDX AIBOM Standards

## 1. Architectural Context & Technical Objective

Modern enterprise supply chain security requires verifiable attestations and cryptographic provenance. Frameworks such as **Sigstore (Cosign / Rekor)**, **in-toto**, **CycloneDX AI BOM (v1.5/v1.6)**, and **OpenSSF Scorecards** provide cryptographic guarantees that code, models, and vulnerability feeds have not been tampered with in transit:

1. **Sigstore/Cosign**: Keyless OIDC signing, transparency log inclusion (Rekor), and verifiable identity certificates (Fulcio).
2. **in-toto & SLSA**: Cryptographic proof of build environment integrity (SLSA Build Level 3) guaranteeing reproducible artifacts.
3. **CycloneDX AI/ML BOM**: Standardized machine-readable bills of materials representing AI models, training datasets, MCP server capabilities, and tool execution boundaries.
4. **OpenSSF Scorecards**: Automated security metric scoring for upstream repositories (branch protection, vulnerability disclosure policies, binary artifacts, code review enforcement).

This document conducts an in-depth technical analysis comparing the `mcp-vulnerabilities` SBOM exporter (`compliance/cyclonedx.py`) and release pipelines against modern supply chain attestation standards. We identify missing capabilities, grade gaps by severity, and propose concrete architectural remediation.

---

## 2. Standards Alignment & Feature Matrix

The following matrix compares `mcp-vulnerabilities` v1.1.0 capabilities against modern supply chain security standards.

| Capability / Standard | Sigstore (Cosign/Rekor) | in-toto / SLSA Level 3 | CycloneDX v1.6 AIBOM | OpenSSF Scorecards | `mcp-vulnerabilities` (Current State) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Cryptographic Feed Signatures** | Yes (Keyless OIDC) | - | - | - | Missing. Feeds rely on TLS without cryptographic identity. |
| **Build Provenance** | - | Yes (SLSA Build L3) | - | - | Missing. GitHub Actions publish to PyPI without in-toto predicates. |
| **AI Model & Tool Boundary Representation** | - | - | Yes | - | Partial mapping. Exporter translates tools to endpoints but lacks ML extensions. |
| **Repository Maintenance Posture** | - | - | - | Yes | Missing. Does not query OpenSSF API for upstream repo health scores. |

### Evaluation of `src/mcp_vulnerabilities/compliance/cyclonedx.py` Schema Completeness

The current CycloneDX exporter models MCP servers as `service` components and MCP tools as `endpoints`. While it embeds VEX (Vulnerability Exploitability eXchange) elements and uses SHA-256 hashes for cryptographic identity, it exhibits structural schema gaps when compared to the **CycloneDX v1.6 AI Extension**:
- Missing definitions for `machineLearningModel` dependencies if an MCP tool wraps an LLM.
- Absence of explicitly defined execution permission boundaries and resource constraints (e.g. read-only vs. read-write tool definitions) mapping to AI BOM parameters.
- Missing `data` components detailing the nature of datasets consumed by MCP tools.

---

## 3. Grading of Missed Capabilities

### HIGH Severity Gaps
* **Lack of Cryptographic Attestation for Vulnerability Feeds**:
  Feeds distributed to clients or web portals (`vulnerabilities.json.gz`) lack Sigstore / Rekor cryptographic verification. This leaves downstream consumers vulnerable to MITM cache poisoning and tampering by rogue CDN nodes.
* **Absence of OpenSSF Scorecard Integration**:
  Upstream GitHub repositories of MCP servers are not scored for risky maintenance practices (e.g., unreviewed PR merges, unpinned actions, lack of branch protection). The risk of adopting a malicious or hijacked upstream MCP server is high without automated health scoring.

### MEDIUM Severity Gaps
* **Incomplete CycloneDX v1.6 AI Extension Mapping**:
  Missing explicit machine learning component types, data datasets boundaries, and hardware execution requirements in the CycloneDX export prevents deep integrations with MLOps supply chain monitors.
* **Absence of SLSA Build Level 3 provenance in the PyPI release workflow**:
  While the project utilizes trusted PyPI OIDC publishing, the release pipeline does not generate verifiable SLSA Build Level 3 provenance (e.g. `provenance.intoto.jsonl`), undermining artifact reproducibility verifiability.

### LOW Severity Gaps
* **Missing SPDX 3.0 export format alongside CycloneDX**:
  While CycloneDX 1.6 is the preferred standard for AI/ML BOMs, enterprise pipelines that strictly enforce SPDX (Software Package Data Exchange) parsing are currently unsupported.

---

## 4. Concrete Architectural Proposals & Implementation Specifications

### A. Keyless Sigstore Signing Workflow (GitHub Actions)

To resolve the HIGH severity feed attestation gap and MEDIUM severity SLSA gap, the `.github/workflows/release.yml` should be augmented to integrate the `sigstore-python` SDK and SLSA generators.

```yaml
name: Publish & Attest Release
on:
  push:
    tags:
      - 'v*'

jobs:
  build-publish-attest:
    runs-on: ubuntu-latest
    permissions:
      id-token: write  # Required for OIDC / Sigstore
      contents: write  # Required to attach signatures to GitHub Release
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4
      
      - name: Build Wheel
        run: python -m build
      
      - name: Publish to PyPI
        uses: pypa/gh-action-pypi-publish@release/v1
        
      - name: Keyless Sign with Sigstore
        run: |
          pip install sigstore
          # Sign the built wheel and daily data snapshot
          sigstore sign dist/*.whl
          sigstore sign docs/data/vulnerabilities.json.gz
          
      - name: Generate SLSA Provenance
        uses: slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v1.4.0
        with:
          base64-subjects: "${{ hashFiles('dist/*.whl') }}"
```

### B. OpenSSF Scorecard Metrics Schema Extension

To integrate OpenSSF Scorecards (HIGH gap), the `mcp_fingerprints.models.ServerPassport` Pydantic model must be extended to parse and store the scorecard API responses.

```python
from pydantic import BaseModel, Field
from typing import Optional, List

class OpenSSFScorecardMetric(BaseModel):
    name: str = Field(..., description="Name of the OpenSSF check (e.g., Branch-Protection)")
    score: float = Field(..., ge=0, le=10, description="Metric score out of 10")
    reason: str = Field(..., description="Explanation for the score")

class OpenSSFScorecardSummary(BaseModel):
    date: str = Field(..., description="Date of the OpenSSF scorecard run")
    overall_score: float = Field(..., ge=0, le=10, description="Aggregate repository score")
    metrics: List[OpenSSFScorecardMetric] = Field(default_factory=list)

class ServerPassport(BaseModel):
    # Existing Fields...
    name: str
    version: str
    upstream_url: str
    
    # Proposed OpenSSF Scorecard Extension
    openssf_scorecard: Optional[OpenSSFScorecardSummary] = Field(
        None, 
        description="Upstream maintenance health metrics pulled from the OpenSSF Scorecard API"
    )
```

Integrating this schema allows the auditing pipeline to flag MCP servers with an `overall_score < 5.0` as `MAINTENANCE_RISK_HIGH`.
