# Task 96: Sigstore Cosign Keyless Attestation & Verifiable Feed Pipeline (P1)

**Blueprint Reference:** Strategic Roadmap Blueprint 3 ([`docs/audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md`](../audit/CUMULATIVE_COMPETITIVE_GAP_ANALYSIS_AND_ROADMAP.md))  
**Target Wave:** Wave 19 (Supply Chain Integrity, Attestation & Automated Remediation)  
**Priority:** `P1` (Core Supply Chain Integrity & Anti-Tampering Feature)

---

## 1. Architectural Context & Technical Objective

Downstream enterprise clients, CI/CD pipelines, and automated scanners rely on `docs/data/vulnerabilities.json.gz` and `docs/data/mcp_catalog_index.json` to enforce security policy. However, currently these catalogs are distributed via plain HTTPS without cryptographic provenance or anti-tamper attestations. A compromised hosting environment, CDN cache poisoning, or DNS hijack could allow attackers to suppress critical CVE alerts or inject benign scores for malicious tools.

This task implements **Keyless Cryptographic Attestation** across the release pipeline and adds local/CLI verification tooling:
1. **GitHub Actions Keyless Signing Workflow (`sigstore`)**:
   - Uses GitHub OIDC token identity (`actions/id-token`) to sign `dist/*.whl`, `dist/*.tar.gz`, `docs/data/vulnerabilities.json.gz`, and `docs/data/mcp_catalog_index.json`.
   - Records cryptographic transparency proofs into the public Sigstore Rekor transparency log without requiring long-lived private keys.
   - Emits `.sigstore.json` (Sigstore bundle) containing the certificate chain and Rekor inclusion proof alongside the artifacts.
2. **Deterministic Catalog Hashes & Manifest (`manifest.json`)**:
   - Generates a canonical `docs/data/manifest.json` containing SHA-256 digests, byte counts, and RFC 3339 generation timestamps for all catalog files (`vulnerabilities.json.gz`, `mcp_catalog_index.json`, `analytics.json`).
3. **Local & CLI Verification Engine (`mcp-vuln verify-feed`)**:
   - Adds subcommand `mcp-vuln verify-feed --feed <path-or-url> [--bundle <bundle-path>] [--expected-issuer <issuer>] [--expected-identity <identity>]`.
   - Verifies the SHA-256 checksum against `manifest.json`.
   - Verifies the Sigstore signature bundle against Rekor and OIDC identity claims (defaulting to repository identity `https://github.com/JMartynov/mcp-vulnerabilities/...` and issuer `https://token.actions.githubusercontent.com`).
   - Returns structured exit codes (`0` on valid signature and untampered digest, `1` on hash mismatch, `2` on signature verification failure, `3` on network/IO error).

---

## 2. Target Files & Isolation Boundaries

- **New Package Files:**
  - `src/mcp_vulnerabilities/attestation/__init__.py`
  - `src/mcp_vulnerabilities/attestation/manifest.py` (canonical hash calculation & manifest generation)
  - `src/mcp_vulnerabilities/attestation/verifier.py` (Sigstore bundle validation & Rekor verification)
- **CLI Integration:**
  - `src/mcp_vulnerabilities/cli.py` (register `verify-feed` subcommand)
- **CI/CD Workflow Enhancement:**
  - `.github/workflows/sign_release.yml` or extension in `release.yml`
- **Test Suite:**
  - `tests/test_attestation_verifier.py`

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Manifest Generation & Deterministic Checksums (`INVARIANT_96_1A` – `INVARIANT_96_1C`)
- **Preconditions**: Execute `generate_catalog_manifest(data_dir)`.
- **Invariants**:
  - [ ] **INVARIANT_96_1A (Canonical Hash Precision)**: `manifest.json` contains exact SHA-256 digests and byte counts for all static catalog targets (`vulnerabilities.json.gz`, `mcp_catalog_index.json`, `analytics.json`).
  - [ ] **INVARIANT_96_1B (Reproducible Key Ordering)**: Output JSON is deterministically sorted by file path with standard 2-space indentation.
  - [ ] **INVARIANT_96_1C (Tamper Detection)**: Modifying a single byte of any catalog target causes `verify_catalog_manifest()` to fail with a clear `ChecksumMismatchError`.

### Scenario 2: Keyless Bundle Verification & OIDC Policy Checks (`INVARIANT_96_2A` – `INVARIANT_96_2C`)
- **Preconditions**: Provide a mock or fixture Sigstore bundle with valid signature, certificate chain, and Rekor inclusion proof.
- **Invariants**:
  - [ ] **INVARIANT_96_2A (Signature Authenticity)**: Verifier confirms ECDSA P-256 signature validity against artifact content.
  - [ ] **INVARIANT_96_2B (OIDC SAN Identity Constraint)**: Rejects bundles whose certificate SAN URI does not match expected GitHub workflow repository identity (`JMartynov/mcp-vulnerabilities`).
  - [ ] **INVARIANT_96_2C (Offline & Graceful Fallback)**: When `--offline` flag is passed, skips network Rekor calls if bundle already embeds an RFC 3161 or Rekor inclusion proof; emits actionable error if verification cannot proceed offline.

### Scenario 3: CLI `mcp-vuln verify-feed` Contract (`INVARIANT_96_3A` – `INVARIANT_96_3B`)
- **Preconditions**: Run `mcp-vuln verify-feed` via CLI invocation.
- **Invariants**:
  - [ ] **INVARIANT_96_3A (Clean Exit Code on Valid Target)**: Exits with code `0` and prints human-readable verification receipt including signing timestamp and certificate identity.
  - [ ] **INVARIANT_96_3B (JSON Output Flag)**: When `--json` is supplied, outputs structured telemetry: `{"verified": true, "artifact": "...", "sha256": "...", "signer": "...", "issuer": "...", "timestamp": "..."}`.

---

## 4. Concrete Implementation Instructions

1. Implement `src/mcp_vulnerabilities/attestation/manifest.py` to inspect target directories, hash files, and generate `manifest.json`.
2. Implement `src/mcp_vulnerabilities/attestation/verifier.py` wrapping standard verification logic (compatible with `sigstore` Python library or fallback crypto parser).
3. Connect `verify-feed` command in `src/mcp_vulnerabilities/cli.py` with arguments:
   `--feed`, `--manifest`, `--bundle`, `--expected-identity`, `--expected-issuer`, `--offline`, `--json`.
4. Add comprehensive test cases in `tests/test_attestation_verifier.py` testing clean passes, tampered payloads, and invalid identity certificates.
5. Verify `.venv/bin/pytest tests/test_attestation_verifier.py` passes cleanly.

---

## 5. Non-Interactive Completion Directive

Implement all modules, CLI hooks, tests, and documentation directly. Run the test suite and verify 100% pass rate before committing.
