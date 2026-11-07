# Task 157B: Multi-Source Fusion and Collision Hardening Test Suite

## Objective
Author a comprehensive empirical and property-based test suite verifying that `AdvisoryFusionEngine`, `CanonicalAliasGraph`, and `deduplicate_references` handle multi-source ingestion deterministically, with zero data loss and robust alias loop resolution.

## Requirements
1. In `tests/test_fusion_multi_source.py`:
   - Test simultaneous ingestion of an advisory across 4 different sources (GHSA, NVD, GitLab, OSV) where each source contributes different subsets of data:
     - NVD contributes canonical CVE ID, official CVSS v3.1 vector and base score.
     - GHSA contributes detailed Markdown writeup, affected semver ranges, and alias links.
     - GitLab contributes additional reference URLs and CWE IDs.
     - OSV contributes package ecosystem metadata.
   - Verify the fused output contains:
     - Canonical ID = CVE ID.
     - All aliases preserved deterministically without duplication.
     - NVD CVSS score as authoritative severity.
     - GHSA markdown details preserved.
     - All reference URLs merged, normalized, and deduplicated.
     - Ranges merged with accurate version boundaries.
   - Test circular/nested alias chains:
     - Advisory A aliases B; Advisory B aliases C; Advisory C aliases A. Verify no infinite loops and deterministic cluster resolution.
   - Test conflicting severity levels:
     - Verify NVD base score overrides vendor estimates.
   - Test empty fields / missing attributes:
     - Ensure graceful fallback with no unhandled exceptions.
2. Run `pytest tests/test_fusion_multi_source.py` and verify all tests pass.
