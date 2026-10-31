# Acceptance Test Coverage Gap Analysis

## 1. Acceptance Coverage Audit Matrix

| Subcommand / Subsystem | Documented Capability | Existing Acceptance Test | Gap Status | Action Required in Invariant Harness |
| :--- | :--- | :---: | :---: | :--- |
| **`audit`** | 17 AI client configuration scanning | `test_universal_9client_audit.py` | ⚠️ Partial | Upgrade to full 17-client end-to-end acceptance test |
| **`network-scan`** | Local & CIDR port probing | `test_network_scanner.py` (2 tests) | 🚨 Critical Gap | Author end-to-end mock socket network acceptance suite |
| **`identify`** | Canonical tool hash passport matching | `test_probe.py` | ⚠️ Partial | Validate unlabelled server identification against passports |
| **`probe-safe`** | Isolated sandboxing with canaries | `test_acceptance_sandbox.py` | ⚠️ Partial | Validate honeytoken exfiltration traps |
| **`proxy`** | Inline JSON-RPC reverse proxy | None | 🚨 Critical Gap | Author live stdio/SSE reverse proxy acceptance test |
| **`audit-transitive`** | Deep lockfile dependency scanning | `test_transitive.py` | ⚠️ Partial | Test all 8 lockfile formats in a unified acceptance run |
| **`audit-typosquat`** | Typosquat package detection | `test_typosquat_detector.py` | ⚠️ Partial | Validate detection and `--fix` config rewriting |
| **`verify-feed`** | Sigstore Cosign attestation | None | 🚨 Critical Gap | Author cryptographic signature & manifest acceptance test |
| **`hub`** | Interactive terminal GUI cockpit | None | 🚨 Critical Gap | Author non-interactive TTY fallback acceptance test |
| **`tui`** | Split-pane curses terminal explorer | None | 🚨 Critical Gap | Author headless curses screen simulation acceptance test |
| **`monitor`** | Scheduled daemon with drift alerts | None | 🚨 Critical Gap | Author daemon scheduling & desktop alert acceptance test |
| **`bridge`** | Localhost browser audit daemon | None | 🚨 Critical Gap | Author localhost CORS & token auth acceptance test |
