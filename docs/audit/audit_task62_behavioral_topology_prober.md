# Empirical Audit — Dynamic Behavioral Topology Server Prober & Transports

## 1. Executive Summary

This report presents the findings of the empirical audit conducted on the `mcp-vulnerabilities` dynamic behavioral topology prober subsystem, encompassing `probe/client.py`, `probe/transport.py`, `probe/fingerprinter.py`, and `fingerprints/matcher.py`. 

The audit focused on the prober's resilience against malformed inputs and connection disruptions, as well as its accuracy in matching tool sets and evaluating behavioral topology. We addressed several structural vulnerabilities that previously caused process stalling or application crashing in real-world scenarios.

## 2. Invariant Evaluations and Findings

### Scenario 1: Subprocess STDIO Transport Noise Filtering Invariant
- **Finding Severity: HIGH**
- **Issue**: The initial `StdioTransport` design blocked indefinitely or immediately raised a `JSONDecodeError` when the child process output non-JSON debugging logs to `stdout` before providing a valid JSON-RPC 2.0 initialization response. In the wild, many servers print arbitrary initialization messages, crashing the prober.
- **Resolution**: `StdioTransport.receive()` was re-engineered. The `read_line` thread now sequentially pulls lines, actively drops non-JSON noise, and parses until a valid JSON response is found or EOF is hit. Invalid lines are queued into a local debugger stream buffer for observability.
- **Invariant 1A (Noise Immunity)**: ✅ Passed
- **Invariant 1B (Timeout & Process Teardown)**: ✅ Passed

### Scenario 2: Network SSE Transport Resilience Invariant
- **Finding Severity: MEDIUM**
- **Issue**: The Server-Sent Events (SSE) network transport connection drop scenarios were under-tested. Abrupt socket closure could potentially leave dangling threads.
- **Resolution**: Verifications within `test_scenario2_sse_network_failures` confirm that the custom `HttpSseTransport` correctly intercepts network timeouts and `urllib.error.HTTPError`, accurately propagates the typed `TransportError`, and reliably joins background listener threads.
- **Invariant 2A (Clean Disconnect Handling)**: ✅ Passed
- **Invariant 2B (Explicit Transport Errors)**: ✅ Passed

### Scenario 3: Topological Similarity & Version Distance Invariant
- **Finding Severity: LOW**
- **Issue**: The original fingerprint matcher required identical dictionaries and strictly failed to load some formats (specifically newer `mcp-fingerprints>=1.0.17` `ServerPackageSpec` objects when validating through `from_dict` instead of modern `pydantic` or `dacite`).
- **Resolution**: Refactored `FingerprintMatcher.load_data()` with robust backwards-compatible type checking (attempting `model_validate`, falling back to `from_dict`, and finally to `dacite.from_dict`). Verified that matching partial topological signatures succeeds natively with partial confidence scores. Added Invariant 3B test to confirm `VulnerabilityCorrelator` maps exact toolset hashes to specific advisory version timelines correctly.
- **Invariant 3A (Topological Match Precision)**: ✅ Passed
- **Invariant 3B (Vulnerability Correlation Stamping)**: ✅ Passed

## 3. Recommended Next Actions
- Monitor `StdioTransport` background threads in multi-server environments (e.g., when probing >100 server subsets concurrently) to ensure memory consumption stays balanced across instances.
- Deploy testing patches across continuous integration pipeline `audit` jobs.
