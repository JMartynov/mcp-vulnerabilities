# Task 162: High-Speed BK-Tree Typosquat Indexing and Real-Time WebSocket Bridge

## Status: IN PROGRESS
**Priority:** P2  
**Components:** Typosquat Detector, Distance Metrics, WebSocket Bridge Daemon  
**Target Files:**
- `src/mcp_vulnerabilities/analyzers/typosquat/detector.py`
- `src/mcp_vulnerabilities/daemon/bridge.py`
- `tests/test_bktree_typosquat.py`
- `tests/test_bridge_stream.py`

---

## 1. Objectives & Scope

1. **BK-Tree Distance Indexing:**
   - Replace linear $O(N)$ Damerau-Levenshtein iteration across 6,258 catalog servers with a Burkhard-Keller tree (`BKTree`) data structure in `detector.py`.
   - Achieve sub-50ms fuzzy matching queries for typosquatting and hallucination audits.
2. **Real-Time WebSocket Protocol Bridge Simulator:**
   - Enhance `src/mcp_vulnerabilities/daemon/bridge.py` to support real-time WebSocket events (`scan_started`, `server_discovered`, `vulnerability_detected`).
   - Add unit tests in `tests/test_bridge_stream.py`.

---

## 2. Acceptance Criteria

- [ ] `BKTree` implementation satisfies discrete metric space axioms (non-negativity, identity, symmetry, triangle inequality).
- [ ] Typosquat detector achieves >10x speedup over linear scans on large server lists.
- [ ] WebSocket bridge simulator streams structured JSON-RPC events cleanly.
- [ ] `tests/test_bktree_typosquat.py` and `tests/test_bridge_stream.py` pass 100%.
