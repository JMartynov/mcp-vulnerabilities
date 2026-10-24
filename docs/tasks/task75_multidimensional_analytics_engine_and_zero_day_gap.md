# Task 75: Multi-Dimensional Analytics Engine & Zero-Day Gap Intelligence (P0)

## 1. Architectural Context & Technical Objective

Currently, `analytics.html` and `src/mcp_vulnerabilities/site_builder.py` calculate only 3 basic metrics derived solely from advisories:
1. Top 10 vulnerable tools
2. Unaggregated OWASP categories
3. Advisory ecosystem counts

This omits critical global security intelligence available across the 6,159 catalog servers, 5,820 passports, and 2,341 tools:
- **The Zero-Day Exposure Gap**: Out of 345 vulnerable servers, **only 60 (17.4%) have an available safe patch**, while **285 (82.6%) have NO KNOWN FIX**. This is an indispensable metric for security officers.
- **Static Capability Surface**: The proportion of servers with filesystem read/write, shell/code execution, and outbound network access.
- **Secrets Perimeter**: The most commonly requested environment variables (API keys/tokens) across the ecosystem.
- **Transport Distribution**: Percentage of local `stdio` servers vs. remote `sse` gateways.
- **Tool Shadowing Entropy**: Frequency of identically named tools with conflicting canonical hashes.

This task extends `src/mcp_vulnerabilities/site_builder.py` to calculate multi-dimensional analytics and overhauls `docs/analytics.html` with interactive charts and KPI widgets.

---

## 2. Target Files & Isolation Boundaries
- Scope: `src/mcp_vulnerabilities/site_builder.py`, `docs/data/analytics.json`, `docs/analytics.html`, `docs/style.css`
- Test Suite: `.venv/bin/pytest tests/test_site_builder.py tests/test_analytics.py`
- Deliverable: Comprehensive `analytics.json` schema and rich `analytics.html` dashboard visualizing the Zero-Day gap, capabilities, secrets, transport, and shadowing risk.

---

## 3. Detailed Acceptance Test Scenarios & Invariant Coverage

### Scenario 1: Zero-Day & Patch Gap Analytics Calculation
- **Preconditions**: Ingest catalog index and sharded servers in `site_builder.py`.
- **Invariants**:
  - [x] **INVARIANT_1A (Patch Availability Calculation)**: Compute exact counts and percentages for `patched_remediable_count` (17.4%) vs `zero_day_unpatched_count` (82.6%).
  - [x] **INVARIANT_1B (Patch Gap Visualizer)**: On `docs/analytics.html`, render a prominent Zero-Day / Remediation Gap card with clear guidance on mitigation (sandboxing vs updating).

### Scenario 2: Static Capability & Permission Surface Breakdown
- **Preconditions**: Iterate through all catalog servers and tool capabilities.
- **Invariants**:
  - [x] **INVARIANT_2A (Capability Aggregation)**: Calculate counts and percentages for:
    - Filesystem Read / Write access
    - Shell / Process execution (`exec`, `bash`, `cmd`)
    - Network / Outbound HTTP egress
    - Mutating vs Read-Only tool ratio
  - [x] **INVARIANT_2B (Capability Matrix Chart)**: On `docs/analytics.html`, render a visual capability distribution matrix.

### Scenario 3: Secrets Perimeter, Transports & Tool Shadowing
- **Preconditions**: Aggregate `required_env_vars`, `transport`, and tool names across all servers.
- **Invariants**:
  - [x] **INVARIANT_3A (Top Required Secrets)**: Rank top 10 required environment variables (`OPENAI_API_KEY`, `GITHUB_TOKEN`, etc.).
  - [x] **INVARIANT_3B (Transport Topology)**: Compute distribution of `stdio` vs `sse` vs `stream`.
  - [x] **INVARIANT_3C (Tool Shadowing Entropy)**: Identify top 10 most shadowed tool names across distinct packages (e.g. `read_file`, `execute_command`) and compute schema variance.
