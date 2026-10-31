# Task 114: CLI Flags & Subcommands Integration (P1)

**Subsystem:** Headless Automation CLI (`src/mcp_vulnerabilities/cli.py`, `tests/test_cli_flags.py`)  
**Priority:** `P1`  
**Parent Plan:** [master_plan_wave21_network_inspection_security_picture_and_cli_hub.md](master_plan_wave21_network_inspection_security_picture_and_cli_hub.md)

---

## 1. Objective & Problem Statement

While interactive users benefit from the Terminal GUI Hub (Task 113), enterprise DevSecOps pipelines and automated CI/CD runners (such as GitHub Actions, GitLab CI, and Jenkins) require fully scriptable, headless CLI subcommands and flags.

Automated pipelines must be able to:
1. Scan local or remote network targets for unauthorized MCP listeners without user interaction.
2. Capture and persist authoritative security baselines (`--save-picture <path>`).
3. Compare current repository and workstation configurations against a checked-in baseline (`--compare-picture <path>`).
4. Enforce strict build failure policies (`--fail-on-drift`, `--fail-on-tamper`) returning standardized exit codes (`0`, `1`, `2`, `3`).
5. Include network-discovered endpoints alongside local client configurations in a single unified audit command (`mcp-vuln audit --network`).

This task integrates these options into `src/mcp_vulnerabilities/cli.py`, establishing a standardized non-interactive contract for pipeline orchestration.

---

## 2. Detailed Technical Requirements

### 2.1 Subcommand: `mcp-vuln network-scan` (`src/mcp_vulnerabilities/cli.py`)

Register the `network-scan` subcommand:
```python
net_p = subparsers.add_parser(
    "network-scan",
    help="Probe local or remote hosts/subnets for active MCP HTTP/SSE endpoints",
)
net_p.add_argument(
    "--target",
    default="localhost",
    help="Target hostname, IP address, or comma-separated list of targets (default: localhost)",
)
net_p.add_argument(
    "--ports",
    default="3000,3001,3333,4000,5000,5001,8000,8001,8080,8765,8800,9000",
    help="Comma-separated list of ports or port ranges (e.g. 3000-3010)",
)
net_p.add_argument(
    "--cidr",
    metavar="CIDR",
    help="CIDR block to scan (e.g. 192.168.1.0/24)",
)
net_p.add_argument(
    "--timeout",
    type=int,
    default=200,
    help="Socket connection timeout in milliseconds (default: 200)",
)
net_p.add_argument(
    "--concurrency",
    type=int,
    default=64,
    help="Maximum concurrent connection probes (default: 64)",
)
net_p.add_argument(
    "--save-picture",
    metavar="PATH",
    help="Save network scan results directly to a SecurityPicture JSON file",
)
net_p.add_argument(
    "--format",
    choices=["table", "json", "sarif"],
    default="table",
    help="Output formatting style (default: table)",
)
```

### 2.2 Upgrades to `mcp-vuln audit`

Extend the existing `audit` subparser (`aud_p`):
1. `--network`:
   - Flags audit to automatically trigger network scanner alongside local client scans.
2. `--network-ports`:
   - Configures ports probed when `--network` is supplied.
3. `--save-picture <path>`:
   - Captures all local and (optionally) network servers into a `SecurityPicture` JSON file at `<path>`.
4. `--compare-picture <path>`:
   - Compares the live scan against the baseline `SecurityPicture` located at `<path>` using `SecurityPictureDiffer`.
5. `--fail-on-drift`:
   - Causes the CLI process to exit with code `2` if security posture drift is detected.
6. `--fail-on-tamper`:
   - Causes the CLI process to exit with code `3` if any tool signature tampering is detected.

### 2.3 Standardized Exit Code Matrix

The CLI adheres to the following exit code contract across all commands:
- `0`: Scan/Audit succeeded; zero vulnerabilities, zero drift, and zero tampering detected.
- `1`: Vulnerabilities identified (when `--fail-on-vuln` or `--strict` is enabled) OR general runtime error.
- `2`: Security drift detected (when `--fail-on-drift` is enabled and `is_clean == False`).
- `3`: Supply chain tampering detected (when `--fail-on-tamper` or `--strict-integrity` is enabled).

---

## 3. Invariant Requirements & Verification Plan

### Acceptance Scenarios & Invariant Gates
- [ ] **INVARIANT_114_1 (CLI Parser Consistency):** Running `mcp-vuln network-scan --help` and `mcp-vuln audit --help` outputs all new flags with accurate descriptions.
- [ ] **INVARIANT_114_2 (Headless JSON Telemetry):** `mcp-vuln network-scan --target localhost --format json` emits valid JSON conforming to the `NetworkScanResult` schema.
- [ ] **INVARIANT_114_3 (Picture Capture Pipeline):** Executing `mcp-vuln audit --save-picture test_picture.json` writes a valid `SecurityPicture` and exits with code `0`.
- [ ] **INVARIANT_114_4 (Drift Gate Exit Code 2):** When a modified mock configuration is evaluated against a baseline using `mcp-vuln audit --compare-picture baseline.json --fail-on-drift`, the process exits with code `2`.
- [ ] **INVARIANT_114_5 (Tamper Gate Exit Code 3):** When tool parameter tampering is detected under `--fail-on-tamper`, the process exits with code `3`.
- [ ] **INVARIANT_114_6 (Automated Test Suite):** `tests/test_cli_flags.py` tests argument parsing, subcommand routing, mock network scan execution, and exit code propagation.

---

## 4. Deliverables

1. `src/mcp_vulnerabilities/cli.py`: Integrated `network-scan` subcommand and `--save-picture`, `--compare-picture`, `--fail-on-drift`, and `--network` flags in `audit`.
2. `tests/test_cli_flags.py`: Test suite validating CLI parsing, option execution, and exit code contracts.
