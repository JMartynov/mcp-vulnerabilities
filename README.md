# Open-Source MCP Vulnerability Advisory Database

[![Daily MCP Vulnerability Ingestion & Sync](https://github.com/JMartynov/mcp-vulnerabilities/actions/workflows/daily_sync.yml/badge.svg)](https://github.com/JMartynov/mcp-vulnerabilities/actions/workflows/daily_sync.yml)
[![Advisories Count](https://img.shields.io/badge/advisories-500%2B-red.svg)](data/vulnerabilities)
[![OSV Schema 1.6.0](https://img.shields.io/badge/schema-OSV%201.6.0-blue.svg)](https://ossf.github.io/osv-schema/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An open-source, automated **Open Source Vulnerability (OSV 1.6)** compliant security advisory database specifically curated for the **Model Context Protocol (MCP)** ecosystem.

## Sources
- **CVE List v5**: Official CVE JSON 5.0 records.
- **GitHub Security Advisories (GHSA)**: Live GraphQL/REST security alerts.
- **OSV.dev**: Unified open-source vulnerability database.
- **National Vulnerability Database (NVD)**: CVE 2.0 vulnerability metrics and CVSS scores.

## Fast Consumption

You can fetch the complete vulnerability database snapshot in a single GET request:
```bash
curl -sL https://raw.githubusercontent.com/JMartynov/mcp-vulnerabilities/main/vulnerabilities.json.gz | gzip -d > vulnerabilities.json
```

### Python
```python
import gzip, json, urllib.request

url = "https://raw.githubusercontent.com/JMartynov/mcp-vulnerabilities/main/vulnerabilities.json.gz"
with urllib.request.urlopen(url) as resp:
    with gzip.GzipFile(fileobj=resp) as gz:
        data = json.load(gz)

print(f"Loaded {data['total_vulnerabilities']} MCP security advisories.")
```

## CI/CD Integration

You can easily prevent vulnerable MCP server dependencies from entering your production environment or being configured into AI client settings by adding this official, reusable GitHub Action to your CI workflows.

### Audit AI Client Configurations
```yaml
- name: Audit MCP Servers
  uses: JMartynov/mcp-vulnerabilities@v1
  with:
    config-path: ".claude/claude_desktop_config.json"
    fail-on-severity: "HIGH"
```

### Audit Dependency Manifests
```yaml
- name: Audit Transitive Dependencies
  uses: JMartynov/mcp-vulnerabilities@v1
  with:
    manifest-path: "package.json"
    fail-on-severity: "HIGH"
```

## CLI Usage
```bash
# Ingest latest advisories from live APIs
python -m mcp_vulnerabilities.cli sync --live-api

# Validate OSV schema compliance
python -m mcp_vulnerabilities.cli validate --dir data/vulnerabilities

# Compile compressed snapshot
python -m mcp_vulnerabilities.cli snapshot
```

## Documentation

- [Specification](docs/SPECIFICATION.md): Details the OSV 1.6 schema extensions, semantics, and vulnerability invariants.
- [Implementation](docs/IMPLEMENTATION.md): Architecture blueprint covering ingestion pipelines, state machines, and acceptance tests.

## Testing

Execute the acceptance test suite to validate the end-to-end functionality:

```bash
uv run pytest -v tests/test_acceptance_*.py
```

## Publishing to PyPI

### Final Optional Step: Tagging v1.0.0 for PyPI
When you're ready to publish the inaugural release to PyPI:
1. Ensure your [PyPI account](https://pypi.org/manage/account/publishing/) has a Pending Publisher configured:
   - **Owner**: `JMartynov`
   - **Repository**: `mcp-vulnerabilities`
   - **Workflow name**: `release.yml`
   - **Environment**: `pypi`
2. Create and push the release tag:
   ```bash
   git tag -a v1.0.0 -m "Release v1.0.0: Inaugural open-source MCP vulnerability database & CLI"
   git push origin v1.0.0
   ```

## License
MIT

