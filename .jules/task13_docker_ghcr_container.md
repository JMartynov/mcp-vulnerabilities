### Task: Official Lightweight Docker Image & GHCR Publishing Workflow

#### 1. Architectural Context & Purpose:
Many CI/CD pipelines, security scanners, and Kubernetes cronjobs prefer running security tools inside container images rather than installing local Python dependencies.
Creating an official multi-arch Docker image (`ghcr.io/jmartynov/mcp-vulnerabilities`) packaged with the CLI and local snapshot allows one-line auditing anywhere:
```bash
docker run --rm -v $(pwd):/app ghcr.io/jmartynov/mcp-vulnerabilities audit --config /app/claude_desktop_config.json
```

#### 2. Codebase References:
* `pyproject.toml`: CLI package definition.
* `Dockerfile`: Container specification to be created.
* `.github/workflows/docker.yml`: Automated GHCR publishing workflow.

#### 3. Implementation Details:
1. Create `Dockerfile`:
   - Multi-stage build based on `python:3.12-slim`.
   - Install `mcp-vulnerabilities` package and pre-copy `data/vulnerabilities` and `vulnerabilities.json.gz`.
   - Set entrypoint to `mcp-vuln` (or `python -m mcp_vulnerabilities.cli`).
   - Run as non-root user (`appuser:10001`).
2. Create `.github/workflows/docker.yml`:
   - Triggers on release tags (`v*.*.*`) or manual dispatch.
   - Uses `docker/setup-buildx-action` and `docker/build-push-action`.
   - Publishes to GitHub Container Registry (`ghcr.io/jmartynov/mcp-vulnerabilities`).

#### 4. Acceptance Criteria:
- [ ] `Dockerfile` builds a working container under 150 MB.
- [ ] Running `docker run --rm mcp-vulnerabilities --help` displays CLI commands and exits with code 0.
- [ ] Automated `.github/workflows/docker.yml` passes YAML syntax validation.
