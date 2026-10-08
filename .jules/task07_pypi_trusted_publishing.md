### Task: PyPI Trusted Publishing Automation & v1.0.0 Release Workflow (release.yml)

#### 1. Architectural Context & Purpose:
The project is packaged via PEP 621 in `pyproject.toml` as `mcp-vulnerabilities` version `1.0.0`.
To publish the inaugural and subsequent releases securely to PyPI without managing long-lived API tokens or passwords, GitHub Actions supports **PyPI Trusted Publishing** via OpenID Connect (OIDC).

This requires:
1. An automated workflow `.github/workflows/release.yml` triggered on Git release tags (e.g. `v1.0.0` or `v*`).
2. OIDC permissions: `id-token: write` and `contents: read`.
3. Building distributions using Python's standard `build` tool (`sdist` and `wheel`).
4. Publishing distributions using official `pypa/gh-action-pypi-publish@release/v1`.
5. Clear instructions in `README.md` and `docs/` for configuring PyPI Pending Publishers and triggering the inaugural release.

#### 2. Codebase References:
* `pyproject.toml`: Build configuration (`[build-system]`, `[project]`).
* `.github/workflows/release.yml`: Target release workflow.
* `README.md`: Public release instructions.
* `docs/tasks/README.md`: Task roadmap index.

#### 3. Engineering & Implementation Blueprint:
1. Create `.github/workflows/release.yml`:
   ```yaml
   name: Publish Python Package to PyPI

   on:
     push:
       tags:
         - "v*.*.*"
     workflow_dispatch:

   jobs:
     pypi-publish:
       name: Build and publish Python 🐍 distribution 📦 to PyPI
       runs-on: ubuntu-latest
       environment:
         name: pypi
         url: https://pypi.org/p/mcp-vulnerabilities
       permissions:
         id-token: write # Required for PyPI OIDC Trusted Publishing
         contents: read
       steps:
         - name: Checkout repository
           uses: actions/checkout@v4

         - name: Set up Python
           uses: actions/setup-python@v5
           with:
             python-version: "3.12"
             cache: "pip"

         - name: Install build dependencies
           run: |
             python -m pip install --upgrade pip
             pip install build

         - name: Build binary wheel and source tarball
           run: python -m build

         - name: Publish distribution 📦 to PyPI
           uses: pypa/gh-action-pypi-publish@release/v1
           with:
             packages-dir: dist/
   ```
2. In `README.md`, add the section:
   ```markdown
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
   ```

#### 4. Guardrails & Security Invariants:
* **Zero Secrets Required**: PyPI Trusted Publishing uses ephemeral OIDC cryptographic tokens. Never store or request PyPI API tokens in GitHub Secrets.
* **Environment Protection**: The workflow must bind to the `pypi` environment to enforce approval rules if configured in repository settings.

#### 5. Acceptance Criteria:
- [ ] `.github/workflows/release.yml` is syntactically valid YAML and adheres to `pypa/gh-action-pypi-publish` v1 specification.
- [ ] PyPI Trusted Publisher parameters (Owner: `JMartynov`, Repository: `mcp-vulnerabilities`, Workflow name: `release.yml`, Environment: `pypi`) are explicitly documented in `README.md`.
- [ ] Local build test (`python -m build`) produces valid `sdist` (.tar.gz) and `wheel` (.whl) packages without warnings or errors.
- [ ] All existing test suites pass (`pytest -v`).
