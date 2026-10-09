"""Acceptance tests against real-life repositories, live feeds, and end-to-end caching."""

from __future__ import annotations

import json
import ssl
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from mcp_vulnerabilities.catalog import McpCatalogState
from mcp_vulnerabilities.converters.ghsa import GhsaConverter
from mcp_vulnerabilities.discovery.npm import NpmDiscoveryProvider
from mcp_vulnerabilities.discovery.pypi import PypiDiscoveryProvider
from mcp_vulnerabilities.pipeline import McpVulnerabilityPipeline
from mcp_vulnerabilities.validator import OsvValidator

DEFAULT_USER_AGENT = "McpVulnerabilitiesAcceptanceTest/1.0"


def _get_ssl_context() -> ssl.SSLContext:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    except Exception:
        return ssl._create_unverified_context()


def _fetch_json(url: str, headers: dict[str, str] | None = None, timeout: float = 10.0, data: bytes | None = None) -> Any:
    """Safely fetch and parse JSON from a remote URL."""
    hdrs = {"User-Agent": DEFAULT_USER_AGENT, "Accept": "application/json"}
    if headers:
        hdrs.update(headers)
    req = urllib.request.Request(url, data=data, headers=hdrs)
    with urllib.request.urlopen(req, timeout=timeout, context=_get_ssl_context()) as resp:
        return json.loads(resp.read().decode("utf-8"))


class TestAcceptanceRealRepositories(unittest.TestCase):
    """End-to-end acceptance tests validating real package registries and OSV conformance."""

    def test_real_npm_repository_discovery_and_osv_batch(self) -> None:
        """Verify real live npm packages can be discovered and queried in OSV batch."""
        npm_packages = NpmDiscoveryProvider.discover(queries=("@modelcontextprotocol/server-postgres",), limit_per_query=5)
        self.assertTrue(len(npm_packages) > 0, "Expected at least 1 real npm package from @modelcontextprotocol")

        target_pkg = npm_packages[0]
        self.assertIn("name", target_pkg)
        self.assertEqual(target_pkg["ecosystem"], "npm")
        self.assertTrue(bool(target_pkg["version"]))

        # Query OSV.dev batch API for this real package
        batch_url = "https://api.osv.dev/v1/querybatch"
        payload = json.dumps({"queries": [{"package": {"name": target_pkg["name"], "ecosystem": "npm"}}]}).encode("utf-8")
        try:
            data = _fetch_json(batch_url, data=payload, timeout=10.0)
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429):
                self.skipTest(f"OSV batch API rate limited ({exc.code})")
            raise
        except Exception as exc:
            self.skipTest(f"OSV batch API unavailable: {exc}")
        self.assertIn("results", data)
        self.assertEqual(len(data["results"]), 1)

    def test_real_pypi_repository_discovery(self) -> None:
        """Verify real live PyPI PEP 691 index discovery identifies canonical MCP servers."""
        try:
            pypi_packages = PypiDiscoveryProvider.discover(timeout=10.0)
        except Exception as exc:
            self.skipTest(f"PyPI discovery unavailable: {exc}")
        self.assertTrue(len(pypi_packages) > 100, f"Expected >100 PyPI packages, found {len(pypi_packages)}")

        pypi_names = {p["name"].lower() for p in pypi_packages}
        self.assertIn("fastmcp", pypi_names)
        self.assertTrue(any(n.startswith("mcp-server-") for n in pypi_names))

    def test_real_ghsa_live_advisory_conversion_and_validation(self) -> None:
        """Verify real GitHub Security Advisory converts into valid OSV 1.6.0 document."""
        url = "https://api.github.com/advisories?per_page=10&direction=desc&sort=updated"
        try:
            data = _fetch_json(url, timeout=10.0)
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429):
                self.skipTest(f"GitHub API rate limited ({exc.code})")
            raise
        except Exception as exc:
            self.skipTest(f"GitHub API unavailable: {exc}")
        self.assertIsInstance(data, list)
        self.assertTrue(len(data) > 0)

        sample_adv = data[0]
        osv_model = GhsaConverter.from_dict(sample_adv)
        self.assertTrue(bool(osv_model.id))
        self.assertTrue(bool(osv_model.summary))
        self.assertTrue(bool(osv_model.details))

        # Validate against OsvValidator
        val_errors = OsvValidator.validate(osv_model)
        self.assertEqual(val_errors, [], f"Validation errors on live GHSA {osv_model.id}: {val_errors}")

    def test_end_to_end_version_aware_caching_lifecycle(self) -> None:
        """Verify that McpVulnerabilityPipeline skips queries on warm cache with unchanged versions."""
        with tempfile.TemporaryDirectory() as tmpdir:
            out_dir = Path(tmpdir) / "vulns"
            state_file = Path(tmpdir) / "sync_state.json"
            catalog_state_file = Path(tmpdir) / "catalog_state.json"
            servers_file = Path(tmpdir) / "servers.json"

            # Pre-seed servers.json with 2 real packages
            servers_file.write_text(
                json.dumps({
                    "version": "1.0.0",
                    "servers": {
                        "npm:@modelcontextprotocol/server-postgres": {
                            "name": "@modelcontextprotocol/server-postgres",
                            "ecosystem": "npm",
                            "version": "0.6.2",
                        },
                        "pypi:fastmcp": {
                            "name": "fastmcp",
                            "ecosystem": "PyPI",
                            "version": "0.4.1",
                        },
                    },
                }),
                encoding="utf-8",
            )

            pipeline = McpVulnerabilityPipeline(
                output_dir=out_dir,
                state_file=state_file,
                catalog_state_file=catalog_state_file,
                servers_catalog_file=servers_file,
            )

            # --- RUN 1 (Cold Cache) ---
            pipeline.run(
                include_osv_api=True,
                include_ghsa_api=False,
                include_verity_catalog=False,
            )
            # Both packages audited and recorded in catalog_state
            cat_state1 = McpCatalogState(state_file=catalog_state_file)
            self.assertIn("npm:@modelcontextprotocol/server-postgres", cat_state1.records)
            self.assertIn("pypi:fastmcp", cat_state1.records)

            # --- RUN 2 (Warm Cache) ---
            # Unchanged versions -> should_query returns False -> 0 packages scanned in OSV batch
            pipeline_run2 = McpVulnerabilityPipeline(
                output_dir=out_dir,
                state_file=state_file,
                catalog_state_file=catalog_state_file,
                servers_catalog_file=servers_file,
            )
            pipeline_run2.run(
                include_osv_api=True,
                include_ghsa_api=False,
                include_verity_catalog=False,
            )
            # Sync state record for osv_dev should report 0 scanned on warm run
            osv_chk = pipeline_run2.state_manager.get_checkpoint("osv_dev")
            self.assertEqual(osv_chk.records_scanned, 0, "Warm run should have scanned 0 packages")


if __name__ == "__main__":
    unittest.main()
