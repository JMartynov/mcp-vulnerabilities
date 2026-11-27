import gzip
import io
import json
import os
import shutil
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from mcp_vulnerabilities.sync_manager import CrossRepoSyncManager


class MockGitHubApiHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/repos/jmartynov/mcp-fingerprints/releases/latest":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()

            response = {
                "assets": [
                    {
                        "name": "passports.json.gz",
                        "browser_download_url": (
                            f"http://{self.server.server_address[0]}:{self.server.server_address[1]}"
                            "/download/passports.json.gz"
                        ),
                    }
                ]
            }
            self.wfile.write(json.dumps(response).encode("utf-8"))

        elif self.path == "/download/passports.json.gz":
            self.send_response(200)
            self.send_header("Content-Type", "application/gzip")
            self.end_headers()

            # Generate a dummy passports file
            passports = {
                "pypi:dummy-server": {
                    "package_name": "dummy-server",
                    "purl": "pkg:pypi/dummy-server",
                    "ecosystem": "pypi",
                    "versions": [
                        {
                            "version": "1.0.0",
                            "toolset_canonical_hash": "0" * 64,
                            "tools": [],
                            "resources": [],
                            "prompts": [],
                        }
                    ],
                }
            }

            out = io.BytesIO()
            with gzip.GzipFile(fileobj=out, mode="w") as f:
                f.write(json.dumps(passports).encode("utf-8"))

            self.wfile.write(out.getvalue())

        elif self.path == "/rate-limit":
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"message": "API rate limit exceeded"}')
        else:
            self.send_response(404)
            self.end_headers()


class TestCrossRepoSync:
    @classmethod
    def setup_class(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockGitHubApiHandler)
        cls.server_thread = threading.Thread(target=cls.server.serve_forever)
        cls.server_thread.daemon = True
        cls.server_thread.start()
        cls.port = cls.server.server_address[1]

    @classmethod
    def teardown_class(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join(timeout=2)

    def setup_method(self, method):
        self.test_dir = Path("test_sync_dir")
        self.test_dir.mkdir(exist_ok=True)
        self.target_path = self.test_dir / "passports.json.gz"
        self.manager = CrossRepoSyncManager(target_path=self.target_path)
        self.manager.github_api_url = (
            f"http://127.0.0.1:{self.port}/repos/jmartynov/mcp-fingerprints/releases/latest"
        )

    def teardown_method(self, method):
        if self.test_dir.exists():
            shutil.rmtree(self.test_dir)

    def test_fetch_latest_passports_success(self):
        result = self.manager.fetch_latest_passports()
        assert result is True
        assert self.target_path.exists()

        # Verify content
        with gzip.open(self.target_path, "rt") as f:
            data = json.load(f)
            assert "pypi:dummy-server" in data

    def test_fetch_latest_passports_rate_limit(self):
        self.manager.github_api_url = f"http://127.0.0.1:{self.port}/rate-limit"
        result = self.manager.fetch_latest_passports()
        assert result is False
        assert not self.target_path.exists()

    def test_sync_and_correlate_and_site_build(self):
        # We need a dummy vulnerability database path
        vuln_dir = self.test_dir / "vulnerabilities"
        vuln_dir.mkdir(exist_ok=True)
        # Empty vulnerability db is enough to test correlation runs without crashing

        results = self.manager.sync_and_correlate(vuln_dir)
        assert results is not None
        assert len(results) == 1
        assert results[0].package_name == "dummy-server"

        # Site building verification
        from mcp_vulnerabilities.site_builder import build_site_data

        # This will test that site building executes successfully after correlation data is fetched
        # Create minimal OSV file to not fail the site build if it parses items
        osv_file = vuln_dir / "GHSA-1234.json"
        with open(osv_file, "w") as f:
            json.dump(
                {
                    "schema_version": "1.6.0",
                    "id": "GHSA-1234",
                    "summary": "Dummy",
                    "details": "Dummy details",
                    "modified": "2024-01-01T00:00:00Z",
                    "published": "2024-01-01T00:00:00Z",
                    "database_specific": {"mcp": {"vulnerable_tools": []}},
                    "affected": [],
                },
                f,
            )

        out_dir = self.test_dir / "docs_test" / "data"
        build_site_data(
            data_dir=str(vuln_dir),
            passports_path=str(self.target_path),
            output_dir=str(out_dir),
        )

        assert out_dir.exists()
        assert (out_dir / "mcp_catalog_index.json").exists()


def test_check_deltas_no_spurious_bump(tmp_path, monkeypatch):
    """AC-112.2: Identical passports.json.gz + vulnerabilities/ yields delta_detected=false."""
    repo_root = Path(__file__).resolve().parent.parent
    script_path = repo_root / "scripts" / "check_deltas.py"

    monkeypatch.chdir(tmp_path)
    data_dir = tmp_path / "data"
    old_vuln_dir = data_dir / "vulnerabilities_backup"
    new_vuln_dir = data_dir / "vulnerabilities"
    old_vuln_dir.mkdir(parents=True, exist_ok=True)
    new_vuln_dir.mkdir(parents=True, exist_ok=True)

    advisory = {
        "schema_version": "1.6.0",
        "id": "GHSA-0000-0000-0001",
        "summary": "Baseline advisory",
        "details": "Baseline advisory details",
        "modified": "2026-01-01T00:00:00Z",
        "published": "2026-01-01T00:00:00Z",
        "affected": [],
        "severity": [],
    }
    (old_vuln_dir / "GHSA-0000-0000-0001.json").write_text(json.dumps(advisory), encoding="utf-8")
    (new_vuln_dir / "GHSA-0000-0000-0001.json").write_text(json.dumps(advisory), encoding="utf-8")

    passports_payload = {
        "total_passports": 1,
        "passports": {
            "pypi:example-mcp": {
                "package_name": "example-mcp",
                "version": "1.0.0",
                "toolset_canonical_hash": "a" * 64,
            }
        },
    }
    for filename in ("passports.json.gz", "passports_backup.json.gz"):
        with gzip.open(data_dir / filename, "wt", encoding="utf-8") as fh:
            json.dump(passports_payload, fh)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root / "src")

    # Control: identical datasets must report delta_detected=false (zero spurious bump)
    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    assert "delta_detected=false" in result.stdout
    assert "delta_detected=true" not in result.stdout

    # Positive contrast: passport payload change must report delta_detected=true
    updated_passports = json.loads(json.dumps(passports_payload))
    updated_passports["passports"]["pypi:example-mcp"]["toolset_canonical_hash"] = "b" * 64
    with gzip.open(data_dir / "passports.json.gz", "wt", encoding="utf-8") as fh:
        json.dump(updated_passports, fh)

    changed_result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        env=env,
        check=True,
    )
    assert "delta_detected=true" in changed_result.stdout
