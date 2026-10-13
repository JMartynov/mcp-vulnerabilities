import gzip
import json
import os
import shutil
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from urllib.error import URLError

from mcp_vulnerabilities.api.server import McpSecurityApiServer


class TestLiveApiServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp_dir = tempfile.mkdtemp()
        cls.data_dir = os.path.join(cls.temp_dir, "data")
        os.makedirs(cls.data_dir)
        
        # mock vulnerabilities
        cls.snapshot_path = os.path.join(cls.temp_dir, "vulnerabilities.json.gz")
        vulns = [
            {
                "id": "CVE-2023-1234",
                "schema_version": "1.6.0",
                "modified": "2023-01-01T00:00:00Z",
                "database_specific": {
                    "mcp_security_extensions": [{"vulnerable_tools": ["read_file"]}]
                }
            }
        ]
        with gzip.open(cls.snapshot_path, "wt", encoding="utf-8") as f:
            json.dump(vulns, f)
            
        # mock passports
        cls.passports_path = os.path.join(cls.temp_dir, "passports.json.gz")
        passports = {
            "passports": [
                {
                    "purl": "pkg:npm/@test/my-server@1.0.0",
                    "package_name": "@test/my-server",
                    "ecosystem": "npm",
                    "repository_url": "https://github.com/test/my-server",
                    "versions": [
                        {
                            "version": "1.0.0",
                            "toolset_canonical_hash": "testhash",
                            "tool_signatures": [
                                {
                                    "name": "my_tool_1",
                                    "description": "desc 1",
                                    "input_schema": {},
                                    "canonical_hash": "hash1"
                                },
                                {
                                    "name": "my_tool_2",
                                    "description": "desc 2",
                                    "input_schema": {},
                                    "canonical_hash": "hash2"
                                }
                            ]
                        }
                    ]
                }
            ]
        }
        with gzip.open(cls.passports_path, "wt", encoding="utf-8") as f:
            json.dump(passports, f)
            
        cls.server = McpSecurityApiServer(
            host="127.0.0.1",
            port=0, # dynamic free port
            data_dir=cls.data_dir,
            snapshot_path=cls.snapshot_path,
            passports_path=cls.passports_path
        )
        cls.server.start()
        # wait a bit for server to start
        time.sleep(1)
        cls.port = cls.server.server.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        if cls.server:
            cls.server.stop()
        shutil.rmtree(cls.temp_dir)

    def test_live_server_lifecycle_and_health(self):
        req = urllib.request.Request(f"{self.base_url}/health")
        try:
            with urllib.request.urlopen(req) as res:
                self.assertEqual(res.status, 200)
                data = json.loads(res.read().decode())
                self.assertEqual(data["status"], "ok")
                self.assertEqual(data["vulnerabilities_indexed"], 1)
                self.assertEqual(data["passports_loaded"], 1)
                self.assertGreaterEqual(data["uptime_seconds"], 0)
        except URLError as e:
            self.fail(f"Failed to connect: {e}")

    def test_live_api_identify_endpoint(self):
        payload = json.dumps({"tools": [{"name": "my_tool_1"}, {"name": "my_tool_2"}]}).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}/api/v1/identify", data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req) as res:
                self.assertEqual(res.status, 200)
                data = json.loads(res.read().decode())
                self.assertEqual(data["package"], "pkg:npm/@test/my-server@1.0.0")
                self.assertGreaterEqual(data["confidence"], 0.95)
        except URLError as e:
            self.fail(f"Failed to connect: {e}")

    def test_live_api_scan_config_with_collisions(self):
        config = {
            "mcpServers": {
                "server1": {"command": "cmd1", "args": ["a1"]},
                "server2": {"command": "cmd2", "args": ["a2"]}
            }
        }
        payload = json.dumps({"config": config, "detect_collisions": True}).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}/api/v1/scan/config", data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req) as res:
                self.assertEqual(res.status, 200)
                data = json.loads(res.read().decode())
                self.assertIn("vulnerabilities", data)
                self.assertIn("collisions", data)
        except URLError as e:
            self.fail(f"Failed to connect: {e}")

    def test_live_api_vulnerabilities_query(self):
        req = urllib.request.Request(f"{self.base_url}/api/v1/vulnerabilities?tool=read_file&limit=5")
        try:
            with urllib.request.urlopen(req) as res:
                self.assertEqual(res.status, 200)
                data = json.loads(res.read().decode())
                self.assertEqual(data["total"], 1)
                self.assertEqual(data["items"][0]["id"], "CVE-2023-1234")
        except URLError as e:
            self.fail(f"Failed to connect: {e}")

    def test_live_api_command_execution_forbidden(self):
        # Verify that unauthenticated command execution over HTTP is forbidden (403)
        payload = json.dumps({"command": "echo vulnerable"}).encode("utf-8")
        req = urllib.request.Request(f"{self.base_url}/api/v1/scan/probe", data=payload, method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req) as res:
                self.fail("Expected HTTP 403 Forbidden")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)
            data = json.loads(e.read().decode())
            self.assertEqual(data["error"]["code"], "FORBIDDEN")

        # Also verify identify with command is forbidden (403)
        req_id = urllib.request.Request(f"{self.base_url}/api/v1/identify", data=payload, method="POST")
        req_id.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req_id) as res:
                self.fail("Expected HTTP 403 Forbidden")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 403)
            data = json.loads(e.read().decode())
            self.assertEqual(data["error"]["code"], "FORBIDDEN")

    def test_live_api_command_probe_test(self):
        import sys
        import tempfile
        import os

        # Temporarily allow remote commands on the test server
        self.server.allow_remote_commands = True
        try:
            script = """import sys, json
for line in sys.stdin:
    try:
        msg = json.loads(line)
        if msg.get('method') == 'initialize':
            sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': {'serverInfo': {'name': 'test', 'version': '1.0'}, 'capabilities': {}}}) + '\\n')
            sys.stdout.flush()
        elif msg.get('method') == 'tools/list':
            sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': {'tools': []}}) + '\\n')
            sys.stdout.flush()
        elif msg.get('method') == 'prompts/list':
            sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': {'prompts': []}}) + '\\n')
            sys.stdout.flush()
        elif msg.get('method') == 'resources/list':
            sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': {'resources': []}}) + '\\n')
            sys.stdout.flush()
    except Exception:
        pass"""
            
            fd, path = tempfile.mkstemp(suffix=".py")
            with os.fdopen(fd, 'w') as f:
                f.write(script)
                
            payload = json.dumps({"command": [sys.executable, path]}).encode("utf-8")
            req = urllib.request.Request(f"{self.base_url}/api/v1/scan/probe", data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            try:
                with urllib.request.urlopen(req) as res:
                    self.assertEqual(res.status, 200)
                    data = json.loads(res.read().decode())
                    self.assertIn("fingerprint", data)
                    self.assertIn("identity", data)
                    self.assertIn("vulnerabilities", data)
            except URLError as e:
                self.fail(f"Failed to connect: {e}")
            finally:
                try:
                    os.unlink(path)
                except Exception:
                    pass
        finally:
            self.server.allow_remote_commands = False

if __name__ == "__main__":
    unittest.main()
