import json
import logging
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from mcp_vulnerabilities.pipeline import McpVulnerabilityPipeline

logger = logging.getLogger(__name__)

class TestAcceptanceIndexPreservation(unittest.TestCase):
    def test_incremental_sync_preserves_full_historical_index(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "output"
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Create 50 historical entries
            index_entries = []
            for i in range(50):
                vuln_id = f"OSV-2024-{i:04d}"
                record = {
                    "schema_version": "1.6.0",
                    "id": vuln_id,
                    "modified": "2024-01-01T00:00:00Z",
                    "published": "2024-01-01T00:00:00Z",
                    "summary": f"Historical Vulnerability {i}",
                    "details": "Details here.",
                    "affected": [
                        {
                            "package": {"ecosystem": "npm", "name": "foo"},
                            "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}],
                        }
                    ]
                }
                record_file = output_dir / f"{vuln_id}.json"
                record_file.write_text(json.dumps(record), encoding="utf-8")
                
                index_entries.append({
                    "id": vuln_id,
                    "summary": f"Historical Vulnerability {i}",
                    "aliases": [],
                    "modified": "2024-01-01T00:00:00Z",
                    "packages": [{"name": "foo", "ecosystem": "npm", "purl": None, "severity": None, "cvss_score": None}],
                })
            
            index_file = output_dir / "index.json"
            index_file.write_text(json.dumps({
                "version": "1.0.0",
                "count": 50,
                "vulnerabilities": index_entries
            }), encoding="utf-8")
            
            state_file = Path(tmpdir) / "sync_state.json"
            catalog_file = Path(tmpdir) / "mcp_catalog_state.json"
            servers_file = Path(tmpdir) / "mcp_servers.json"
            
            pipeline = McpVulnerabilityPipeline(
                output_dir=output_dir,
                state_file=state_file,
                catalog_state_file=catalog_file,
                servers_catalog_file=servers_file
            )
            
            # Setup an incremental feed via markdown that emits 1 new advisory
            md_dir = Path(tmpdir) / "md"
            md_dir.mkdir(parents=True, exist_ok=True)
            
            new_id = "OSV-2024-9999"
            md_content = f"""# {new_id}

## Summary
A new vulnerability

## Affected
- npm foo

## Details
New details here.
"""
            md_file = md_dir / f"{new_id}.md"
            md_file.write_text(md_content, encoding="utf-8")
            
            pipeline.run(
                include_markdown_dirs=[md_dir],
                include_cvelistv5_dirs=[],
                include_cvelist_delta=False,
                include_ghsa_api=False,
                include_osv_api=False,
                include_verity_catalog=False,
                reset_checkpoints=False
            )
            
            self.assertTrue((output_dir / f"{new_id}.json").exists())
            for i in range(50):
                self.assertTrue((output_dir / f"OSV-2024-{i:04d}.json").exists())
            
            updated_index = json.loads(index_file.read_text(encoding="utf-8"))
            self.assertEqual(updated_index["count"], 51)
            self.assertEqual(len(updated_index["vulnerabilities"]), 51)

    def test_amended_historical_cve_reprocessed_via_mtime(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "output"
            output_dir.mkdir(parents=True, exist_ok=True)
            
            state_file = Path(tmpdir) / "sync_state.json"
            catalog_file = Path(tmpdir) / "mcp_catalog_state.json"
            servers_file = Path(tmpdir) / "mcp_servers.json"
            
            pipeline = McpVulnerabilityPipeline(
                output_dir=output_dir,
                state_file=state_file,
                catalog_state_file=catalog_file,
                servers_catalog_file=servers_file
            )
            
            cve_dir = Path(tmpdir) / "cve"
            cve_dir.mkdir(parents=True, exist_ok=True)
            
            cve_id = "CVE-2024-1234"
            cve_content = {
                "dataType": "CVE_RECORD",
                "dataVersion": "5.0",
                "cveMetadata": {
                    "cveId": cve_id,
                    "assignerOrgId": "foo",
                    "state": "PUBLISHED"
                },
                "containers": {
                    "cna": {
                        "affected": [{"product": "mcp-server-github", "versions": [{"status": "affected", "version": "1.0"}]}],
                        "descriptions": [{"lang": "en", "value": "Initial"}]
                    }
                }
            }
            cve_file = cve_dir / f"{cve_id}.json"
            cve_file.write_text(json.dumps(cve_content), encoding="utf-8")
            
            import os
            import time

            # To test deduplication, we actually don't need to fake the output file.
            # We can run the pipeline twice and just modify the CVE in between.
            result = pipeline.run(
                include_cvelistv5_dirs=[cve_dir],
                include_markdown_dirs=[],
                include_cvelist_delta=False,
                include_ghsa_api=False,
                include_osv_api=False,
                include_verity_catalog=False,
                reset_checkpoints=False
            )
            self.assertEqual(result.emitted_count, 1)

            # First scan with the CVE modified *after* the scan
            # Modify the CVE file and update mtime
            cve_content["containers"]["cna"]["descriptions"][0]["value"] = "Updated description that is longer."
            cve_content["cveMetadata"]["dateUpdated"] = "2025-01-01T00:00:00.000Z" # Needed for deduplication to pick the newer one
            cve_file.write_text(json.dumps(cve_content), encoding="utf-8")
            
            time.sleep(1) # Wait so mtime > last_scan_utc
            current_time = time.time()
            os.utime(cve_file, (current_time, current_time))
            
            # Second scan should re-evaluate because of mtime > last_scan_utc
            result2 = pipeline.run(
                include_cvelistv5_dirs=[cve_dir],
                include_markdown_dirs=[],
                include_cvelist_delta=False,
                include_ghsa_api=False,
                include_osv_api=False,
                include_verity_catalog=False,
                reset_checkpoints=False
            )
            
            self.assertEqual(result2.emitted_count, 1)
            
            # Check the output JSON to see if the update propagated
            output_cve_file = output_dir / f"{cve_id}.json"
            self.assertTrue(output_cve_file.exists())
            output_data = json.loads(output_cve_file.read_text(encoding="utf-8"))
            self.assertIn("Updated description that is longer.", output_data["details"])

    def test_atomic_index_write_on_failure(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            output_dir = Path(tmpdir) / "output"
            output_dir.mkdir(parents=True, exist_ok=True)
            
            index_file = output_dir / "index.json"
            index_file.write_text(json.dumps({
                "version": "1.0.0",
                "count": 1,
                "vulnerabilities": [{"id": "OSV-1"}]
            }), encoding="utf-8")
            
            state_file = Path(tmpdir) / "sync_state.json"
            catalog_file = Path(tmpdir) / "mcp_catalog_state.json"
            servers_file = Path(tmpdir) / "mcp_servers.json"
            
            pipeline = McpVulnerabilityPipeline(
                output_dir=output_dir,
                state_file=state_file,
                catalog_state_file=catalog_file,
                servers_catalog_file=servers_file
            )
            
            # Mock `replace` on `Path` to raise an exception simulating failure during atomicity
            with patch.object(Path, 'replace', side_effect=Exception("Simulated crash during replace")):
                # Provide a markdown dir to trigger an update
                md_dir = Path(tmpdir) / "md"
                md_dir.mkdir(parents=True, exist_ok=True)
                md_file = md_dir / "OSV-2024-0000.md"
                md_file.write_text("# OSV-2024-0000\n## Summary\nSum\n## Affected\n- npm foo\n## Details\nDet\n", encoding="utf-8")
                
                with self.assertRaises(Exception) as context:
                    pipeline.run(
                        include_markdown_dirs=[md_dir],
                        include_cvelistv5_dirs=[],
                        include_cvelist_delta=False,
                        include_ghsa_api=False,
                        include_osv_api=False,
                        include_verity_catalog=False,
                        reset_checkpoints=False
                    )
                self.assertIn("Simulated crash during replace", str(context.exception))
            
            # Ensure the original index is still there and uncorrupted
            self.assertTrue(index_file.exists())
            index_content = json.loads(index_file.read_text(encoding="utf-8"))
            self.assertEqual(index_content["count"], 1)

if __name__ == '__main__':
    unittest.main()
