import json
import tempfile
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from mcp_vulnerabilities.attestation.manifest import (
    generate_catalog_manifest,
    verify_catalog_manifest,
    ChecksumMismatchError
)
from mcp_vulnerabilities.attestation.verifier import verify_sigstore_bundle

def test_manifest_generation_and_verification(tmp_path):
    target1 = tmp_path / "vulnerabilities.json.gz"
    target2 = tmp_path / "mcp_catalog_index.json"
    target3 = tmp_path / "analytics.json"
    target1.write_bytes(b"dummy1")
    target2.write_bytes(b"dummy2")
    target3.write_bytes(b"dummy3")
    
    manifest_path = generate_catalog_manifest(tmp_path)
    assert Path(manifest_path).exists()
    
    with open(manifest_path, "r") as f:
        manifest = json.load(f)
        
    assert "vulnerabilities.json.gz" in manifest["files"]
    assert "mcp_catalog_index.json" in manifest["files"]
    assert "analytics.json" in manifest["files"]
    
    # Should not raise
    verify_catalog_manifest(tmp_path)
    
    # Tamper with file
    target1.write_bytes(b"tampered")
    with pytest.raises(ChecksumMismatchError):
        verify_catalog_manifest(tmp_path)

def test_verify_sigstore_bundle_mock():
    # We will mock the sigstore Verifier
    bundle_data = {
        "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1",
        "verificationMaterial": {},
        "messageSignature": {"messageDigest": {"algorithm": "SHA2_256", "digest": ""}, "signature": ""}
    }
    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_dir = Path(tmp_dir)
        target = tmp_dir / "target.txt"
        target.write_bytes(b"dummy")
        
        bundle_path = tmp_dir / "bundle.json"
        with open(bundle_path, "w") as f:
            json.dump(bundle_data, f)
            
        with patch('mcp_vulnerabilities.attestation.verifier.Bundle.from_json') as mock_from_json, \
             patch('mcp_vulnerabilities.attestation.verifier.Verifier.production') as mock_production:
             
            mock_bundle = MagicMock()
            mock_bundle.verification_material.certificate.parsed_extensions = MagicMock()
            mock_from_json.return_value = mock_bundle
            
            mock_verifier = MagicMock()
            mock_production.return_value = mock_verifier
            
            # mock verify_artifact to do nothing (success)
            mock_verifier.verify_artifact.return_value = None
            
            result = verify_sigstore_bundle(target, bundle_path)
            
            assert result["verified"] is True
            assert result["signer"] == "https://github.com/JMartynov/mcp-vulnerabilities/.github/workflows/sign_release.yml@refs/heads/main"
            assert result["issuer"] == "https://token.actions.githubusercontent.com"
            assert result["timestamp"] == "N/A"
            
            # Now test failure
            mock_verifier.verify_artifact.side_effect = Exception("VerificationError")
            
            with pytest.raises(Exception, match="VerificationError"):
                verify_sigstore_bundle(target, bundle_path)

