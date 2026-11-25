"""ATDD unit tests for AC-105.5: Attestation Verifier Optional Sigstore."""

import hashlib
import importlib
import json
import sys
from unittest.mock import MagicMock, patch

from mcp_vulnerabilities.attestation import verifier


def test_sigstore_optional_sha256_fallback(tmp_path, monkeypatch):
    """AC-105.5: When sigstore is unavailable, fallback returns sha256-manifest without ImportError."""
    target = tmp_path / "vulnerabilities.json.gz"
    payload = b"test-feed-bytes"
    target.write_bytes(payload)
    digest = hashlib.sha256(payload).hexdigest()

    manifest = {
        "generated_at": "2026-01-01T00:00:00Z",
        "files": {
            "vulnerabilities.json.gz": {"sha256": digest, "size": len(payload)}
        },
    }
    (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

    bundle = tmp_path / "bundle.json"
    bundle.write_text("{}", encoding="utf-8")

    monkeypatch.setitem(sys.modules, "sigstore", None)
    monkeypatch.setitem(sys.modules, "sigstore.verify", None)
    monkeypatch.setitem(sys.modules, "sigstore.models", None)
    monkeypatch.setitem(sys.modules, "sigstore.verify.policy", None)

    reloaded = importlib.reload(verifier)
    result = reloaded.verify_sigstore_bundle(target, bundle)

    assert result.method == "sha256-manifest"
    assert result["method"] == "sha256-manifest"
    assert result.verified is True
    assert result["verified"] is True
    assert result.sha256 == digest
    assert result.reason


def test_sigstore_available_path_used(tmp_path):
    """AC-105.5 paired benign control: when sigstore is available, sigstore path is used."""
    target = tmp_path / "feed.json.gz"
    target.write_bytes(b"signed-feed")
    bundle = tmp_path / "bundle.json"
    bundle.write_text('{"mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.1"}', encoding="utf-8")

    mock_bundle = MagicMock()
    mock_verifier = MagicMock()
    mock_verifier.verify_artifact.return_value = None

    with (
        patch("sigstore.models.Bundle.from_json", return_value=mock_bundle) as m_from_json,
        patch("sigstore.verify.Verifier.production", return_value=mock_verifier) as m_prod,
    ):
        result = verifier.verify_sigstore_bundle(target, bundle)

    m_from_json.assert_called_once()
    m_prod.assert_called_once()
    mock_verifier.verify_artifact.assert_called_once()
    assert result.verified is True
    assert result["verified"] is True
    assert result.method == "sigstore"
    assert result["method"] == "sigstore"
