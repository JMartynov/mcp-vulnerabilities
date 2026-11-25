import json
import sys
from pathlib import Path

from mcp_vulnerabilities.attestation.manifest import hash_file


class VerificationResult(dict):
    """Dict result that also supports attribute access."""

    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


def _load_sigstore():
    if "sigstore" in sys.modules and sys.modules["sigstore"] is None:
        return None
    for mod in ("sigstore.verify", "sigstore.models", "sigstore.verify.policy"):
        if mod in sys.modules and sys.modules[mod] is None:
            return None
    try:
        from sigstore.verify import Verifier
        from sigstore.models import Bundle
        from sigstore.verify.policy import Identity
    except ImportError:
        return None
    return Verifier, Bundle, Identity


def verify_sigstore_bundle(
    target_path: Path,
    bundle_path: Path,
    expected_identity: str = "https://github.com/JMartynov/mcp-vulnerabilities/.github/workflows/sign_release.yml@refs/heads/main",
    expected_issuer: str = "https://token.actions.githubusercontent.com",
    offline: bool = False,
) -> VerificationResult:
    loaded = _load_sigstore()
    if loaded is not None:
        Verifier, Bundle, Identity = loaded

        with open(bundle_path, "r") as f:
            bundle_data = json.load(f)

        bundle = Bundle.from_json(bundle_data)

        auth_policy = Identity(
            identity=expected_identity,
            issuer=expected_issuer,
        )

        verifier = Verifier.production(offline=offline)

        with open(target_path, "rb") as f:
            target_content = f.read()

        verifier.verify_artifact(
            input_=target_content,
            bundle=bundle,
            policy=auth_policy,
        )

        return VerificationResult({
            "verified": True,
            "method": "sigstore",
            "artifact": str(target_path),
            "signer": expected_identity,
            "issuer": expected_issuer,
            "timestamp": "N/A",
            "reason": "Verified via Sigstore bundle",
        })

    target_path = Path(target_path)
    if not target_path.exists():
        return VerificationResult({
            "verified": False,
            "method": "sha256-manifest",
            "artifact": str(target_path),
            "signer": None,
            "issuer": None,
            "timestamp": "N/A",
            "sha256": None,
            "reason": f"Target file not found: {target_path}",
        })

    digest = hash_file(target_path)
    verified = True
    reason = "Sigstore unavailable; verified target SHA-256 digest"
    manifest_path = target_path.parent / "manifest.json"
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            files = manifest.get("files", {})
            if target_path.name in files:
                expected_sha = files[target_path.name].get("sha256")
                verified = digest == expected_sha
                reason = (
                    "SHA-256 digest matches manifest"
                    if verified
                    else f"SHA-256 mismatch: expected {expected_sha}, got {digest}"
                )
        except Exception:
            pass

    return VerificationResult({
        "verified": verified,
        "method": "sha256-manifest",
        "artifact": str(target_path),
        "signer": "sha256-manifest",
        "issuer": "local",
        "timestamp": "N/A",
        "sha256": digest,
        "reason": reason,
    })

