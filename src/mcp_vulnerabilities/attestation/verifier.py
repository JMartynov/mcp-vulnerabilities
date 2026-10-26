import json
from pathlib import Path
from sigstore.verify import Verifier, policy
from sigstore.models import Bundle
from sigstore.verify.policy import Identity

def verify_sigstore_bundle(
    target_path: Path,
    bundle_path: Path,
    expected_identity: str = "https://github.com/JMartynov/mcp-vulnerabilities/.github/workflows/sign_release.yml@refs/heads/main",
    expected_issuer: str = "https://token.actions.githubusercontent.com",
    offline: bool = False
) -> dict:
    
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
    
    signer = expected_identity
    issuer = expected_issuer
    timestamp = "N/A" 

    return {
        "verified": True,
        "artifact": str(target_path),
        "signer": signer,
        "issuer": issuer,
        "timestamp": timestamp
    }

