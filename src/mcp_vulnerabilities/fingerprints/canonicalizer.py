import json
import hashlib
from typing import Any, Dict

from .models import ToolContractSignature

def canonicalize_json(obj: Any) -> str:
    """Sorts dictionary keys recursively, produces compact separators (',', ':') without extraneous whitespace."""
    return json.dumps(obj, separators=(',', ':'), sort_keys=True)

def compute_sha256(data: str | bytes) -> str:
    """Returns sha256:<hex_digest>."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return f"sha256:{hashlib.sha256(data).hexdigest()}"

def extract_tool_signature(tool_def: Dict[str, Any]) -> ToolContractSignature:
    """
    Normalizes properties, sorts parameter keys, sorts required keys, extracts types,
    and computes SHA-256 canonical hash.
    """
    name = tool_def.get("name", "")
    description = tool_def.get("description", "")
    
    input_schema = tool_def.get("inputSchema", {})
    if not isinstance(input_schema, dict):
        input_schema = {}
        
    properties = input_schema.get("properties", {})
    if not isinstance(properties, dict):
        properties = {}
        
    required = input_schema.get("required", [])
    if not isinstance(required, list):
        required = []

    # Sort property keys and required keys for consistency
    property_keys = tuple(sorted(properties.keys()))
    required_keys = tuple(sorted([str(k) for k in required]))

    # Extract types for properties
    param_types = []
    for k in property_keys:
        prop = properties.get(k, {})
        if isinstance(prop, dict) and "type" in prop:
            param_types.append(str(prop["type"]))
        else:
            param_types.append("unknown")
            
    parameter_types = tuple(param_types)
    
    # Construct a canonical representation of the tool interface
    canonical_repr = {
        "name": name,
        "properties": {k: properties[k] for k in property_keys},
        "required": list(required_keys)
    }
    
    canonical_json_str = canonicalize_json(canonical_repr)
    canonical_hash = compute_sha256(canonical_json_str)
    
    desc_hash = None
    if description:
        desc_hash = compute_sha256(description.strip())
        
    return ToolContractSignature(
        name=name,
        canonical_hash=canonical_hash,
        description=description,
        property_keys=property_keys,
        required_keys=required_keys,
        parameter_types=parameter_types,
        input_schema=canonicalize_json(input_schema),
        output_schema=None, # Usually tools only have inputSchema
        description_hash=desc_hash
    )

def compute_toolset_canonical_hash(tools: list[Dict[str, Any]]) -> str:
    """
    Deterministically sorts all extracted tool canonical hashes and combines with | 
    to form the order-independent toolset SHA-256 hash.
    """
    if not tools:
        return compute_sha256("")
        
    tool_hashes = []
    for t in tools:
        sig = extract_tool_signature(t)
        tool_hashes.append(sig.canonical_hash)
        
    # Sort hashes to be order-independent
    tool_hashes.sort()
    
    combined_str = "|".join(tool_hashes)
    return compute_sha256(combined_str)
