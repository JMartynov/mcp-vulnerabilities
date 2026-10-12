import gzip
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

from .models import FingerprintMatchResult, ServerPackageSpec, VersionFingerprint
from .canonicalizer import extract_tool_signature, compute_toolset_canonical_hash

logger = logging.getLogger(__name__)

class FingerprintMatcher:
    def __init__(self, data_path: Path | None = None):
        self.by_toolset_hash: Dict[str, List[Tuple[ServerPackageSpec, VersionFingerprint]]] = {}
        self.by_tool_hash: Dict[str, Set[str]] = {}
        self.by_tool_name: Dict[str, Set[str]] = {}
        
        # Keep packages for reference
        self.packages: Dict[str, ServerPackageSpec] = {}
        
        self.load_data(data_path)
        
    def load_data(self, data_path: Path | None = None) -> None:
        path = data_path or Path("data/passports.json.gz")
        if not path.exists():
            logger.warning(f"Passports file not found at {path}. Fingerprint identification will be degraded.")
            return
            
        try:
            if path.suffix == ".gz":
                with gzip.open(path, "rt", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    
            if not isinstance(data, list):
                if isinstance(data, dict) and "passports" in data:
                    data = data["passports"]
                else:
                    logger.error("Passports data is not a list of packages.")
                    return
                    
            for item in data:
                try:
                    spec = ServerPackageSpec.from_dict(item)
                    self.packages[spec.package_name] = spec
                    
                    for ver in spec.versions:
                        # Index by toolset hash
                        if ver.toolset_canonical_hash:
                            if ver.toolset_canonical_hash not in self.by_toolset_hash:
                                self.by_toolset_hash[ver.toolset_canonical_hash] = []
                            self.by_toolset_hash[ver.toolset_canonical_hash].append((spec, ver))
                            
                        # Index by individual tools
                        for tool in ver.tool_signatures:
                            if tool.canonical_hash:
                                if tool.canonical_hash not in self.by_tool_hash:
                                    self.by_tool_hash[tool.canonical_hash] = set()
                                self.by_tool_hash[tool.canonical_hash].add(spec.package_name)
                                
                            if tool.name:
                                if tool.name not in self.by_tool_name:
                                    self.by_tool_name[tool.name] = set()
                                self.by_tool_name[tool.name].add(spec.package_name)
                                
                except Exception as e:
                    logger.warning(f"Failed to parse package spec: {e}")
                    
            logger.info(f"Loaded {len(self.packages)} server passports.")
        except Exception as e:
            logger.error(f"Error loading passports from {path}: {e}")

    def _compute_jaccard(self, set1: Set[str], set2: Set[str]) -> float:
        if not set1 and not set2:
            return 1.0
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))
        return intersection / union if union > 0 else 0.0

    def match_tools(self, tools: List[Dict[str, Any]]) -> List[FingerprintMatchResult]:
        if not tools:
            return []
            
        toolset_hash = compute_toolset_canonical_hash(tools)
        
        # 1. Exact toolset hash match (Confidence 1.0)
        if toolset_hash in self.by_toolset_hash:
            results = []
            for spec, ver in self.by_toolset_hash[toolset_hash]:
                results.append(FingerprintMatchResult(
                    package_name=spec.package_name,
                    ecosystem=spec.ecosystem,
                    version=ver.version,
                    repository_url=spec.repository_url,
                    confidence_score=1.0,
                    match_type="toolset_exact",
                    matched_tools_count=len(tools),
                    total_tools_count=len(ver.tool_signatures)
                ))
            return sorted(results, key=lambda x: x.confidence_score, reverse=True)
            
        # 2. Individual tool matching
        signatures = [extract_tool_signature(t) for t in tools]
        target_tool_hashes = {sig.canonical_hash for sig in signatures}
        target_tool_names = {sig.name for sig in signatures}
        target_tool_props = {sig.name: set(sig.property_keys) for sig in signatures}
        
        # Score candidates
        candidate_scores: Dict[Tuple[str, str], Dict[str, Any]] = {}
        
        for pkg_name, spec in self.packages.items():
            for ver in spec.versions:
                if not ver.tool_signatures:
                    continue
                    
                cand_tool_hashes = {t.canonical_hash for t in ver.tool_signatures}
                cand_tool_names = {t.name for t in ver.tool_signatures}
                
                # Check tool hashes overlap
                hash_overlap = len(target_tool_hashes.intersection(cand_tool_hashes))
                if hash_overlap > 0:
                    confidence = hash_overlap / max(len(target_tool_hashes), len(cand_tool_hashes))
                    key = (pkg_name, ver.version)
                    if key not in candidate_scores or candidate_scores[key]["confidence"] < confidence:
                        candidate_scores[key] = {
                            "confidence": confidence,
                            "match_type": "tool_hash",
                            "matched_count": hash_overlap,
                            "spec": spec,
                            "ver": ver
                        }
                    continue
                
                # Check fuzzy topological overlap (names and properties)
                name_overlap = target_tool_names.intersection(cand_tool_names)
                if name_overlap:
                    total_jaccard = 0.0
                    for name in name_overlap:
                        t_props = target_tool_props.get(name, set())
                        
                        # Find matching tool in candidate
                        c_props = set()
                        for c_tool in ver.tool_signatures:
                            if c_tool.name == name:
                                c_props = set(c_tool.property_keys)
                                break
                                
                        total_jaccard += self._compute_jaccard(t_props, c_props)
                        
                    avg_jaccard = total_jaccard / max(len(target_tool_names), len(cand_tool_names))
                    if avg_jaccard > 0.3: # Threshold
                        key = (pkg_name, ver.version)
                        if key not in candidate_scores or candidate_scores[key]["confidence"] < avg_jaccard:
                            candidate_scores[key] = {
                                "confidence": avg_jaccard,
                                "match_type": "fuzzy_topological",
                                "matched_count": len(name_overlap),
                                "spec": spec,
                                "ver": ver
                            }

        # Convert to results
        results = []
        for (pkg_name, version), data in candidate_scores.items():
            spec = data["spec"]
            ver = data["ver"]
            results.append(FingerprintMatchResult(
                package_name=spec.package_name,
                ecosystem=spec.ecosystem,
                version=ver.version,
                repository_url=spec.repository_url,
                confidence_score=data["confidence"],
                match_type=data["match_type"],
                matched_tools_count=data["matched_count"],
                total_tools_count=len(ver.tool_signatures)
            ))
            
        return sorted(results, key=lambda x: x.confidence_score, reverse=True)
