import gzip
import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple, Optional

from mcp_fingerprints.data_loader import get_passports_path
from .models import FingerprintMatchResult, ServerPackageSpec, VersionFingerprint
from .canonicalizer import extract_tool_signature, compute_toolset_canonical_hash

logger = logging.getLogger(__name__)


class FingerprintMatcher:
    """High-performance fingerprint matcher indexing passports for toolset and topological matching."""

    def __init__(self, data_path: Path | None = None):
        self.by_toolset_hash: Dict[str, List[Tuple[ServerPackageSpec, VersionFingerprint]]] = {}
        self.by_tool_hash: Dict[str, Set[str]] = {}
        self.by_tool_name: Dict[str, Set[str]] = {}
        self.packages: Dict[str, ServerPackageSpec] = {}
        self.load_data(data_path)

    def load_data(self, data_path: Path | None = None) -> None:
        path = data_path
        if not path:
            candidate = Path("data/passports.json.gz")
            if candidate.exists():
                path = candidate
            else:
                try:
                    path = get_passports_path(download_if_missing=False)
                except Exception:
                    path = candidate

        if not path or not path.exists():
            logger.warning(f"Passports file not found at {path}. Fingerprint identification will be degraded.")
            return

        try:
            if path.suffix == ".gz":
                with gzip.open(path, "rt", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)

            items_to_process = []
            if isinstance(data, dict):
                pkg_dict = data.get("passports", data)
                if isinstance(pkg_dict, dict):
                    items_to_process = list(pkg_dict.values())
                elif isinstance(pkg_dict, list):
                    items_to_process = pkg_dict
            elif isinstance(data, list):
                items_to_process = data

            for item in items_to_process:
                if not isinstance(item, dict) or "package_name" not in item:
                    continue
                try:
                    spec = ServerPackageSpec.from_dict(item)
                    self.packages[spec.package_name] = spec
                    for ver in spec.versions:
                        if ver.toolset_canonical_hash:
                            if ver.toolset_canonical_hash not in self.by_toolset_hash:
                                self.by_toolset_hash[ver.toolset_canonical_hash] = []
                            self.by_toolset_hash[ver.toolset_canonical_hash].append((spec, ver))

                        for tool in ver.tool_signatures:
                            if tool.canonical_hash not in self.by_tool_hash:
                                self.by_tool_hash[tool.canonical_hash] = set()
                            self.by_tool_hash[tool.canonical_hash].add(spec.package_name)

                            t_name = tool.name.lower()
                            if t_name not in self.by_tool_name:
                                self.by_tool_name[t_name] = set()
                            self.by_tool_name[t_name].add(spec.package_name)
                except Exception as e:
                    logger.debug(f"Error indexing package spec: {e}")
                    continue

            logger.info(f"Loaded {len(self.packages)} server packages for fingerprint matching.")
        except Exception as e:
            logger.error(f"Failed to load passports from {path}: {e}")

    def _compute_jaccard(self, set1: Set[str], set2: Set[str]) -> float:
        if not set1 and not set2:
            return 1.0
        union = len(set1.union(set2))
        intersection = len(set1.intersection(set2))
        return intersection / union if union > 0 else 0.0

    def match_tools(self, tools: List[Dict[str, Any]]) -> List[FingerprintMatchResult]:
        if not tools:
            return []

        toolset_hash = compute_toolset_canonical_hash(tools)

        # 1. Exact toolset hash match (Confidence 1.0)
        if toolset_hash in self.by_toolset_hash:
            results = []
            for spec, ver in self.by_toolset_hash[toolset_hash]:
                results.append(
                    FingerprintMatchResult(
                        package_name=spec.package_name,
                        ecosystem=spec.ecosystem,
                        version=ver.version,
                        repository_url=spec.repository_url,
                        confidence_score=1.0,
                        match_type="toolset_exact",
                        matched_tools_count=len(tools),
                        total_tools_count=len(ver.tool_signatures),
                    )
                )
            return sorted(results, key=lambda x: x.confidence_score, reverse=True)

        # 2. Individual tool matching
        signatures = [extract_tool_signature(t) for t in tools]
        target_tool_hashes = {sig.canonical_hash for sig in signatures}
        target_tool_names = {sig.name for sig in signatures}
        target_tool_props = {sig.name: set(sig.property_keys) for sig in signatures}

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
                            "ver": ver,
                        }
                    continue

                # Check fuzzy topological overlap
                name_overlap = target_tool_names.intersection(cand_tool_names)
                if name_overlap:
                    total_jaccard = 0.0
                    for name in name_overlap:
                        t_props = target_tool_props.get(name, set())
                        c_props = set()
                        for c_tool in ver.tool_signatures:
                            if c_tool.name == name:
                                c_props = set(c_tool.property_keys)
                                break
                        total_jaccard += self._compute_jaccard(t_props, c_props)

                    avg_jaccard = total_jaccard / max(len(target_tool_names), len(cand_tool_names))
                    if avg_jaccard > 0.3:
                        key = (pkg_name, ver.version)
                        if key not in candidate_scores or candidate_scores[key]["confidence"] < avg_jaccard:
                            candidate_scores[key] = {
                                "confidence": avg_jaccard,
                                "match_type": "fuzzy_topological",
                                "matched_count": len(name_overlap),
                                "spec": spec,
                                "ver": ver,
                            }

        final_results = []
        for (pkg_name, ver_str), score_info in candidate_scores.items():
            spec = score_info["spec"]
            ver = score_info["ver"]
            final_results.append(
                FingerprintMatchResult(
                    package_name=pkg_name,
                    ecosystem=spec.ecosystem,
                    version=ver_str,
                    repository_url=spec.repository_url,
                    confidence_score=round(score_info["confidence"], 3),
                    match_type=score_info["match_type"],
                    matched_tools_count=score_info["matched_count"],
                    total_tools_count=len(ver.tool_signatures),
                )
            )

        return sorted(final_results, key=lambda x: x.confidence_score, reverse=True)
