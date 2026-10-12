from dataclasses import dataclass, field, asdict
from typing import Any, Tuple, Dict, List

@dataclass(frozen=True)
class ToolContractSignature:
    name: str
    canonical_hash: str
    description: str | None = None
    property_keys: Tuple[str, ...] = field(default_factory=tuple)
    required_keys: Tuple[str, ...] = field(default_factory=tuple)
    parameter_types: Tuple[str, ...] = field(default_factory=tuple)
    input_schema: str | None = None
    output_schema: str | None = None
    description_hash: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolContractSignature":
        return cls(
            name=data["name"],
            canonical_hash=data["canonical_hash"],
            description=data.get("description"),
            property_keys=tuple(data.get("property_keys", ())),
            required_keys=tuple(data.get("required_keys", ())),
            parameter_types=tuple(data.get("parameter_types", ())),
            input_schema=data.get("input_schema"),
            output_schema=data.get("output_schema"),
            description_hash=data.get("description_hash"),
        )

@dataclass(frozen=True)
class PromptSignature:
    name: str
    description: str | None = None
    argument_keys: Tuple[str, ...] = field(default_factory=tuple)
    required_arguments: Tuple[str, ...] = field(default_factory=tuple)
    arguments_schema: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
        
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PromptSignature":
        return cls(
            name=data["name"],
            description=data.get("description"),
            argument_keys=tuple(data.get("argument_keys", ())),
            required_arguments=tuple(data.get("required_arguments", ())),
            arguments_schema=data.get("arguments_schema")
        )

@dataclass(frozen=True)
class VersionFingerprint:
    version: str
    toolset_canonical_hash: str
    release_date: str | None = None
    dependencies: Tuple[str, ...] = field(default_factory=tuple)
    capabilities: Tuple[str, ...] = field(default_factory=tuple)
    tool_signatures: Tuple[ToolContractSignature, ...] = field(default_factory=tuple)
    prompt_signatures: Tuple[PromptSignature, ...] = field(default_factory=tuple)
    
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["tool_signatures"] = [t.to_dict() for t in self.tool_signatures]
        d["prompt_signatures"] = [p.to_dict() for p in self.prompt_signatures]
        return d
        
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "VersionFingerprint":
        return cls(
            version=data["version"],
            toolset_canonical_hash=data["toolset_canonical_hash"],
            release_date=data.get("release_date"),
            dependencies=tuple(data.get("dependencies", ())),
            capabilities=tuple(data.get("capabilities", ())),
            tool_signatures=tuple(ToolContractSignature.from_dict(t) for t in data.get("tool_signatures", [])),
            prompt_signatures=tuple(PromptSignature.from_dict(p) for p in data.get("prompt_signatures", []))
        )

@dataclass(frozen=True)
class ServerPackageSpec:
    package_name: str
    purl: str
    ecosystem: str
    display_name: str | None = None
    description: str | None = None
    repository_url: str | None = None
    homepage_url: str | None = None
    versions: Tuple[VersionFingerprint, ...] = field(default_factory=tuple)
    security_profile: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["versions"] = [v.to_dict() for v in self.versions]
        return d
        
    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ServerPackageSpec":
        return cls(
            package_name=data["package_name"],
            purl=data["purl"],
            ecosystem=data["ecosystem"],
            display_name=data.get("display_name"),
            description=data.get("description"),
            repository_url=data.get("repository_url"),
            homepage_url=data.get("homepage_url"),
            versions=tuple(VersionFingerprint.from_dict(v) for v in data.get("versions", [])),
            security_profile=data.get("security_profile", {})
        )

@dataclass
class FingerprintMatchResult:
    package_name: str
    ecosystem: str
    version: str
    repository_url: str | None
    confidence_score: float
    match_type: str
    matched_tools_count: int
    total_tools_count: int
