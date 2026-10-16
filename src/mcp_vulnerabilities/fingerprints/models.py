"""Data models for MCP Structural Fingerprints, Passports, and Version Correlated Timelines."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Literal, Optional, Tuple

from mcp_vulnerabilities.models import OsvVulnerability

TransportType = Literal["stdio", "sse", "streamable-http", "websocket"]


@dataclass(frozen=True)
class ParameterMetadata:
    """Rich parameter metadata for a tool argument."""

    name: str
    type: str
    description: str | None = None
    required: bool = False
    default: Any = None
    enum: tuple[Any, ...] | None = None
    format: str | None = None
    items_type: str | None = None
    nested_properties: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "description": self.description,
            "required": self.required,
            "default": self.default,
            "enum": list(self.enum) if self.enum is not None else None,
            "format": self.format,
            "items_type": self.items_type,
            "nested_properties": self.nested_properties,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ParameterMetadata:
        raw_enum = data.get("enum")
        enum_val = tuple(raw_enum) if isinstance(raw_enum, (list, tuple)) else None
        return cls(
            name=str(data.get("name", "")),
            type=str(data.get("type", "string")),
            description=data.get("description"),
            required=bool(data.get("required", False)),
            default=data.get("default"),
            enum=enum_val,
            format=data.get("format"),
            items_type=data.get("items_type"),
            nested_properties=data.get("nested_properties"),
        )


@dataclass(frozen=True)
class ResourceSignature:
    """Structural signature of an exposed MCP resource."""

    uri_template: str
    name: str | None = None
    description: str = ""
    mime_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "uri_template": self.uri_template,
            "name": self.name,
            "description": self.description,
            "mime_type": self.mime_type,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ResourceSignature:
        return cls(
            uri_template=data.get("uri_template")
            or data.get("uriTemplate")
            or data.get("uri")
            or "",
            name=data.get("name"),
            description=data.get("description", ""),
            mime_type=data.get("mime_type") or data.get("mimeType"),
        )


@dataclass(frozen=True)
class ToolContractSignature:
    """Structural signature of a single MCP tool contract."""

    name: str
    canonical_hash: str
    description: str = ""
    is_mutating: bool = False
    property_keys: tuple[str, ...] = ()
    required_keys: tuple[str, ...] = ()
    parameter_types: dict[str, str] | tuple[str, ...] = field(default_factory=dict)
    input_schema: dict[str, Any] | str | None = None
    output_schema: dict[str, Any] | str | None = None
    description_hash: str | None = None
    parameters: tuple[ParameterMetadata, ...] = ()
    annotations: dict[str, bool] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "canonical_hash": self.canonical_hash,
            "description": self.description,
            "is_mutating": self.is_mutating,
            "property_keys": list(self.property_keys),
            "required_keys": list(self.required_keys),
            "parameter_types": (
                self.parameter_types
                if isinstance(self.parameter_types, dict)
                else list(self.parameter_types)
            ),
            "inputSchema": self.input_schema,
            "outputSchema": self.output_schema,
            "description_hash": self.description_hash,
            "parameters": [p.to_dict() for p in self.parameters],
            "annotations": self.annotations,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ToolContractSignature:
        if not isinstance(data, dict):
            data = {}
        property_keys = tuple(str(k) for k in data.get("property_keys", ()))
        required_keys = tuple(str(k) for k in data.get("required_keys", ()))

        raw_param_types = data.get("parameter_types", {})
        if isinstance(raw_param_types, dict):
            parameter_types: dict[str, str] | tuple[str, ...] = {
                str(k): str(v) for k, v in raw_param_types.items()
            }
        elif isinstance(raw_param_types, (list, tuple)):
            parameter_types = tuple(str(x) for x in raw_param_types)
        else:
            parameter_types = {}

        input_schema = data.get("inputSchema") or data.get("input_schema")
        output_schema = data.get("outputSchema") or data.get("output_schema")

        raw_params = data.get("parameters")
        parameters: list[ParameterMetadata] = []
        if isinstance(raw_params, (list, tuple)) and len(raw_params) > 0:
            for p in raw_params:
                if isinstance(p, ParameterMetadata):
                    parameters.append(p)
                elif isinstance(p, dict):
                    parameters.append(ParameterMetadata.from_dict(p))
        elif isinstance(input_schema, dict) and isinstance(input_schema.get("properties"), dict):
            props = input_schema["properties"]
            for k in sorted(props.keys()):
                v = props[k]
                if isinstance(v, dict):
                    raw_enum = v.get("enum")
                    enum_tuple = tuple(raw_enum) if isinstance(raw_enum, (list, tuple)) else None
                    items_type = (
                        v.get("items", {}).get("type")
                        if isinstance(v.get("items"), dict)
                        else None
                    )
                    nested_properties = (
                        v.get("properties") if isinstance(v.get("properties"), dict) else None
                    )
                    parameters.append(
                        ParameterMetadata(
                            name=str(k),
                            type=str(v.get("type", "string")),
                            description=v.get("description"),
                            required=k in required_keys,
                            default=v.get("default"),
                            enum=enum_tuple,
                            format=v.get("format"),
                            items_type=items_type,
                            nested_properties=nested_properties,
                        )
                    )

        raw_annotations = data.get("annotations", {})
        annotations: dict[str, bool] = {}
        if isinstance(raw_annotations, dict):
            for ak, av in raw_annotations.items():
                annotations[str(ak)] = bool(av)

        return cls(
            name=str(data.get("name", "")),
            canonical_hash=str(data.get("canonical_hash", "")),
            description=str(data.get("description", "") or ""),
            is_mutating=bool(data.get("is_mutating", False)),
            property_keys=property_keys,
            required_keys=required_keys,
            parameter_types=parameter_types,
            input_schema=input_schema,
            output_schema=output_schema,
            description_hash=data.get("description_hash"),
            parameters=tuple(parameters),
            annotations=annotations,
        )


@dataclass(frozen=True)
class PromptSignature:
    """Structural signature of an MCP prompt template."""

    name: str
    description: str | None = None
    argument_keys: tuple[str, ...] = ()
    required_arguments: tuple[str, ...] = ()
    arguments_schema: list[dict[str, Any]] | str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "argument_keys": list(self.argument_keys),
            "required_arguments": list(self.required_arguments),
            "arguments": self.arguments_schema,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PromptSignature:
        args_schema = (
            data.get("arguments")
            or data.get("parameters")
            or data.get("args")
            or data.get("arguments_schema")
            or []
        )
        arg_keys = list(data.get("argument_keys", ()))
        req_args = list(data.get("required_arguments", ()))
        if not arg_keys and isinstance(args_schema, list):
            for a in args_schema:
                if isinstance(a, dict) and "name" in a:
                    arg_keys.append(str(a["name"]))
                    if a.get("required"):
                        req_args.append(str(a["name"]))
                elif isinstance(a, str):
                    arg_keys.append(a)
        return cls(
            name=str(data.get("name", "")),
            description=data.get("description"),
            argument_keys=tuple(arg_keys),
            required_arguments=tuple(req_args),
            arguments_schema=args_schema if isinstance(args_schema, list) else None,
        )


@dataclass(frozen=True)
class VersionFingerprint:
    """Fingerprint signature for a specific version release of an MCP server."""

    version: str
    toolset_canonical_hash: str
    release_date: str | None = None
    dependencies: dict[str, str] | tuple[str, ...] = field(default_factory=dict)
    capabilities: dict[str, bool] | tuple[str, ...] = field(default_factory=dict)
    connections: list[dict[str, Any]] = field(default_factory=list)
    transport: TransportType = "stdio"
    remote_endpoint: str | None = None
    auth_type: Literal["none", "bearer", "api-key", "oauth2"] = "none"
    headers_schema: dict[str, str] = field(default_factory=dict)
    required_env_vars: tuple[str, ...] = ()
    tool_signatures: tuple[ToolContractSignature, ...] = field(default_factory=tuple)
    prompt_signatures: tuple[PromptSignature, ...] = field(default_factory=tuple)
    resource_signatures: tuple[ResourceSignature, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "toolset_canonical_hash": self.toolset_canonical_hash,
            "release_date": self.release_date,
            "dependencies": (
                self.dependencies
                if isinstance(self.dependencies, dict)
                else list(self.dependencies)
            ),
            "capabilities": (
                self.capabilities
                if isinstance(self.capabilities, dict)
                else list(self.capabilities)
            ),
            "connections": self.connections,
            "transport": self.transport,
            "remote_endpoint": self.remote_endpoint,
            "auth_type": self.auth_type,
            "headers_schema": self.headers_schema,
            "required_env_vars": list(self.required_env_vars),
            "tool_signatures": [t.to_dict() for t in self.tool_signatures],
            "prompt_signatures": [p.to_dict() for p in self.prompt_signatures],
            "resource_signatures": [r.to_dict() for r in self.resource_signatures],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> VersionFingerprint:
        raw_env = data.get("required_env_vars", ())
        env_vars = tuple(str(e) for e in raw_env) if isinstance(raw_env, (list, tuple)) else ()

        return cls(
            version=data["version"],
            toolset_canonical_hash=data.get("toolset_canonical_hash", ""),
            release_date=data.get("release_date"),
            dependencies=data.get("dependencies", {}),
            capabilities=data.get("capabilities", {}),
            connections=data.get("connections", []),
            transport=data.get("transport", "stdio"),
            remote_endpoint=data.get("remote_endpoint"),
            auth_type=data.get("auth_type", "none"),
            headers_schema=data.get("headers_schema", {}),
            required_env_vars=env_vars,
            tool_signatures=tuple(
                ToolContractSignature.from_dict(t) for t in data.get("tool_signatures", [])
            ),
            prompt_signatures=tuple(
                PromptSignature.from_dict(p) for p in data.get("prompt_signatures", [])
            ),
            resource_signatures=tuple(
                ResourceSignature.from_dict(r) for r in data.get("resource_signatures", [])
            ),
        )


@dataclass(frozen=True)
class ServerPackageSpec:
    """Catalog specification of an MCP server package and all its known version fingerprints."""

    package_name: str
    purl: str
    ecosystem: str
    display_name: str | None = None
    description: str | None = None
    author: str | None = None
    repository_url: str | None = None
    homepage_url: str | None = None
    license: str | None = None
    keywords: tuple[str, ...] = ()
    aliases: tuple[str, ...] = ()
    sources_merged: tuple[str, ...] = ()
    dist_tags: dict[str, str] = field(default_factory=dict)
    versions: tuple[VersionFingerprint, ...] = field(default_factory=tuple)
    transport: TransportType = "stdio"
    remote_endpoint: str | None = None
    auth_type: Literal["none", "bearer", "api-key", "oauth2"] = "none"
    headers_schema: dict[str, str] = field(default_factory=dict)
    security_profile: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "purl": self.purl,
            "ecosystem": self.ecosystem,
            "display_name": self.display_name,
            "description": self.description,
            "author": self.author,
            "repository_url": self.repository_url,
            "homepage_url": self.homepage_url,
            "license": self.license,
            "keywords": list(self.keywords),
            "aliases": list(self.aliases),
            "sources_merged": list(self.sources_merged),
            "dist_tags": self.dist_tags,
            "versions": [v.to_dict() for v in self.versions],
            "transport": self.transport,
            "remote_endpoint": self.remote_endpoint,
            "auth_type": self.auth_type,
            "headers_schema": self.headers_schema,
            "security_profile": self.security_profile,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ServerPackageSpec:
        raw_versions = data.get("versions", [])
        versions = tuple(
            VersionFingerprint.from_dict(v) if isinstance(v, dict) else v
            for v in raw_versions
        )
        return cls(
            package_name=data["package_name"],
            purl=data.get(
                "purl",
                f"pkg:{data.get('ecosystem', 'generic').lower()}/{data['package_name']}",
            ),
            ecosystem=data.get("ecosystem", "generic"),
            display_name=data.get("display_name"),
            description=data.get("description"),
            author=data.get("author"),
            repository_url=data.get("repository_url"),
            homepage_url=data.get("homepage_url"),
            license=data.get("license"),
            keywords=tuple(data.get("keywords", ())),
            aliases=tuple(data.get("aliases", ())),
            sources_merged=tuple(data.get("sources_merged", ())),
            dist_tags=data.get("dist_tags", {}),
            versions=versions,
            transport=data.get("transport", "stdio"),
            remote_endpoint=data.get("remote_endpoint"),
            auth_type=data.get("auth_type", "none"),
            headers_schema=data.get("headers_schema", {}),
            security_profile=data.get("security_profile", {}),
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


@dataclass
class VersionVulnerabilityState:
    version: str
    is_vulnerable: bool
    advisories: list[OsvVulnerability] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "is_vulnerable": self.is_vulnerable,
            "advisories": [adv.to_dict() if hasattr(adv, "to_dict") else adv for adv in self.advisories],
        }


@dataclass
class CorrelatedTimeline:
    package_name: str
    ecosystem: str
    timeline: list[VersionVulnerabilityState] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "ecosystem": self.ecosystem,
            "timeline": [state.to_dict() for state in self.timeline],
        }
