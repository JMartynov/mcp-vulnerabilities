from __future__ import annotations

import re
from typing import Any

from .models import ReadinessIssue, ReadinessReport


class ReadinessLinter:
    def __init__(self) -> None:
        self.standard_platform_commands = {
            "ls", "cd", "rm", "mv", "cp", "cat", "echo", "mkdir", "rmdir",
            "grep", "find", "chmod", "chown", "ps", "kill", "top", "sudo",
            "curl", "wget", "git", "python", "node", "npm", "pip", "bash",
            "sh", "zsh", "docker", "podman", "tar", "zip", "unzip", "sed", "awk"
        }
        self.destructive_prefixes = (
            "delete_", "drop_", "remove_", "destroy_", "purge_", "wipe_", "kill_"
        )

    def lint_tool(self, tool: dict[str, Any]) -> list[ReadinessIssue]:
        issues: list[ReadinessIssue] = []
        name = str(tool.get("name", "unknown")).strip()

        # MCP-R001: Missing/Vague Tool Description
        description = tool.get("description", "")
        desc_str = str(description).strip() if description else ""
        if not desc_str or len(desc_str) < 12:
            issues.append(
                ReadinessIssue(
                    rule_id="MCP-R001",
                    severity="CRITICAL",
                    target=f"tool:{name}",
                    message="Tool description is missing, empty, or too vague (under 12 characters).",
                    recommendation="Provide a detailed description of the tool's functionality.",
                )
            )

        # MCP-R006: Naming Collision & Convention Violation
        if not re.match(r"^[a-z0-9_-]+$", name):
            issues.append(
                ReadinessIssue(
                    rule_id="MCP-R006",
                    severity="WARNING",
                    target=f"tool:{name}",
                    message="Tool name contains spaces, uppercase letters, or illegal characters.",
                    recommendation="Use lowercase alphanumeric characters, dashes, and underscores only.",
                )
            )
        elif name in self.standard_platform_commands:
            issues.append(
                ReadinessIssue(
                    rule_id="MCP-R006",
                    severity="WARNING",
                    target=f"tool:{name}",
                    message=f"Tool name '{name}' collides with a standard platform command.",
                    recommendation="Choose a more specific, domain-prefixed tool name.",
                )
            )

        input_schema = tool.get("inputSchema") or tool.get("input_schema") or {}
        if not isinstance(input_schema, dict):
            input_schema = {}

        # MCP-R007: Mutating Tool Error Contract Absence
        is_mutating = bool(tool.get("is_mutating", False))
        if not is_mutating:
            for prefix in self.destructive_prefixes:
                if name.startswith(prefix):
                    is_mutating = True
                    break

        if is_mutating:
            output_schema = tool.get("outputSchema") or tool.get("output_schema")
            if not output_schema:
                issues.append(
                    ReadinessIssue(
                        rule_id="MCP-R007",
                        severity="WARNING",
                        target=f"tool:{name}",
                        message="Mutating tool lacks outputSchema or failure response definition.",
                        recommendation="Define an outputSchema or error schema for mutating operations.",
                    )
                )

        # Schema property checks
        properties = input_schema.get("properties", {})
        if not isinstance(properties, dict):
            properties = {}

        # MCP-R003: Missing Required Parameter Specification
        if properties and "required" not in input_schema:
            issues.append(
                ReadinessIssue(
                    rule_id="MCP-R003",
                    severity="CRITICAL",
                    target=f"tool:{name}",
                    message="Object schema lacks an explicit required array.",
                    recommendation="Provide an explicit 'required' array in the inputSchema.",
                )
            )

        required_params = input_schema.get("required", [])
        if not isinstance(required_params, list):
            required_params = []

        for param_name, param_schema in properties.items():
            if not isinstance(param_schema, dict):
                continue

            param_target = f"tool:{name}.param:{param_name}"
            param_type = param_schema.get("type")

            # MCP-R002: Untyped or Broad Parameters
            if not param_type or param_type == "any":
                issues.append(
                    ReadinessIssue(
                        rule_id="MCP-R002",
                        severity="CRITICAL",
                        target=param_target,
                        message="Parameter lacks explicit JSON schema type or is unconstrained 'any'.",
                        recommendation="Specify a concrete JSON schema type (e.g., 'string', 'integer', 'object').",
                    )
                )

            # MCP-R004: Parameter Description Absence (only for required params)
            if param_name in required_params:
                param_desc = param_schema.get("description", "")
                if not param_desc or not str(param_desc).strip():
                    issues.append(
                        ReadinessIssue(
                            rule_id="MCP-R004",
                            severity="WARNING",
                            target=param_target,
                            message=f"Required parameter '{param_name}' lacks a description.",
                            recommendation="Provide an explanatory description for the model.",
                        )
                    )

            # MCP-R005: Unbounded Collection Parameters
            if param_type == "array":
                if "items" not in param_schema:
                    issues.append(
                        ReadinessIssue(
                            rule_id="MCP-R005",
                            severity="WARNING",
                            target=param_target,
                            message="Array parameter lacks 'items' definition.",
                            recommendation="Define the 'items' schema for array elements.",
                        )
                    )
            elif param_type in ("integer", "number"):
                if "minimum" not in param_schema and "maximum" not in param_schema:
                    issues.append(
                        ReadinessIssue(
                            rule_id="MCP-R005",
                            severity="INFO",
                            target=param_target,
                            message="Numeric parameter lacks minimum/maximum bounds.",
                            recommendation="Define 'minimum' and/or 'maximum' to restrict input range.",
                        )
                    )

        return issues

    def lint_schema(
        self, schema: dict[str, Any] | list[dict[str, Any]], target_name: str = "unknown"
    ) -> ReadinessReport:
        tools: list[dict[str, Any]] = []
        if isinstance(schema, list):
            tools = schema
        elif isinstance(schema, dict):
            if "tools" in schema and isinstance(schema["tools"], list):
                tools = schema["tools"]
            elif "versions" in schema and isinstance(schema["versions"], list) and len(schema["versions"]) > 0:
                first_version = schema["versions"][0]
                if "tool_signatures" in first_version:
                    tools = first_version["tool_signatures"]
            elif "name" in schema and ("description" in schema or "inputSchema" in schema or "input_schema" in schema):
                tools = [schema]

        all_issues: list[ReadinessIssue] = []
        for tool in tools:
            if isinstance(tool, dict):
                all_issues.extend(self.lint_tool(tool))

        score = 100
        counts = {"CRITICAL": 0, "WARNING": 0, "INFO": 0}

        for issue in all_issues:
            counts[issue.severity] = counts.get(issue.severity, 0) + 1
            if issue.severity == "CRITICAL":
                score -= 20
            elif issue.severity == "WARNING":
                score -= 5
            elif issue.severity == "INFO":
                score -= 1

        score = max(0, score)

        if score >= 90:
            grade = "A"
        elif score >= 80:
            grade = "B"
        elif score >= 70:
            grade = "C"
        elif score >= 60:
            grade = "D"
        else:
            grade = "F"

        return ReadinessReport(
            target_name=target_name,
            score=score,
            grade=grade,
            issues=all_issues,
            summary_counts=counts,
        )
