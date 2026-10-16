from typing import Optional, Dict, Any
from .matcher import AuditReport
from ..transitive import TransitiveAuditResult

class SarifReporter:
    """Generates SARIF v2.1.0 formatted reports for GitHub Code Scanning."""

    @staticmethod
    def _map_severity_to_level(severity: str) -> str:
        severity = severity.upper()
        if severity in ("CRITICAL", "HIGH"):
            return "error"
        if severity == "MEDIUM":
            return "warning"
        return "note"

    @classmethod
    def _create_base_sarif(cls) -> Dict[str, Any]:
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mcp-vulnerabilities",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/JMartynov/mcp-vulnerabilities",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }

    @classmethod
    def generate_audit_sarif(cls, report: AuditReport, target_path: Optional[str] = None) -> Dict[str, Any]:
        sarif = cls._create_base_sarif()
        run = sarif["runs"][0]
        rules_dict = {}
        results = []

        # Default path if none provided
        default_location = target_path if target_path else "claude_desktop_config.json"

        # Deterministic sorting
        sorted_findings = sorted(report.findings, key=lambda f: (f.vulnerability_id, f.package_name))

        for finding in sorted_findings:
            rule_id = finding.vulnerability_id
            level = cls._map_severity_to_level(finding.severity_level)

            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": "VulnerableMCPServerDependency",
                    "shortDescription": {"text": finding.summary},
                    "fullDescription": {
                        "text": f"{finding.summary}\nAffected range: {finding.affected_range}\nRemediation: Upgrade to >= {finding.fixed_version or 'N/A'}"
                    },
                    "defaultConfiguration": {"level": level},
                    "help": {
                        "text": f"Remediation: Upgrade to >= {finding.fixed_version or 'N/A'}.\n\nReferences:\n" + "\n".join(finding.references),
                        "markdown": f"**Remediation:** Upgrade to `>= {finding.fixed_version or 'N/A'}`.\n\n**References:**\n" + "\n".join([f"- {ref}" for ref in finding.references])
                    },
                    "properties": {
                        "tags": ["security", "mcp", "supply-chain"],
                        "cvssScore": finding.cvss_score
                    }
                }

            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"MCP server '{finding.server_name}' ({finding.package_name}@{finding.installed_version or 'unpinned'}) is affected by {rule_id}. Upgrade to >= {finding.fixed_version or 'N/A'}."
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": default_location
                            }
                        }
                    }
                ]
            }
            results.append(result)

        run["tool"]["driver"]["rules"] = sorted(list(rules_dict.values()), key=lambda r: r["id"])
        run["results"] = results
        return sarif

    @classmethod
    def generate_transitive_sarif(cls, report: TransitiveAuditResult) -> Dict[str, Any]:
        sarif = cls._create_base_sarif()
        run = sarif["runs"][0]
        rules_dict = {}
        results = []

        target_path = report.target_manifest or "package.json"

        # Deterministic sorting
        sorted_findings = sorted(report.findings, key=lambda f: (f.vulnerability_id, f.dependency_name))

        for finding in sorted_findings:
            rule_id = finding.vulnerability_id
            level = cls._map_severity_to_level(finding.severity)

            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": "VulnerableTransitiveDependency",
                    "shortDescription": {"text": finding.summary},
                    "fullDescription": {
                        "text": f"{finding.summary}\nRemediation: Upgrade to >= {finding.fixed_version or 'N/A'}"
                    },
                    "defaultConfiguration": {"level": level},
                    "help": {
                        "text": f"Remediation: Upgrade to >= {finding.fixed_version or 'N/A'}.",
                        "markdown": f"**Remediation:** Upgrade to `>= {finding.fixed_version or 'N/A'}`."
                    },
                    "properties": {
                        "tags": ["security", "mcp", "supply-chain", "transitive"],
                        "cvssScore": finding.cvss_score
                    }
                }

            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"Dependency '{finding.dependency_name}' ({finding.ecosystem}) @ {finding.installed_version or 'unpinned'} is affected by {rule_id}. Upgrade to >= {finding.fixed_version or 'N/A'}."
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": target_path
                            }
                        }
                    }
                ]
            }
            results.append(result)

        run["tool"]["driver"]["rules"] = sorted(list(rules_dict.values()), key=lambda r: r["id"])
        run["results"] = results
        return sarif

    @classmethod
    def generate_ast_taint_sarif(cls, findings: list) -> Dict[str, Any]:
        sarif = cls._create_base_sarif()
        run = sarif["runs"][0]
        rules_dict = {}
        results = []

        # Deterministic sorting
        sorted_findings = sorted(findings, key=lambda f: (f.file_path or "", f.sink_line, f.sink_category))

        for finding in sorted_findings:
            rule_id = finding.sink_category
            level = cls._map_severity_to_level(finding.severity)

            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": rule_id.title().replace("_", ""),
                    "shortDescription": {"text": f"Dangerous static AST taint detected: {rule_id}"},
                    "fullDescription": {
                        "text": f"Unsanitized input may reach a dangerous sink.\nRemediation: {finding.remediation}"
                    },
                    "defaultConfiguration": {"level": level},
                    "help": {
                        "text": f"Remediation: {finding.remediation}",
                        "markdown": f"**Remediation:** {finding.remediation}"
                    },
                    "properties": {
                        "tags": ["security", "ast", "taint", "sast"]
                    }
                }

            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"Tainted parameter '{finding.parameter_name}' from tool '{finding.tool_name}' reaches {finding.sink_call}."
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.file_path or "unknown_file.py"
                            },
                            "region": {
                                "startLine": finding.sink_line
                            }
                        }
                    }
                ]
            }
            results.append(result)

        run["tool"]["driver"]["rules"] = sorted(list(rules_dict.values()), key=lambda r: r["id"])
        run["results"] = results
        return sarif

    @classmethod
    def generate_collision_sarif(
        cls, report: Any, config_path: str = "mcp_client_config.json"
    ) -> Dict[str, Any]:
        sarif = cls._create_base_sarif()
        run = sarif["runs"][0]
        rules_dict = {}
        results = []

        collisions = getattr(report, "collisions", [])

        for collision in collisions:
            risk_tier = getattr(collision, "risk_tier", "medium").upper()
            rule_id = f"MCP-STRUCTURAL-COLLISION-{risk_tier}"
            level = "error" if risk_tier in ("CRITICAL", "HIGH") else "warning"

            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": "McpToolCollisionShadowing",
                    "shortDescription": {
                        "text": f"MCP Tool Collision with {risk_tier} risk"
                    },
                    "fullDescription": {
                        "text": f"Multiple MCP servers expose the same tool name, leading to potential tool shadowing or prompt injection hijacking. Risk tier: {risk_tier}."
                    },
                    "defaultConfiguration": {"level": level},
                    "help": {
                        "text": "Review duplicate tool names to ensure your LLM client routes calls to the intended backend. Prefix or rename tools to prevent conflicts."
                    },
                }

            servers_str = ", ".join(getattr(collision, "servers", []))
            packages_str = ", ".join(getattr(collision, "packages", []))
            is_identical = getattr(collision, "schema_identical", False)
            match_status = "IDENTICAL" if is_identical else "DIVERGENT"
            tool_name = getattr(collision, "tool_name", "")

            msg = (
                f"Tool name collision detected for '{tool_name}'. "
                f"Exposed by servers: {servers_str} ({packages_str}). "
                f"Schema Match: {match_status}."
            )
            indicators = getattr(collision, "risk_indicators", [])
            if indicators:
                msg += f" Risk Factors: {', '.join(indicators)}."
            divergence = getattr(collision, "divergence_details", None)
            if divergence:
                msg += f" Divergence: {divergence}."

            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": msg},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": str(config_path)},
                                "region": {"startLine": 1, "startColumn": 1},
                            }
                        }
                    ],
                }
            )

        run["tool"]["driver"]["rules"] = sorted(
            list(rules_dict.values()), key=lambda r: r["id"]
        )
        run["results"] = results
        return sarif

