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
