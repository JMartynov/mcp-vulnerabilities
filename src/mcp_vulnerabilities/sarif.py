from typing import Dict, Any, Optional
from mcp_vulnerabilities.compliance.models import OwaspComplianceReport

class ComplianceSarifReporter:
    @staticmethod
    def _map_severity_to_level(severity: str) -> str:
        severity = severity.upper()
        if severity in ("CRITICAL", "HIGH"):
            return "error"
        if severity in ("MEDIUM", "WARNING"):
            return "warning"
        return "note"

    @classmethod
    def generate_compliance_sarif(
        cls, report: OwaspComplianceReport, target_path: Optional[str] = None
    ) -> Dict[str, Any]:
        target_path = target_path or "schema.json"
        
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "mcp-vuln-compliance",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/JMartynov/mcp-vulnerabilities",
                            "rules": []
                        }
                    },
                    "results": []
                }
            ]
        }
        
        run = sarif["runs"][0]
        rules_dict = {}
        results = []

        for violation in report.violations:
            rule_id = violation.original_rule_id
            level = cls._map_severity_to_level(violation.severity)

            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": violation.category_name.replace(" ", "").replace("/", ""),
                    "shortDescription": {"text": f"Compliance Violation: {violation.category_name}"},
                    "fullDescription": {
                        "text": f"{violation.description}\nRemediation: {violation.remediation_guidance}"
                    },
                    "defaultConfiguration": {"level": level},
                    "help": {
                        "text": f"Remediation: {violation.remediation_guidance}",
                        "markdown": f"**Remediation:** {violation.remediation_guidance}"
                    },
                    "properties": {
                        "tags": ["compliance", "security", f"owasp-mcp-top-10:{violation.owasp_mcp_id}", f"owasp-llm:{violation.owasp_id.split(':')[0]}"]
                    }
                }

            result = {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": f"Target '{violation.target}' violated {violation.category_name} ({violation.owasp_mcp_id}). {violation.description}"
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
