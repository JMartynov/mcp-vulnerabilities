from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .capability_classifier import (
    CapabilityRiskClassifier,
    SecurityCommentaryEngine,
    analyze_tool_security,
)
from .models import AnalysisTarget, ThreatCategory, ThreatFinding, ThreatSeverity
from .regex_matcher import RegexThreatMatcher

try:
    import yara
    HAS_YARA = True
except ImportError:
    HAS_YARA = False

class ThreatEngine:
    def __init__(self, rules_dir: str | None = None):
        self.regex_matcher = RegexThreatMatcher()
        self.classifier = CapabilityRiskClassifier()
        self.commentary_engine = SecurityCommentaryEngine()
        self.yara_rules = None
        
        if HAS_YARA:
            if rules_dir is None:
                rules_dir = str(Path(__file__).parent / "rules")
            
            yara_files = {}
            if os.path.exists(rules_dir):
                for f in os.listdir(rules_dir):
                    if f.endswith(".yar") or f.endswith(".yara"):
                        yara_files[f] = os.path.join(rules_dir, f)
            
            if yara_files:
                try:
                    self.yara_rules = yara.compile(filepaths=yara_files)
                except Exception as e:
                    print(f"Warning: Failed to compile YARA rules: {e}")
                    self.yara_rules = None

    def analyze(self, target: AnalysisTarget) -> list[ThreatFinding]:
        findings_map: dict[str, ThreatFinding] = {}

        # 1. Extract strings to inspect
        surfaces = self._extract_surfaces(target)

        # 2. Run analysis
        for target_name, text in surfaces.items():
            if not text:
                continue

            # Yara match
            if self.yara_rules:
                matches = self.yara_rules.match(data=text)
                for match in matches:
                    rule_id = match.rule
                    # Default values if metadata is missing
                    meta = match.meta
                    category = ThreatCategory(meta.get("category", ThreatCategory.PROMPT_INJECTION.value))
                    severity = ThreatSeverity(meta.get("severity", ThreatSeverity.HIGH.value))
                    
                    finding = ThreatFinding(
                        rule_id=rule_id,
                        category=category,
                        severity=severity,
                        title=meta.get("title", rule_id),
                        description=meta.get("description", "Yara rule match"),
                        matched_target=target_name,
                        matched_pattern="[YARA Match]",  # difficult to get exact string from yara easily without custom logic
                        remediation_guidance=meta.get("remediation", "Review matched string"),
                        cwe_id=meta.get("cwe", "CWE-0")
                    )
                    
                    key = f"{rule_id}:{target_name}"
                    if key not in findings_map:
                        findings_map[key] = finding

            # Fallback regex match
            # Always run regex matcher if yara didn't catch or is disabled to ensure rules are caught. 
            # In our implementation we can run regex alongside or fallback. Let's just run it as it's quick.
            regex_matches = self.regex_matcher.match(text)
            for (rule_id, matched_pattern, category, severity, title, desc, rem, cwe) in regex_matches:
                finding = ThreatFinding(
                    rule_id=rule_id,
                    category=category,
                    severity=severity,
                    title=title,
                    description=desc,
                    matched_target=target_name,
                    matched_pattern=matched_pattern,
                    remediation_guidance=rem,
                    cwe_id=cwe
                )
                
                key = f"{rule_id}:{target_name}"
                if key not in findings_map:
                    findings_map[key] = finding
                    
        return list(findings_map.values())

    def _extract_surfaces(self, target: AnalysisTarget) -> dict[str, str]:
        surfaces = {}

        if target.instructions:
            surfaces["server.instructions"] = target.instructions
            
        for tool in target.tools:
            name = tool.get("name", "unknown")
            if "description" in tool:
                surfaces[f"tool:{name}.description"] = tool["description"]
                
            # Check properties
            input_schema = tool.get("inputSchema", {})
            properties = input_schema.get("properties", {})
            for prop_name, prop_data in properties.items():
                if isinstance(prop_data, dict) and "description" in prop_data:
                    surfaces[f"tool:{name}.parameter:{prop_name}"] = prop_data["description"]
                    
        for prompt in target.prompts:
            name = prompt.get("name", "unknown")
            if "description" in prompt:
                surfaces[f"prompt:{name}.description"] = prompt["description"]
            
            args = prompt.get("arguments", [])
            for arg in args:
                if isinstance(arg, dict) and "description" in arg:
                    arg_name = arg.get("name", "unknown")
                    surfaces[f"prompt:{name}.argument:{arg_name}"] = arg["description"]
                    
        for resource in target.resources:
            uri = resource.get("uri", "unknown")
            if "description" in resource:
                surfaces[f"resource:{uri}.description"] = resource["description"]
                
        return surfaces

    def analyze_capabilities(self, target: AnalysisTarget) -> dict[str, Any]:
        """Classifies capabilities and security commentary for target tools."""
        classifications = [self.classifier.classify_tool(t) for t in target.tools]
        commentary = self.commentary_engine.generate_server_commentary(
            server_name="target",
            tool_classifications=classifications,
        )
        return {
            "classifications": classifications,
            "commentary": commentary,
        }
