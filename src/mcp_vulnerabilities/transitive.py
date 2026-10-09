"""Transitive dependency security auditor scanning bundled dependencies of MCP servers."""

from __future__ import annotations

import json
import logging
import re
import ssl
import sys
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomllib
    except ImportError:
        pass


logger = logging.getLogger(__name__)


def _get_ssl_context() -> ssl.SSLContext:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    except Exception:
        return ssl._create_unverified_context()


@dataclass
class TransitiveFinding:
    dependency_name: str
    installed_version: str | None
    ecosystem: str
    vulnerability_id: str
    summary: str
    severity: str
    cvss_score: float | None
    fixed_version: str | None


@dataclass
class TransitiveAuditResult:
    target_manifest: str
    total_dependencies: int
    findings: list[TransitiveFinding] = field(default_factory=list)

    @property
    def has_critical_or_high(self) -> bool:
        return any(f.severity in ("CRITICAL", "HIGH") for f in self.findings)

    @property
    def max_cvss(self) -> float:
        scores = [f.cvss_score for f in self.findings if f.cvss_score is not None]
        return max(scores) if scores else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest": self.target_manifest,
            "total_dependencies": self.total_dependencies,
            "vulnerable_dependencies_count": len(self.findings),
            "max_cvss": self.max_cvss,
            "has_critical_or_high": self.has_critical_or_high,
            "findings": [
                {
                    "dependency": f.dependency_name,
                    "version": f.installed_version,
                    "ecosystem": f.ecosystem,
                    "id": f.vulnerability_id,
                    "summary": f.summary,
                    "severity": f.severity,
                    "cvss_score": f.cvss_score,
                    "fixed_version": f.fixed_version,
                }
                for f in self.findings
            ],
        }


class TransitiveDependencyAuditor:
    """Audits third-party dependencies of MCP servers using the OSV batch API."""

    OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"

    @classmethod
    def audit_manifest_file(cls, manifest_path: str | Path) -> TransitiveAuditResult:
        """Parses a requirements.txt or package.json file and audits its dependencies."""
        path = Path(manifest_path)
        if not path.exists():
            raise FileNotFoundError(f"Manifest not found: {path}")

        deps: list[tuple[str, str | None, str]] = []  # (name, version, ecosystem)

        if path.name == "package.json":
            deps = cls.parse_package_json(path)
        elif path.name == "uv.lock":
            deps = cls.parse_uv_lock(path)
        elif path.name == "poetry.lock":
            deps = cls.parse_poetry_lock(path)
        elif path.name == "pyproject.toml":
            deps = cls.parse_pyproject_toml(path)
        elif "requirements" in path.name or path.name.endswith(".txt"):
            deps = cls.parse_requirements_txt(path)
        elif path.name.endswith(".toml"):
            content = path.read_text(encoding="utf-8")
            if "project" in content and "dependencies" in content:
                deps = cls.parse_pyproject_toml(path)
            elif "[[package]]" in content:
                deps = cls.parse_uv_lock(path)
            else:
                deps = []
        else:
            # Try guessing by content
            content = path.read_text(encoding="utf-8")
            if content.strip().startswith("{"):
                deps = cls.parse_package_json(path)
            else:
                deps = cls.parse_requirements_txt(path)

        findings = cls.audit_dependencies(deps)
        return TransitiveAuditResult(
            target_manifest=str(path),
            total_dependencies=len(deps),
            findings=findings,
        )

    @classmethod
    def parse_package_json(cls, path: Path) -> list[tuple[str, str | None, str]]:
        """Extracts direct dependencies from a package.json file."""
        data = json.loads(path.read_text(encoding="utf-8"))
        deps_dict = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
        extracted: list[tuple[str, str | None, str]] = []

        for name, ver_spec in deps_dict.items():
            # Clean semantic prefixes like ^, ~, >=
            clean_ver = re.sub(r"[^0-9.]", "", str(ver_spec).split("-")[0])
            extracted.append((name, clean_ver if clean_ver else None, "npm"))
        return extracted

    @classmethod
    def parse_requirements_txt(cls, path: Path) -> list[tuple[str, str | None, str]]:
        """Extracts pinned dependencies from a Python requirements.txt file."""
        extracted: list[tuple[str, str | None, str]] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-")):
                continue
            parts = re.split(r"(==|>=|<=|>|<|~=)", line, maxsplit=1)
            pkg = parts[0].strip()
            ver = parts[2].strip() if len(parts) > 2 else None
            extracted.append((pkg, ver, "PyPI"))
        return extracted

    @classmethod
    def parse_pyproject_toml(cls, path: Path) -> list[tuple[str, str | None, str]]:
        """Extracts dependencies from a PEP 621 pyproject.toml file."""
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        project = data.get("project", {})
        deps_list = project.get("dependencies", [])
        
        opt_deps = project.get("optional-dependencies", {})
        for opt_list in opt_deps.values():
            deps_list.extend(opt_list)

        extracted: list[tuple[str, str | None, str]] = []
        for dep in deps_list:
            # Similar logic as parse_requirements_txt
            # e.g., "httpx>=0.23.0", "fastapi[all]>=0.95.0", "pydantic", "fastapi^0.95.0"
            parts = re.split(r"(==|>=|<=|>|<|~=|\^|~)", dep, maxsplit=1)
            pkg = parts[0].strip()
            # Remove extras e.g. [all]
            pkg = re.sub(r"\[.*\]", "", pkg).strip()
            ver = parts[2].strip() if len(parts) > 2 else None
            extracted.append((pkg, ver, "PyPI"))
        return extracted

    @classmethod
    def parse_uv_lock(cls, path: Path) -> list[tuple[str, str | None, str]]:
        """Extracts pinned dependencies from a uv.lock file."""
        return cls._parse_toml_package_array(path)

    @classmethod
    def parse_poetry_lock(cls, path: Path) -> list[tuple[str, str | None, str]]:
        """Extracts pinned dependencies from a poetry.lock file."""
        return cls._parse_toml_package_array(path)

    @classmethod
    def _parse_toml_package_array(cls, path: Path) -> list[tuple[str, str | None, str]]:
        """Common logic to extract dependencies from [[package]] tables."""
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        extracted: list[tuple[str, str | None, str]] = []
        for pkg in data.get("package", []):
            name = pkg.get("name")
            version = pkg.get("version")
            if name:
                extracted.append((name, version, "PyPI"))
        return extracted

    @classmethod
    def audit_dependencies(
        cls,
        dependencies: list[tuple[str, str | None, str]],
    ) -> list[TransitiveFinding]:
        """Queries OSV Batch API for a list of dependencies (name, version, ecosystem)."""
        if not dependencies:
            return []

        queries = []
        for name, ver, eco in dependencies:
            q: dict[str, Any] = {"package": {"name": name, "ecosystem": eco}}
            if ver:
                q["version"] = ver
            queries.append(q)

        findings: list[TransitiveFinding] = []
        try:
            payload = json.dumps({"queries": queries}).encode("utf-8")
            req = urllib.request.Request(
                cls.OSV_BATCH_URL,
                data=payload,
                headers={"Content-Type": "application/json", "User-Agent": "McpVulnerabilities/1.0"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15.0, context=_get_ssl_context()) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                results = data.get("results", [])

                for idx, r in enumerate(results):
                    vulns = r.get("vulns", [])
                    if not vulns or idx >= len(dependencies):
                        continue

                    pkg_name, pkg_ver, pkg_eco = dependencies[idx]

                    for v in vulns:
                        vid = v.get("id", "UNKNOWN")
                        summary = v.get("summary") or (v.get("details", "")[:120])
                        sev, cvss = cls._extract_severity_info(v)
                        fix = cls._find_fixed_version(v)

                        findings.append(
                            TransitiveFinding(
                                dependency_name=pkg_name,
                                installed_version=pkg_ver,
                                ecosystem=pkg_eco,
                                vulnerability_id=vid,
                                summary=summary,
                                severity=sev,
                                cvss_score=cvss,
                                fixed_version=fix,
                            )
                        )

        except Exception as exc:
            logger.warning("OSV batch transitive audit query failed: %s", exc)

        return findings

    @staticmethod
    def _extract_severity_info(adv: dict[str, Any]) -> tuple[str, float | None]:
        cvss = None
        for s in adv.get("severity", []):
            try:
                cvss = float(s.get("score"))
                break
            except (ValueError, TypeError):
                pass

        db_spec = adv.get("database_specific", {})
        sev = db_spec.get("severity")
        if not sev and cvss is not None:
            if cvss >= 9.0:
                sev = "CRITICAL"
            elif cvss >= 7.0:
                sev = "HIGH"
            elif cvss >= 4.0:
                sev = "MEDIUM"
            else:
                sev = "LOW"
        return (sev or "UNKNOWN").upper(), cvss

    @staticmethod
    def _find_fixed_version(adv: dict[str, Any]) -> str | None:
        for aff in adv.get("affected", []):
            for r in aff.get("ranges", []):
                for ev in r.get("events", []):
                    if "fixed" in ev:
                        return ev["fixed"]
        return None
