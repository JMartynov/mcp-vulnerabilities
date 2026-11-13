import json
import logging
import os
import sys
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityFinding:
    cve_id: str
    package_name: str
    installed_version: str
    fixed_version: str
    severity: str
    title: str
    references: list[str] = field(default_factory=list)

@dataclass
class TrivyScanResult:
    target: str
    findings: list[VulnerabilityFinding] = field(default_factory=list)

class TrivyScanner:
    def __init__(self, trivy_bin: str = "trivy"):
        self.trivy_bin = shutil.which(trivy_bin) or "trivy"
        if not shutil.which(self.trivy_bin):
            local_bin = os.path.expanduser("~/.local/bin/trivy")
            if os.path.exists(local_bin):
                self.trivy_bin = local_bin

    def ensure_db(self) -> None:
        try:
            subprocess.run(
                [self.trivy_bin, "image", "--download-db-only"],
                check=True,
                capture_output=True
            )
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to download Trivy DB: {e.stderr.decode()}")

    def _run_trivy(self, target_label: str, *args: str) -> TrivyScanResult:
        cmd = [self.trivy_bin] + list(args) + ["--format", "json"]
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            output = result.stdout
        except subprocess.CalledProcessError as e:
            output = e.stdout
            if not output:
                logger.error(f"Trivy scan failed: {e.stderr}")
                return TrivyScanResult(target=target_label, findings=[])

        if not output.strip():
            return TrivyScanResult(target=target_label, findings=[])

        try:
            data = json.loads(output)
        except json.JSONDecodeError:
            logger.error("Failed to parse Trivy JSON output")
            return TrivyScanResult(target=target_label, findings=[])

        findings = []
        for result_item in data.get("Results", []):
            for vuln in result_item.get("Vulnerabilities", []):
                findings.append(VulnerabilityFinding(
                    cve_id=vuln.get("VulnerabilityID", ""),
                    package_name=vuln.get("PkgName", ""),
                    installed_version=vuln.get("InstalledVersion", ""),
                    fixed_version=vuln.get("FixedVersion", ""),
                    severity=vuln.get("Severity", "UNKNOWN"),
                    title=vuln.get("Title", ""),
                    references=vuln.get("References", [])
                ))
        return TrivyScanResult(target=target_label, findings=findings)

    def scan_fs(self, path: Path | str) -> TrivyScanResult:
        return self._run_trivy(str(path), "fs", str(path))

    def scan_npm_package(self, package_name: str, version: str | None = None) -> TrivyScanResult:
        pkg = f"{package_name}@{version}" if version else package_name
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                subprocess.run(
                    ["npm", "pack", pkg],
                    cwd=tmpdir,
                    check=True,
                    capture_output=True
                )

                for file in os.listdir(tmpdir):
                    if file.endswith(".tgz"):
                        tar_path = os.path.join(tmpdir, file)
                        with tarfile.open(tar_path) as tar:
                            if hasattr(tarfile, 'data_filter'):
                                tar.extractall(path=tmpdir, filter='data')
                            else:
                                tar.extractall(path=tmpdir)

                return self._run_trivy(pkg, "fs", os.path.join(tmpdir, "package"))
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to fetch npm package {pkg}: {e.stderr.decode()}")
                return TrivyScanResult(target=pkg, findings=[])

    def scan_pypi_package(self, package_name: str, version: str | None = None) -> TrivyScanResult:
        pkg = f"{package_name}=={version}" if version else package_name
        pip_cmd = [sys.executable, "-m", "pip"] if "sys" in globals() else ["pip3"]
        with tempfile.TemporaryDirectory() as tmpdir:
            try:
                subprocess.run(
                    pip_cmd + ["download", "--no-deps", "-d", tmpdir, pkg],
                    check=True,
                    capture_output=True
                )

                # Unpack wheels or tarballs
                for file in os.listdir(tmpdir):
                    file_path = os.path.join(tmpdir, file)
                    if file.endswith(".whl") or file.endswith(".zip"):
                        with zipfile.ZipFile(file_path, 'r') as zip_ref:
                            zip_ref.extractall(tmpdir)
                    elif file.endswith(".tar.gz") or file.endswith(".tgz"):
                        with tarfile.open(file_path) as tar:
                            if hasattr(tarfile, 'data_filter'):
                                tar.extractall(path=tmpdir, filter='data')
                            else:
                                tar.extractall(path=tmpdir)

                return self._run_trivy(pkg, "fs", tmpdir)
            except subprocess.CalledProcessError as e:
                logger.error(f"Failed to fetch PyPI package {pkg}: {e.stderr.decode()}")
                return TrivyScanResult(target=pkg, findings=[])

    def scan_image(self, image_ref: str) -> TrivyScanResult:
        return self._run_trivy(image_ref, "image", image_ref)

