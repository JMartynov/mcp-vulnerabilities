import logging
import shutil
import subprocess
import tarfile
import urllib.error
import urllib.request
from pathlib import Path

from mcp_vulnerabilities.converters.gitlab import GitLabConverter
from mcp_vulnerabilities.models import OsvVulnerability

logger = logging.getLogger(__name__)

class GitLabAdvisorySync:
    """GitLab Advisory Database synchronizer."""

    def __init__(self, storage_dir: str | Path = "data/sources/gitlab") -> None:
        self.storage_dir = Path(storage_dir)
        self.repo_url = "https://gitlab.com/gitlab-org/advisories-community.git"
        self.archive_url = "https://gitlab.com/gitlab-org/advisories-community/-/archive/main/advisories-community-main.tar.gz"
        self.target_ecosystems = ["npm", "pypi", "go"]

    def _clone_or_pull_git(self, repo_dir: Path, force: bool = False) -> bool:
        try:
            if repo_dir.exists() and (repo_dir / ".git").exists():
                if force:
                    subprocess.run(["git", "-C", str(repo_dir), "reset", "--hard", "origin/main"], check=True, capture_output=True)
                subprocess.run(["git", "-C", str(repo_dir), "pull", "--rebase"], check=True, capture_output=True)
            else:
                if repo_dir.exists():
                    shutil.rmtree(repo_dir)
                repo_dir.mkdir(parents=True, exist_ok=True)

                subprocess.run(["git", "clone", "--filter=blob:none", "--sparse", self.repo_url, str(repo_dir)], check=True, capture_output=True)

                for eco in self.target_ecosystems:
                    subprocess.run(["git", "-C", str(repo_dir), "sparse-checkout", "add", eco], check=True, capture_output=True)
            return True
        except (subprocess.CalledProcessError, FileNotFoundError) as e:
            logger.warning(f"Git sync failed: {e}")
            return False

    def _download_archive(self, repo_dir: Path) -> bool:
        try:
            archive_path = self.storage_dir / "archive.tar.gz"
            urllib.request.urlretrieve(self.archive_url, archive_path)

            with tarfile.open(archive_path, "r:gz") as tar:
                # Filter to only extract the ecosystems we care about, adjusting paths to strip the top-level dir
                members_to_extract = []
                for member in tar.getmembers():
                    parts = member.name.split('/')
                    if len(parts) > 1 and parts[1] in self.target_ecosystems:
                        # Strip the top dir
                        member.name = "/".join(parts[1:])
                        members_to_extract.append(member)

                tar.extractall(path=repo_dir, members=members_to_extract)

            archive_path.unlink()
            return True
        except (urllib.error.URLError, tarfile.TarError, OSError) as e:
            logger.warning(f"Archive download failed: {e}")
            return False

    def sync_repository(self, sparse_checkout: bool = True, force: bool = False) -> Path:
        """Sync the upstream repository to local storage."""
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        repo_dir = self.storage_dir / "repo"
        marker_file = self.storage_dir / ".sync_marker"

        if sparse_checkout and self._clone_or_pull_git(repo_dir, force):
            marker_file.touch()
        elif self._download_archive(repo_dir):
            marker_file.touch()
        else:
            logger.info("Operating in offline mode using existing data.")

        return repo_dir

    def scan_advisories(self, target_dir: Path | str | None = None) -> list[OsvVulnerability]:
        """Scan directory and parse advisories into OSV models."""
        target = Path(target_dir) if target_dir else self.storage_dir / "repo"
        advisories: list[OsvVulnerability] = []

        if not target.exists():
            return advisories

        for ext in ("*.yml", "*.yaml"):
            for eco in self.target_ecosystems:
                eco_dir = target / eco
                if eco_dir.exists():
                    for file_path in eco_dir.rglob(ext):
                        try:
                            vuln = GitLabConverter.from_file(file_path)
                            advisories.append(vuln)
                        except Exception as e:
                            logger.error(f"Failed to parse {file_path}: {e}")

        return advisories

