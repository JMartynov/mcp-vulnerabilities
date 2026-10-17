import os
import json
import logging
import urllib.request
import urllib.error
from pathlib import Path
from typing import Optional, List

from mcp_vulnerabilities.fingerprints.correlator import VulnerabilityCorrelator
from mcp_vulnerabilities.fingerprints.models import CorrelatedTimeline

logger = logging.getLogger(__name__)

class CrossRepoSyncManager:
    """Manages cross-repository synchronization of passports.json.gz from mcp-fingerprints."""
    
    def __init__(self, target_path: Path = Path("data/passports.json.gz")):
        self.target_path = target_path
        self.github_api_url = "https://api.github.com/repos/jmartynov/mcp-fingerprints/releases/latest"
        
    def fetch_latest_passports(self, github_token: Optional[str] = None) -> bool:
        """
        Fetches the latest passports.json.gz release asset from mcp-fingerprints.
        Falls back to local file if download fails or is rate-limited.
        Returns True if a new file was successfully downloaded, False otherwise (or if fallback used).
        """
        req = urllib.request.Request(self.github_api_url)
        if github_token:
            req.add_header("Authorization", f"Bearer {github_token}")
        req.add_header("Accept", "application/vnd.github.v3+json")
        req.add_header("User-Agent", "mcp-vulnerabilities-sync")
        
        try:
            with urllib.request.urlopen(req) as response:
                release_data = json.loads(response.read().decode('utf-8'))
                
            download_url = None
            for asset in release_data.get("assets", []):
                if asset.get("name") == "passports.json.gz":
                    download_url = asset.get("browser_download_url")
                    break
                    
            if not download_url:
                logger.warning("passports.json.gz asset not found in the latest release. Falling back to raw github content.")
                raise Exception("Asset not found")
                
            logger.info(f"Downloading passports.json.gz from {download_url}")
            asset_req = urllib.request.Request(download_url)
            if github_token:
                asset_req.add_header("Authorization", f"Bearer {github_token}")
            asset_req.add_header("User-Agent", "mcp-vulnerabilities-sync")
            
            with urllib.request.urlopen(asset_req) as asset_response:
                self.target_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.target_path, "wb") as f:
                    f.write(asset_response.read())
                    
            logger.info(f"Successfully downloaded passports.json.gz to {self.target_path}")
            return True
            
        except urllib.error.HTTPError as e:
            if e.code == 403 and "rate limit" in str(e.reason).lower():
                logger.warning("GitHub API rate limit exceeded during cross-repo sync. Falling back to raw github content.")
            else:
                logger.error(f"HTTPError fetching passports: {e.code} {e.reason}. Falling back to raw github content.")
        except Exception as e:
            logger.error(f"Error fetching passports: {e}. Falling back to raw github content.")
            
        # Fallback to downloading from raw.githubusercontent.com
        fallback_url = "https://raw.githubusercontent.com/jmartynov/mcp-fingerprints/main/passports.json.gz"
        logger.info(f"Attempting fallback download from {fallback_url}")
        
        try:
            fallback_req = urllib.request.Request(fallback_url)
            fallback_req.add_header("User-Agent", "mcp-vulnerabilities-sync")
            if github_token:
                fallback_req.add_header("Authorization", f"Bearer {github_token}")
            
            with urllib.request.urlopen(fallback_req) as fallback_response:
                self.target_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.target_path, "wb") as f:
                    f.write(fallback_response.read())
                    
            logger.info(f"Successfully downloaded passports.json.gz from fallback to {self.target_path}")
            return True
            
        except Exception as fallback_e:
            logger.error(f"Fallback download also failed: {fallback_e}. Using local snapshot if available.")
            return False

    def sync_and_correlate(self, vulnerabilities_path: Path, github_token: Optional[str] = None) -> Optional[List[CorrelatedTimeline]]:
        """
        Coordinates the full sync workflow: downloading passports, running correlation,
        and optionally triggering downstream processes.
        """
        logger.info("Starting cross-repository snapshot sync...")
        self.fetch_latest_passports(github_token=github_token)
        
        if not self.target_path.exists():
            logger.error(f"No passports.json.gz available at {self.target_path}. Cannot proceed with correlation.")
            return None
            
        logger.info("Running vulnerability correlation engine...")
        correlator = VulnerabilityCorrelator.from_paths(vulnerabilities_path, self.target_path)
        correlated_results = correlator.correlate_all()
        logger.info(f"Successfully correlated {len(correlated_results)} packages.")
        
        return correlated_results
