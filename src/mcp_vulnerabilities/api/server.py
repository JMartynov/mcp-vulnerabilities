import gzip
import json
import logging
import threading
import time
from http.server import ThreadingHTTPServer
from pathlib import Path

from mcp_vulnerabilities.api.middleware import ApiRequestHandler
from mcp_vulnerabilities.api.routes import router
from mcp_vulnerabilities.audit import VulnerabilityMatcher
from mcp_vulnerabilities.fingerprints.matcher import FingerprintMatcher

logger = logging.getLogger(__name__)

class McpSecurityApiServer:
    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8080,
        cors_origins: str | None = None,
        data_dir: str = "data/vulnerabilities",
        snapshot_path: str = "vulnerabilities.json.gz",
        passports_path: str = "data/passports.json.gz"
    ):
        self.host = host
        self.port = port
        self.cors_origins = cors_origins
        self.data_dir = data_dir
        self.snapshot_path = snapshot_path
        self.passports_path = passports_path
        
        self.server: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None
        self.start_time: float = 0
        
        self.vulnerability_matcher: VulnerabilityMatcher | None = None
        self.fingerprint_matcher: FingerprintMatcher | None = None

    def _load_data(self):
        logger.info("Loading vulnerability data...")
        s_path = Path(self.snapshot_path)
        vulns_data = []
        if s_path.exists():
            try:
                if s_path.suffix == ".gz":
                    with gzip.open(s_path, "rt", encoding="utf-8") as f:
                        vulns_data = json.load(f)
                else:
                    with open(s_path, "r", encoding="utf-8") as f:
                        vulns_data = json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load vulnerabilities: {e}")
        self.vulnerability_matcher = VulnerabilityMatcher(vulns_data)
        
        logger.info(f"Loading passports from {self.passports_path}...")
        self.fingerprint_matcher = FingerprintMatcher(Path(self.passports_path))

    def start(self):
        self._load_data()
        
        class Handler(ApiRequestHandler):
            pass
            
        Handler.router = staticmethod(router)
        Handler.cors_origins = self.cors_origins
        Handler.server_instance = self

        self.server = ThreadingHTTPServer((self.host, self.port), Handler)
        self.start_time = time.time()
        
        logger.info(f"Starting MCP Security API on {self.host}:{self.port}")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            logger.info("Shutting down API server...")
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=5)
        logger.info("API server stopped.")
