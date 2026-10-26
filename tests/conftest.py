import sys
from unittest.mock import MagicMock

# Mock mcp_fingerprints
sys.modules['mcp_fingerprints'] = MagicMock()
sys.modules['mcp_fingerprints.config_scanner'] = MagicMock()
sys.modules['mcp_fingerprints.models'] = MagicMock()
