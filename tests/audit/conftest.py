import sys
from unittest.mock import MagicMock

class MockModule(MagicMock):
    __path__ = []

try:
    import mcp_fingerprints
except ImportError:
    sys.modules['mcp_fingerprints'] = MockModule()
    sys.modules['mcp_fingerprints.models'] = MockModule()
    sys.modules['mcp_fingerprints.config_scanner'] = MockModule()
