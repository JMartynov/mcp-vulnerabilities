import ssl
from typing import Optional


def get_ssl_context(insecure: bool = False, cafile: Optional[str] = None) -> ssl.SSLContext:
    """
    Creates an SSL context with certificate verification enabled by default.
    Falls back to certifi CA bundle if available to prevent macOS Python certificate errors.
    If insecure is True, explicitly disables certificate validation (use only for testing/proxies).
    """
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    if cafile:
        return ssl.create_default_context(cafile=cafile)

    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except (ImportError, Exception):
        return ssl.create_default_context()
