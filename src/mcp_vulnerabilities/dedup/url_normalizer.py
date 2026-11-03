import urllib.parse
from collections.abc import Iterable
from mcp_vulnerabilities.models import ReferenceSpec


def normalize_url(url: str) -> str:
    """
    Normalize a URL for deduplication.
    - Lowercase scheme and netloc.
    - Strip HTTP tracking query parameters (utm_*, fbclid, gclid).
    - Remove trailing slashes from path (except for root domain).
    """
    if not url:
        return url

    try:
        parsed = urllib.parse.urlparse(url)
    except ValueError:
        return url

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    path = parsed.path
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    query_params = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    tracking_params = {"utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "fbclid", "gclid"}

    filtered_params = [(k, v) for k, v in query_params if k.lower() not in tracking_params]

    query = urllib.parse.urlencode(filtered_params)

    normalized_parsed = urllib.parse.ParseResult(
        scheme=scheme,
        netloc=netloc,
        path=path,
        params=parsed.params,
        query=query,
        fragment=parsed.fragment
    )

    return urllib.parse.urlunparse(normalized_parsed)


def deduplicate_references(references: Iterable[ReferenceSpec]) -> tuple[ReferenceSpec, ...]:
    """Deduplicate references based on their normalized URL."""
    seen = set()
    deduped = []

    for ref in references:
        norm_url = normalize_url(ref.url)
        if norm_url not in seen:
            seen.add(norm_url)
            # Store the normalized url to avoid keeping the version with tracking queries
            deduped.append(ReferenceSpec(url=norm_url, type=ref.type))

    return tuple(deduped)
