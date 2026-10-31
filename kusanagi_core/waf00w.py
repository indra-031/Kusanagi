"""
WAF / CDN detection.

Tries WAFW00F if installed; otherwise falls back to header heuristics.

Categorizes services by strictness so we can pick a safe thread count:
  - Strict WAFs (Cloudflare, Akamai, ...) → 2 threads
  - CDN-only services (Cloudfront, Fastly, ...) → 5 threads
  - Unknown WAF → 3 threads
"""

import json
import shutil
import subprocess

from .colors import C


# Headers that strongly indicate a CDN/WAF
SUSPECT_HEADERS = {
    "cf-ray": "Cloudflare",
    "x-akamai-transformed": "Akamai",
    "x-sucuri-id": "Sucuri",
    "x-iinfo": "Imperva",
    "x-cdn": "Generic CDN",
    "x-varnish": "Varnish",
    "x-amz-cf-id": "Cloudfront",
    "x-azure-ref": "Azure CDN",
    "x-fastly-request-id": "Fastly",
    "x-served-by": "Fastly",
    "x-timer": "Fastly",
    "x-github-request-id": "GitHub",
    "x-cache": "CDN cache",
    "x-cache-status": "CDN cache",
    "x-proxy-cache": "CDN cache",
    "x-edge-location": "CDN edge",
    "x-cdn-geo": "CDN edge",
    "via": "Proxy/CDN",
}

# Server header substrings that indicate a WAF/CDN
SERVER_SUBSTRINGS = [
    "cloudflare", "cloudfront", "akamai", "imperva", "incapsula",
    "sucuri", "fastly", "stackpath", "azion", "keycdn", "bunnycdn",
    "gcore", "arvancloud", "cdn77", "edgecast", "limelight",
    "varnish",
]

# Services that actively rate-limit / block aggressive scanning
STRICT_WAFS = {
    "cloudflare", "akamai", "imperva", "incapsula", "sucuri",
    "f5", "barracuda", "fortiweb", "reblaze", "radware",
    "signal sciences", "wallarm", "aws waf", "azure waf",
}

# Services that are CDN-only — safe to hit a bit harder
CDN_SERVICES = {
    "cloudfront", "fastly", "azure cdn", "bunnycdn", "keycdn",
    "gcore", "cdn77", "stackpath", "azion", "arvancloud",
    "edgecast", "limelight", "cloudinary",
}


def get_safe_threads(waf_name, default=10):
    """
    Return a safe thread count for the detected service.

    Strict WAFs get a very conservative limit; CDN-only services are
    more tolerant.
    """
    w = (waf_name or "").lower()
    if not w:
        return default
    if any(x in w for x in STRICT_WAFS):
        return 2
    if any(x in w for x in CDN_SERVICES):
        return 5
    return 3


def _header_heuristic(url, timeout=10):
    """Fallback: inspect response headers for known WAF/CDN markers."""
    from .http_client import raw_request
    try:
        status, headers, body, _ = raw_request(
            "GET", url, timeout=timeout, follow_redirects=True,
        )
    except Exception:
        return False, ""

    lower_headers = {k.lower(): v for k, v in headers.items()}

    for h, vendor in SUSPECT_HEADERS.items():
        if h in lower_headers:
            return True, vendor

    server = lower_headers.get("server", "").lower()
    for sub in SERVER_SUBSTRINGS:
        if sub in server:
            return True, server

    return False, ""


def _wafw00f_available():
    return shutil.which("wafw00f") is not None


def _run_wafw00f(url, timeout=120):
    """Run WAFW00F CLI and parse JSON output."""
    cmd = ["wafw00f", "-o", "-", "-f", "json", url]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        raw = proc.stdout or ""
    except Exception:
        return False, ""

    try:
        data = json.loads(raw)
    except Exception:
        return False, ""

    if isinstance(data, list) and data:
        entry = data[0]
        if entry.get("detected"):
            return True, entry.get("firewall", "WAF")
    return False, ""


def detect_waf(url, timeout=10, prefer_wafw00f=True):
    """
    Detect whether the target sits behind a WAF/CDN.
    Returns (is_behind_waf: bool, waf_name: str).
    """
    if prefer_wafw00f and _wafw00f_available():
        found, name = _run_wafw00f(url, timeout=timeout)
        if found:
            return True, name

    return _header_heuristic(url, timeout=timeout)