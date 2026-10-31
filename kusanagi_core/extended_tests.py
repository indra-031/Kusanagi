"""
Extended test task generators (v5 upgrade).

Produces Task objects for:
  - IP variant x header combinations
  - Protocol scheme switch (http <-> https)
  - Sliding single/double-char percent encoding
  - Wayback Machine lookup (not a Task — direct call)
"""

import json
import urllib.request
from urllib.parse import urlparse, urlunparse

from .colors import C
from .task import Task


# =====================================================================
#  IP variants
# =====================================================================

IP_VARIANTS = [
    "127.0.0.1",
    "localhost",
    "localhost:80",
    "localhost:443",
    "127.0.0.1:80",
    "127.0.0.1:443",
    "127.0.0.1:5000",
    "2130706433",              # decimal of 127.0.0.1
    "0x7F000001",              # hex of 127.0.0.1
    "0177.0000.0000.0001",     # octal of 127.0.0.1
    "0",                       # 0.0.0.0
    "127.1",
    "10.0.0.0",
    "10.0.0.1",
    "172.16.0.0",
    "172.16.0.1",
    "192.168.1.0",
    "192.168.1.1",
    "http://127.0.0.1",
    "https://127.0.0.1",
    "127.0.0.1, 68.180.194.242",
    "127.0.0.1,127.0.0.1",
]

IP_HEADERS_FOR_VARIANTS = [
    "X-Forwarded-For",
    "X-Real-IP",
    "X-Client-IP",
    "X-Originating-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Custom-IP-Authorization",
    "Client-IP",
    "X-Forwarded",
    "X-Forward-For",
    "X-Forwarded-Host",
]


# =====================================================================
#  Task generators
# =====================================================================

def generate_ip_variant_tasks(target, base_headers):
    """Every IP header combined with every IP variant."""
    for h in IP_HEADERS_FOR_VARIANTS:
        for ip in IP_VARIANTS:
            hdrs = dict(base_headers)
            hdrs[h] = ip
            yield Task(f"H: {h}: {ip}", "GET", target, hdrs)


def generate_protocol_switch_tasks(target, base_headers):
    """Switch the URL scheme (http <-> https) using the correct default port."""
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        return

    alt_scheme = "http" if parsed.scheme == "https" else "https"
    host = parsed.hostname

    # Use default port for the new scheme; keep non-standard ports
    if parsed.port and parsed.port not in (80, 443):
        netloc = f"{host}:{parsed.port}"
    else:
        netloc = host

    alt_url = urlunparse(parsed._replace(scheme=alt_scheme, netloc=netloc))
    yield Task(f"Protocol: {alt_scheme}://", "GET", alt_url, base_headers)


def generate_sliding_encode_tasks(scheme, host, port, path, base_headers):
    """
    Single- and double-char percent encoding, sliding across the path.

    For 'admin':
      Single: %61dmin, a%64min, ad%6din, adm%69n, admi%6e
      Double: %2561dmin, a%2564min, ad%256din, adm%2569n, admi%256e
    """
    name = path.lstrip("/")
    if not name:
        return

    # Single
    for i, ch in enumerate(name):
        if ch == "/":
            continue
        enc = "%{:02x}".format(ord(ch))
        new_path = f"/{name[:i]}{enc}{name[i+1:]}"
        new_url = f"{scheme}://{host}:{port}{new_path}"
        yield Task(f"Slide-single: {ch}@{i}", "GET", new_url, base_headers)

    # Double
    for i, ch in enumerate(name):
        if ch == "/":
            continue
        enc = "%25{:02x}".format(ord(ch))
        new_path = f"/{name[:i]}{enc}{name[i+1:]}"
        new_url = f"{scheme}://{host}:{port}{new_path}"
        yield Task(f"Slide-double: {ch}@{i}", "GET", new_url, base_headers)


# =====================================================================
#  Wayback lookup (not a task — direct API call)
# =====================================================================

def run_wayback_lookup(target):
    print(f"\n{C.BOLD}{C.BLUE}--- [ Wayback Machine Cached Copy ] "
          f"---------------------{C.RESET}")
    api = f"https://archive.org/wayback/available?url={target}"
    try:
        with urllib.request.urlopen(api, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"  {C.DIM}Wayback lookup failed: {e}{C.RESET}")
        return

    snap = data.get("archived_snapshots", {}).get("closest")
    if snap and snap.get("available"):
        print(f"  {C.GREEN}[+] Cached copy found:{C.RESET}")
        print(f"      URL   : {snap.get('url')}")
        print(f"      Date  : {snap.get('timestamp')}")
        print(f"      Status: {snap.get('status')}")
    else:
        print(f"  {C.DIM}No cached version found.{C.RESET}")