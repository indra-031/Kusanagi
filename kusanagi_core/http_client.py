"""
HTTP client with per-thread connection pooling (keep-alive) and
shared SSL context. This makes repeated requests 3-5x faster by
reusing TCP + TLS connections.
"""

import http.client
import socket
import ssl
import threading
from urllib.parse import urlparse, urljoin


# =====================================================================
#  Shared SSL context (created once)
# =====================================================================

_ssl_context = None
_ssl_context_lock = threading.Lock()


def _get_ssl_context():
    global _ssl_context
    if _ssl_context is None:
        with _ssl_context_lock:
            if _ssl_context is None:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                _ssl_context = ctx
    return _ssl_context


# =====================================================================
#  Per-thread connection pool
# =====================================================================

_thread_local = threading.local()


def _get_pool():
    pool = getattr(_thread_local, "pool", None)
    if pool is None:
        pool = {}
        _thread_local.pool = pool
    return pool


def _create_conn(scheme, host, port, timeout, http_version):
    if scheme == "https":
        conn = http.client.HTTPSConnection(
            host, port, timeout=timeout, context=_get_ssl_context()
        )
    else:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)

    if http_version == "1.0":
        conn._http_vsn = 10
        conn._http_vsn_str = "HTTP/1.0"
    else:
        conn._http_vsn = 11
        conn._http_vsn_str = "HTTP/1.1"

    return conn


def _is_alive(conn):
    if conn is None:
        return False
    if conn.sock is None:
        return False
    try:
        return conn.sock.fileno() >= 0
    except Exception:
        return False


def _get_conn(scheme, host, port, timeout, http_version):
    """Return (conn, key). May reuse from pool or create new."""
    pool = _get_pool()
    key = (scheme, host, port, http_version)

    conn = pool.get(key)
    if conn is not None and not _is_alive(conn):
        try:
            conn.close()
        except Exception:
            pass
        pool.pop(key, None)
        conn = None

    if conn is None:
        conn = _create_conn(scheme, host, port, timeout, http_version)
        pool[key] = conn

    return conn, key


def _discard_conn(key):
    """Remove a connection from the pool and close it."""
    pool = _get_pool()
    conn = pool.pop(key, None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass


def close_all():
    """Close all pooled connections for the current thread."""
    pool = _get_pool()
    for conn in list(pool.values()):
        try:
            conn.close()
        except Exception:
            pass
    pool.clear()


# =====================================================================
#  Verbose printers (lazy color import to avoid cycles)
# =====================================================================

def _print_request(method, scheme, host, port, path, headers, http_version):
    from .colors import C
    url = f"{scheme}://{host}:{port}{path}"
    print(f"  {C.DIM}>>> {method} {url} HTTP/{http_version}{C.RESET}")
    for k, v in headers.items():
        print(f"  {C.DIM}    {k}: {v}{C.RESET}")


def _print_response(status, reason, resp_headers, body, preview_bytes=300):
    from .colors import C
    print(f"  {C.DIM}<<< {status} {reason} ({len(body)} bytes){C.RESET}")
    for k, v in resp_headers.items():
        print(f"  {C.DIM}    {k}: {v}{C.RESET}")
    if body:
        try:
            snippet = body[:preview_bytes].decode("utf-8", errors="replace")
        except Exception:
            snippet = repr(body[:preview_bytes])
        snippet = snippet.replace("\n", " ").replace("\r", " ")
        if len(body) > preview_bytes:
            snippet += " ..."
        print(f"  {C.DIM}    body: {snippet}{C.RESET}")


# =====================================================================
#  Core request
# =====================================================================

_RETRYABLE = (
    http.client.RemoteDisconnected,
    http.client.CannotSendRequest,
    http.client.BadStatusLine,
    ConnectionResetError,
    BrokenPipeError,
    ConnectionAbortedError,
)


def _do_request(method, scheme, host, port, path, headers,
                timeout, http_version, verbose):
    """Single request with one retry on stale connection."""

    max_attempts = 2
    conn, key = _get_conn(scheme, host, port, timeout, http_version)

    for attempt in range(max_attempts):
        try:
            conn.request(method, path, headers=headers)
            resp = conn.getresponse()
            body = resp.read()
            resp_headers = {k: v for k, v in resp.getheaders()}
            status = resp.status
            reason = resp.reason

            if verbose:
                _print_response(status, reason, resp_headers, body)

            # Discard the connection if the server wants to close
            conn_hdr = (resp_headers.get("Connection")
                        or resp_headers.get("connection")
                        or "").lower()
            if "close" in conn_hdr or getattr(resp, "will_close", False):
                _discard_conn(key)

            return status, resp_headers, body, reason

        except _RETRYABLE:
            _discard_conn(key)
            if attempt < max_attempts - 1:
                conn, key = _get_conn(scheme, host, port, timeout,
                                      http_version)
                continue
            raise
        except Exception:
            _discard_conn(key)
            raise

    # unreachable
    raise RuntimeError("request failed")


def raw_request(method, url, headers=None, timeout=10.0,
                follow_redirects=False, max_redirects=5,
                verbose=False, http_version="1.1"):
    """
    Send an HTTP request without normalizing the path.
    Reuses per-thread connections via keep-alive.
    Returns (status_code, headers_dict, body_bytes, final_url).
    """
    headers = dict(headers or {})
    if "Connection" not in headers and "connection" not in headers:
        headers["Connection"] = "keep-alive"

    current_url = url
    last = (0, {}, b"", current_url)

    for _ in range(max_redirects + 1):
        parsed = urlparse(current_url)
        scheme = parsed.scheme or "http"
        host = parsed.hostname
        if not host:
            raise ValueError(f"Invalid URL: {current_url}")
        port = parsed.port or (443 if scheme == "https" else 80)

        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query

        if verbose:
            _print_request(method, scheme, host, port, path, headers,
                           http_version)

        status, resp_headers, body, reason = _do_request(
            method, scheme, host, port, path, headers,
            timeout, http_version, verbose,
        )

        last = (status, resp_headers, body, current_url)

        if follow_redirects and 300 <= status < 400:
            loc = resp_headers.get("Location") or resp_headers.get("location")
            if loc:
                current_url = urljoin(current_url, loc)
                continue
        return last

    return last