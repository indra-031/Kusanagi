from .http_client import raw_request


def get_baseline(url, headers=None, timeout=10.0, follow=False):
    """Probe the target once to build a reference response."""
    status, resp_headers, body, _ = raw_request(
        "GET", url, headers=headers, timeout=timeout, follow_redirects=follow
    )
    return {
        "status": status,
        "size": len(body),
        "body": body,
        "headers": resp_headers,
    }