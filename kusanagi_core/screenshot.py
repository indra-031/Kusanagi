"""
Screenshot module.

Captures a screenshot for one representative hit per test category
(e.g., Path Manipulation, Method Override, Header Injection).

Uses Playwright to load the *exact* request (method + headers + URL)
via `context.request`, then intercepts the browser's navigation to
fulfill it with the fetched response — so the screenshot reflects
the real bypass, not a 403.

Install:
    pip install playwright
    playwright install chromium
"""

import os
import re
from urllib.parse import urlparse


def is_available():
    try:
        from playwright.sync_api import sync_playwright  # noqa: F401
        return True
    except ImportError:
        return False


def _safe_name(s, max_len=80):
    s = (s or "").strip()
    s = re.sub(r"[^a-zA-Z0-9._-]+", "_", s)
    s = s.strip("_")
    return s[:max_len] or "item"


def _target_dir(base_dir, target):
    parsed = urlparse(target)
    host = parsed.netloc or "target"
    return os.path.join(base_dir, _safe_name(host))


def _get_category(desc):
    """Return a stable category name for a hit description."""
    if any(desc.startswith(f"H: {h}") for h in (
        "X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
        "X-Forwarded-Path", "X-Original-URI", "X-HTTP-DestinationURL",
        "X-Forwarded-Prefix",
    )):
        return "Path_Override_Headers"
    if desc.startswith("H: "):
        return "Header_Injection"
    if desc.startswith("Host: "):
        return "Host_Header"
    if "(via POST)" in desc:
        return "Method_Override"
    if desc.startswith("Method: "):
        return "Method_Tampering"
    if any(desc.startswith(p) for p in (
        "Path:", "Lead:", "Trail:", "Mix:", "Combo:", "LastSeg:",
        "Backslash", "EncSlash",
    )):
        return "Path_Manipulation"
    if desc.startswith("DblEnc:"):
        return "Double_Encoding"
    if desc.startswith("Slide-"):
        return "Sliding_Encode"
    if desc.startswith("Param:") or "?" in desc:
        return "Parameter_Tampering"
    return "Other"


def take_screenshots(target, hits, out_dir, max_count=5, timeout_ms=15000):
    """
    Group confirmed hits by test category, then take 1 screenshot
    per category using the exact method + headers of that hit.
    """
    if not is_available():
        return [{
            "url": target, "ok": False,
            "error": "playwright not installed "
                     "(pip install playwright && playwright install chromium)",
        }]

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return [{"url": target, "ok": False, "error": "playwright not available"}]

    results = []
    safe_target = _safe_name(urlparse(target).netloc or "target")
    target_dir = os.path.join(out_dir, safe_target)
    try:
        os.makedirs(target_dir, exist_ok=True)
    except Exception as e:
        return [{"url": target, "ok": False, "error": f"mkdir failed: {e}"}]

    # ── Deduplicate by category ──
    grouped = {}
    for h in hits:
        cat = _get_category(h.get("desc", ""))
        if cat not in grouped:
            grouped[cat] = h

    to_shot = list(grouped.values())[:max_count]

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(ignore_https_errors=True)

            for i, hit in enumerate(to_shot, 1):
                url = hit.get("url") or target
                category = _get_category(hit.get("desc", ""))
                fname = f"{i:03d}_{category}.png"
                fpath = os.path.join(target_dir, fname)

                # Fetch the EXACT request (method + headers + URL)
                resp_body = None
                resp_headers = {}
                resp_status = 200
                fetch_err = None

                try:
                    api_resp = context.request.fetch(
                        url,
                        method=hit.get("method", "GET"),
                        headers=hit.get("headers", {}),
                        timeout=timeout_ms,
                        ignore_https_errors=True,
                    )
                    resp_body = api_resp.body()
                    resp_headers = api_resp.headers
                    resp_status = api_resp.status
                except Exception as e:
                    fetch_err = str(e)[:200]

                # Open a page and inject the fetched response
                page = context.new_page()

                if resp_body is not None:
                    def _handler(route, _url=url, _status=resp_status,
                                 _headers=resp_headers, _body=resp_body):
                        if route.request.url == _url:
                            route.fulfill(status=_status,
                                          headers=_headers,
                                          body=_body)
                        else:
                            route.continue_()
                    page.route("**/*", _handler)

                try:
                    page.goto(url, timeout=timeout_ms,
                              wait_until="domcontentloaded")
                    page.screenshot(path=fpath, full_page=True)
                    page.close()
                    results.append({
                        "url": url,
                        "method": hit.get("method"),
                        "status": hit.get("status"),
                        "category": category,
                        "path": fpath,
                        "ok": True,
                        "fetch_error": fetch_err,
                    })
                except Exception as e:
                    try:
                        page.close()
                    except Exception:
                        pass
                    results.append({
                        "url": url,
                        "method": hit.get("method"),
                        "status": hit.get("status"),
                        "category": category,
                        "ok": False,
                        "error": str(e)[:200],
                    })

            browser.close()
    except Exception as e:
        results.append({"url": target, "ok": False, "error": str(e)[:200]})

    return results