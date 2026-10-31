import json
import urllib.parse
import urllib.request


MAX_CATEGORIES = 8
MAX_PER_CATEGORY = 5


def _api_url(token, method):
    return f"https://api.telegram.org/bot{token}/{method}"


def send_message(token, chat_id, text, thread_id="", timeout=10.0,
                 disable_preview=True):
    if not token or not chat_id:
        return False

    if len(text) > 4050:
        text = text[:4050] + "\n... (truncated)"

    data = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "true" if disable_preview else "false",
    }
    tid = str(thread_id).strip() if thread_id else ""
    if tid:
        data["message_thread_id"] = tid

    body = urllib.parse.urlencode(data).encode("utf-8")
    req = urllib.request.Request(
        _api_url(token, "sendMessage"),
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
            return bool(payload.get("ok"))
    except Exception as e:
        print(f"[!] Telegram error: {e}")
        return False


# ---------- Helpers ----------

def _escape(s):
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))


def _category(entry):
    desc = entry.get("desc", "")

    if any(desc.startswith(f"H: {h}") for h in (
        "X-Original-URL", "X-Rewrite-URL", "X-Override-URL",
        "X-Forwarded-Path", "X-Original-URI", "X-HTTP-DestinationURL",
        "X-Forwarded-Prefix",
    )):
        return "🎯", "Path Override Headers"

    if desc.startswith("H: "):
        return "📨", "Header Injection"
    if desc.startswith("Host: "):
        return "🏠", "Host Header"
    if "(via POST)" in desc:
        return "🔀", "Method Override"
    if desc.startswith("Method: "):
        return "🛠️", "Method Tampering"
    if desc.startswith("HTTP/"):
        return "📡", "Protocol Version"
    if desc.startswith("Protocol:"):
        return "🌐", "Protocol Scheme"
    if any(desc.startswith(p) for p in (
        "Path:", "Lead:", "Trail:", "Mix:", "Combo:", "LastSeg:",
        "Backslash", "EncSlash",
    )):
        return "🧬", "Path Manipulation"
    if desc.startswith("DblEnc:"):
        return "🔐", "Double Encoding"
    if desc.startswith("Slide-"):
        return "🎚️", "Sliding Encode"
    if desc.startswith("Param:") or "?" in desc:
        return "🧪", "Parameter Tampering"

    return "📌", "Other"


def _hit_icon(entry):
    """Status-based icon."""
    status = entry.get("status", 0) or 0
    if 200 <= status < 300:
        return "✅"
    if 300 <= status < 400:
        return "🔄"
    if 400 <= status < 500:
        return "⚠️"
    if 500 <= status < 600:
        return "💥"
    return "•"


def _format_hit_line(entry):
    icon = _hit_icon(entry)
    status = entry.get("status", "?")
    method = entry.get("method", "") or ""
    desc = entry.get("desc", "")
    url = entry.get("url", "")

    if desc.startswith("H: "):
        what = desc[3:]
    elif desc.startswith("Host: "):
        what = desc
    elif "(via POST)" in desc:
        what = desc
    elif desc.startswith("HTTP/"):
        what = desc
    elif url:
        what = url
    else:
        what = desc

    if len(what) > 90:
        what = what[:87] + "..."

    return f"{icon} <code>[{status}]</code> {method} <code>{_escape(what)}</code>"


def _build_message(target, hits, source_label="Kusanagi", extra_notes="",
                   confident_count=0, low_conf_count=0, total_tested=0):
    """Assemble a nicely-formatted Telegram message — includes 4xx too."""

    lines = []

    # ── Title ──
    lines.append(f"🚨 <b>{_escape(source_label)} — 403 Bypass Found</b>")
    lines.append("")

    # ── Target ──
    lines.append("🎯 <b>Target:</b>")
    lines.append(f"<code>{_escape(target)}</code>")
    lines.append("")

    # ── Summary ──
    if not confident_count and not low_conf_count:
        confident_count = sum(1 for h in hits if (h.get("status") or 0) < 400)
        low_conf_count = sum(1 for h in hits
                             if 400 <= (h.get("status") or 0) < 500)

    if confident_count:
        lines.append(f"✅ <b>Confirmed (2xx/3xx):</b> {confident_count}")
    if low_conf_count:
        lines.append(f"⚠️ <b>Possible (4xx):</b> {low_conf_count}")
    if total_tested:
        lines.append(f"🔍 <b>Total tested:</b> {total_tested}")
    lines.append("")

    # ── Group by category ──
    groups = {}
    order = []
    for h in hits:
        icon, label = _category(h)
        key = f"{icon} <b>{label}</b>"
        if key not in groups:
            groups[key] = []
            order.append(key)
        groups[key].append(h)

    # ── Prioritize categories with more confirmed hits ──
    def cat_score(k):
        items = groups[k]
        confirmed = sum(1 for h in items if (h.get("status") or 0) < 400)
        return (-confirmed, -len(items))

    order = sorted(order, key=cat_score)

    # ── Render each category ──
    for key in order[:MAX_CATEGORIES]:
        items = groups[key]
        confirmed = sum(1 for h in items if (h.get("status") or 0) < 400)
        low = len(items) - confirmed

        # Sort within category: confirmed first, then by status
        sorted_items = sorted(
            items,
            key=lambda h: (0 if (h.get("status") or 0) < 400 else 1,
                           h.get("status") or 999),
        )

        lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━")

        if confirmed and low:
            lines.append(f"{key} (✅{confirmed} ⚠️{low})")
        elif low:
            lines.append(f"{key} (⚠️{low})")
        else:
            lines.append(f"{key} ({len(items)})")

        for h in sorted_items[:MAX_PER_CATEGORY]:
            lines.append(_format_hit_line(h))

        if len(items) > MAX_PER_CATEGORY:
            lines.append(f"<i>... +{len(items) - MAX_PER_CATEGORY} more</i>")
        lines.append("")

    if len(order) > MAX_CATEGORIES:
        lines.append(f"<i>... and {len(order) - MAX_CATEGORIES} more categories</i>")
        lines.append("")

    # ── Notes ──
    if extra_notes:
        lines.append(extra_notes)
        lines.append("")

    # ── Footer ──
    lines.append("━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    lines.append("⚠️ <i>Verify manually before reporting.</i>")

    return "\n".join(lines)


def notify_bypass_found(cfg, target, hits, extra_notes="",
                        source_label="Kusanagi",
                        confident_count=0, low_conf_count=0, total_tested=0):
    """
    Send a formatted bypass notification to Telegram.

    Includes both confident (2xx/3xx) and low-confidence (4xx) hits.
    """
    tg = cfg.get("telegram", {})
    if not tg.get("enabled"):
        return False

    if not hits:
        return False

    text = _build_message(
        target=target,
        hits=hits,
        source_label=source_label,
        extra_notes=extra_notes,
        confident_count=confident_count,
        low_conf_count=low_conf_count,
        total_tested=total_tested,
    )

    return send_message(
        token=tg.get("bot_token", ""),
        chat_id=tg.get("chat_id", ""),
        text=text,
        thread_id=tg.get("thread_id", ""),
    )