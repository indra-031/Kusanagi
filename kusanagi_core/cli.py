import argparse


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="kusanagi",
        description="Kusanagi - 401/403 bypass testing tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    p.add_argument("-u", "--url", default=None, help="Single target URL")
    p.add_argument("-f", "--file", default=None,
                   help="File containing target URLs (one per line)")
    p.add_argument("-p", "--path", default="kusanagi",
                   help="Default target path (default: kusanagi)")
    p.add_argument("-c", "--cookie", default="",
                   help="Cookie header value")

    p.add_argument("-t", "--threads", type=int, default=10,
                   help="Number of concurrent workers (default: 10)")
    p.add_argument("-T", "--timeout", type=float, default=10.0,
                   help="Per-request timeout in seconds (default: 10.0)")
    p.add_argument("-d", "--delay", type=float, default=0.0,
                   help="Delay in seconds between requests "
                        "(e.g. -d 1 or -d 0.5). Default: 0 (no delay). "
                        "Useful for strict WAFs.")

    p.add_argument("-L", "--follow", action="store_true",
                   help="Follow redirects")
    p.add_argument("-a", "--all", dest="show_all", action="store_true",
                   help="Show every test, not only interesting ones")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Show every test as '<what was tested> | status: <code>'")
    p.add_argument("--payloads-dir", default="payloads",
                   help="Directory containing payload files")
    p.add_argument("--ua", default=("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                                    "Chrome/124.0 Safari/537.36"),
                   help="User-Agent header")
    p.add_argument("-o", "--output", default="",
                   help="Optional output file (plain text log)")
    p.add_argument("-C", "--config", default="config.json",
                   help="Config file path")

    # FIX: default=None (not "") so action="append" can work
    p.add_argument("-fc", "--filter-code", default=None, action="append",
                   help="Comma-separated HTTP status code(s) to hide from "
                        "output (e.g. -fc 404 or -fc 404,405,500). "
                        "Can be repeated.")

    # === Resume ===
    p.add_argument("--resume", action="store_true",
                   help="Resume from a previous run: skip targets already "
                        "recorded in the resume file")
    p.add_argument("--resume-file", default=".kusanagi_resume",
                   help="Resume state file (default: .kusanagi_resume)")
    p.add_argument("--reset-resume", action="store_true",
                   help="Clear the resume file before starting")

    # === JSON output ===
    p.add_argument("--json", default="",
                   help="Save results as structured JSON to this file "
                        "(e.g. --json results.json)")

    # === Screenshot ===
    p.add_argument("--screenshot", nargs="?", const="screenshots", default="",
                   help="Take screenshots of confirmed bypasses. "
                        "Optional DIR (default: screenshots/). "
                        "Requires: pip install playwright && "
                        "playwright install chromium")
    p.add_argument("--screenshot-max", type=int, default=5,
                   help="Max screenshots per target (default: 5)")

    # === WAF/CDN ===
    p.add_argument("--no-waf00w", action="store_true",
                   help="Skip WAF/CDN detection (always use the -t value)")
    p.add_argument("--waf-threads", type=int, default=None,
                   help="Override auto-reduced thread count when a WAF/CDN "
                        "is detected (e.g. --waf-threads 5)")

    # === Optional extras ===
    p.add_argument("--wayback", action="store_true",
                   help="Look up cached versions in the Wayback Machine "
                        "(off by default)")

    # === Telegram ===
    p.add_argument("--telegram", dest="telegram", action="store_true",
                   default=None, help="Force telegram notification")
    p.add_argument("--no-telegram", dest="telegram", action="store_false",
                   help="Disable telegram notification")
    p.add_argument("--thread-id", dest="thread_id", default=None,
                   help="Telegram forum topic ID (overrides config)")

    return p


def parse_filter_codes(raw_values) -> set:
    codes = set()
    if not raw_values:
        return codes
    if isinstance(raw_values, str):
        raw_values = [raw_values]
    for chunk in raw_values:
        for piece in str(chunk).split(","):
            piece = piece.strip()
            if not piece:
                continue
            try:
                codes.add(int(piece))
            except ValueError:
                pass
    return codes


def parse_args():
    args = build_parser().parse_args()
    if not args.url and not args.file:
        build_parser().error("either -u/--url or -f/--file is required")
    args.filter_codes = parse_filter_codes(args.filter_code)
    return args